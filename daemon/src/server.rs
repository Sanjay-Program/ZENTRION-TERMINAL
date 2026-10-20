//! TCP loopback server for SDK requests.

use crate::{ExecRequest, ExecResult, Metrics};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use z_core::runtime::Runtime;

const MAX_REQUEST_LINE: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub async fn start_daemon(port: u16, once: bool) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("cannot bind 127.0.0.1:{port}"))?;
    let addr = listener.local_addr()?;
    println!("ZENTRION IPC daemon listening on {addr}");
    println!("  loopback only · newline-delimited JSON · brokered execution");
    if std::env::var("ZENTRION_DAEMON_TOKEN")
        .map(|token| !token.is_empty())
        .unwrap_or(false)
    {
        println!("  shared-token authentication: required");
    } else {
        println!(
            "  shared-token authentication: disabled (set ZENTRION_DAEMON_TOKEN to require it)"
        );
    }

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if !peer.ip().is_loopback() {
                    // Defensive: the listener is already loopback-bound.
                    continue;
                }
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        eprintln!("daemon connection error: {e:#}");
                    }
                });
                if once {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(150)) => {
                if SHUTDOWN.load(Ordering::SeqCst) {
                    println!("ZENTRION IPC daemon stopped.");
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_connection(stream: TcpStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let read = timeout(REQUEST_TIMEOUT, reader.read_line(&mut line)).await;
        let read = match read {
            Ok(result) => result?,
            Err(_) => {
                write_response(&mut writer, error_response("timeout", "request timed out")).await?;
                return Ok(());
            }
        };
        if read == 0 {
            return Ok(());
        }
        if line.len() > MAX_REQUEST_LINE {
            write_response(
                &mut writer,
                error_response("too_large", "request exceeds 1 MiB"),
            )
            .await?;
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: ExecRequest = match serde_json::from_str(trimmed) {
            Ok(request) => request,
            Err(e) => {
                write_response(
                    &mut writer,
                    error_response("bad_request", &format!("invalid JSON request: {e}")),
                )
                .await?;
                continue;
            }
        };

        let result = handle_request(request).await;
        write_response(&mut writer, result).await?;
    }
}

async fn write_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    result: ExecResult,
) -> Result<()> {
    let mut data = serde_json::to_vec(&result)?;
    data.push(b'\n');
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

fn error_response(id: &str, message: &str) -> ExecResult {
    ExecResult {
        status: "error".into(),
        request_id: id.to_string(),
        metrics: metrics(),
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
        error: Some(message.to_string()),
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn metrics() -> Metrics {
    let mut system = sysinfo::System::new();
    system.refresh_cpu();
    system.refresh_memory();
    let cpu_usage = system.global_cpu_info().cpu_usage() as f64;
    Metrics {
        cpu_usage,
        memory_usage: system.used_memory(),
        pid: std::process::id(),
    }
}

async fn handle_request(request: ExecRequest) -> ExecResult {
    let request_id = request
        .id
        .clone()
        .unwrap_or_else(|| format!("req-{}", std::process::id()));

    if let Ok(expected) = std::env::var("ZENTRION_DAEMON_TOKEN") {
        if !expected.is_empty() {
            let presented = request.token.as_deref().unwrap_or("");
            if !constant_time_eq(presented, &expected) {
                return ExecResult {
                    status: "error".into(),
                    request_id,
                    metrics: metrics(),
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: None,
                    error: Some(
                        "unauthorized: ZENTRION_DAEMON_TOKEN is required for this daemon".into(),
                    ),
                };
            }
        }
    }

    let command = request.command.trim().to_string();

    if command.is_empty() {
        return ExecResult {
            status: "error".into(),
            request_id,
            metrics: metrics(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            error: Some("empty command".into()),
        };
    }

    if command == "shutdown" {
        SHUTDOWN.store(true, Ordering::SeqCst);
        return ExecResult {
            status: "ok".into(),
            request_id,
            metrics: metrics(),
            stdout: "shutting down\n".into(),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
        };
    }

    if command == "status" || command == "ping" {
        return ExecResult {
            status: "ok".into(),
            request_id,
            metrics: metrics(),
            stdout: format!(
                "zentrion {} · pid {}\n",
                env!("CARGO_PKG_VERSION"),
                std::process::id()
            ),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
        };
    }

    if command == "version" {
        return ExecResult {
            status: "ok".into(),
            request_id,
            metrics: metrics(),
            stdout: format!("{}\n", env!("CARGO_PKG_VERSION")),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
        };
    }

    match execute(request_id.clone(), command, request.args).await {
        Ok(result) => result,
        Err(e) => ExecResult {
            status: "error".into(),
            request_id,
            metrics: metrics(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            error: Some(format!("{e:#}")),
        },
    }
}

async fn execute(request_id: String, program: String, args: Vec<String>) -> Result<ExecResult> {
    // Policy is resolved on every request so config edits take effect without
    // restarting the daemon.
    let runtime = Runtime::init(None)?;
    let policy = effective_policy(&runtime)?;
    let actor = z_identity::local_user()?;
    let audit_path = z_core::config::user_data_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine the data directory"))?
        .join("audit")
        .join("events.jsonl");
    let audit = z_audit::AuditLog::open(&audit_path)?;
    let platform = format!(
        "{}-{}",
        runtime.host.os.as_str(),
        runtime.host.arch.as_str()
    );
    let mut broker = z_exec::Broker::new(
        policy,
        audit,
        runtime.project.as_ref().map(|p| p.root.clone()),
        platform,
    );
    let req = z_exec::ExecRequest {
        actor: z_exec::ActorRef {
            id: actor.id.clone(),
            actor_type: actor.actor_type.as_str().to_string(),
        },
        action: "process.spawn".into(),
        resource: program.clone(),
        reason: Some("sdk daemon".into()),
    };
    // SDK callers cannot type `--approve`; high-risk actions require a project
    // policy that explicitly allows them and are still recorded.
    let result = broker.execute_process(&req, &program, &args, false)?;
    let exit_code = match &result.status {
        z_exec::ExecStatus::Allowed => Some(0),
        _ => None,
    };
    Ok(ExecResult {
        status: format!("{:?}", result.status).to_ascii_lowercase(),
        request_id,
        metrics: metrics(),
        stdout: result.stdout.unwrap_or_default(),
        stderr: result.stderr.unwrap_or_default(),
        exit_code,
        error: None,
    })
}

fn effective_policy(runtime: &Runtime) -> Result<z_policy::Policy> {
    let base = z_policy::Policy::default();
    match &runtime.project {
        Some(project) => {
            let policy_path = PathBuf::from(&project.root)
                .join(".zentrion")
                .join("policy.yaml");
            if !policy_path.exists() {
                return Ok(base);
            }
            let text = z_core::fs::read_text(&policy_path)?;
            let project_policy = z_policy::parse_policy(&text)?;
            Ok(z_policy::merge::merge(&base, &project_policy))
        }
        None => Ok(base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_has_real_metrics() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(handle_request(ExecRequest {
            id: Some("t1".into()),
            command: "status".into(),
            args: vec![],
            token: None,
        }));
        assert_eq!(response.status, "ok");
        assert_eq!(response.request_id, "t1");
        assert_eq!(response.metrics.pid, std::process::id());
        assert!(response.stdout.contains("zentrion"));
    }

    #[test]
    fn empty_command_is_rejected() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(handle_request(ExecRequest {
            id: None,
            command: "   ".into(),
            args: vec![],
            token: None,
        }));
        assert_eq!(response.status, "error");
    }
}
