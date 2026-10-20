//! `z web` — loopback web observer for sessions.

use super::*;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use z_session::{SessionClient, SessionInfo};
use z_web::{SessionProvider, SessionSnapshot, SessionSummary, WebConfig};

struct DaemonProvider {
    client: Arc<SessionClient>,
}

impl SessionProvider for DaemonProvider {
    fn sessions(&self) -> Result<Vec<SessionSummary>, String> {
        let sessions = self.client.list().map_err(|e| e.to_string())?;
        Ok(sessions.into_iter().map(summary).collect())
    }

    fn snapshot(&self, id: &str) -> Result<SessionSnapshot, String> {
        let value = self
            .client
            .call("session.snapshot", json!({"session_id": id}))
            .map_err(|e| e.to_string())?;
        let blocks = self
            .client
            .call("session.blocks", json!({"session_id": id}))
            .ok()
            .and_then(|value| value.get("blocks").cloned())
            .and_then(|blocks| blocks.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|block| z_web::server::BlockSummary {
                command: block["command"].as_str().unwrap_or("").to_string(),
                status: block["status"].as_str().unwrap_or("").to_string(),
                exit_code: block["exit_code"].as_i64().map(|code| code as i32),
                id: block["id"].as_str().unwrap_or("").to_string(),
            })
            .collect();
        Ok(SessionSnapshot {
            id: value["info"]["id"].as_str().unwrap_or(id).to_string(),
            title: value["info"]["title"].as_str().unwrap_or("").to_string(),
            cwd: value["info"]["cwd"].as_str().unwrap_or("").to_string(),
            seq: value["seq"].as_u64().unwrap_or(0),
            contents: value["contents"].as_str().unwrap_or("").to_string(),
            progress: value["progress"]
                .get("state")
                .and_then(|state| state.as_str())
                .map(|state| match value["progress"]["pct"].as_u64() {
                    Some(pct) => format!("{state} {pct}%"),
                    None => state.to_string(),
                }),
            blocks,
        })
    }

    fn input(&self, id: &str, data: &[u8]) -> Result<(), String> {
        self.client.input(id, data).map_err(|e| e.to_string())
    }
}

fn summary(info: SessionInfo) -> SessionSummary {
    SessionSummary {
        id: info.id,
        title: info.title,
        shell: info.shell,
        cwd: info.cwd,
        rows: info.rows,
        cols: info.cols,
        status: info.status,
        integration: info.integration,
    }
}

pub fn web(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--bind", "--token-file", "--server-name"]);
    match parsed.command("serve") {
        "serve" => {
            let config = load_config()?.config;
            let bind = parsed
                .value("--bind")
                .map(str::to_string)
                .unwrap_or_else(|| config.remote.web_bind.clone());
            let bind: SocketAddr = bind
                .parse()
                .map_err(|_| fail("--bind must be a socket address such as 127.0.0.1:8080"))?;
            if !bind.ip().is_loopback() {
                return Err(fail(
                    "the web observer only binds to loopback; use an SSH tunnel for remote access",
                ));
            }
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            let provider = Arc::new(DaemonProvider {
                client: Arc::new(client),
            });
            let mut web_config = WebConfig::new(bind);
            if parsed.flag("--allow-input") {
                web_config = web_config.with_input();
            }
            if let Some(name) = parsed.value("--server-name") {
                web_config.server_name = name.to_string();
            }
            // Bind now so the printed URL has the actual ephemeral port.
            let listener = std::net::TcpListener::bind(web_config.bind)
                .map_err(|e| map_err("cannot bind web listener", e))?;
            let actual = listener
                .local_addr()
                .map_err(|e| map_err("cannot determine web address", e))?;
            web_config.bind = actual;
            let token_path = parsed
                .value("--token-file")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    data_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("web")
                        .join("tokens.json")
                });
            if let Some(parent) = token_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| map_err("cannot create token directory", e))?;
            }
            let token_doc = json!({
                "read": web_config.read_token,
                "write": web_config.write_token,
                "read_url": web_config.read_url(),
                "write_url": web_config.write_url(),
            });
            std::fs::write(
                &token_path,
                serde_json::to_string_pretty(&token_doc).unwrap_or_default(),
            )
            .map_err(|e| map_err("cannot write token file", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
            let _ = write_audit(
                "user",
                "user",
                "web.serve",
                &actual.to_string(),
                "allow",
                if web_config.write_token.is_some() {
                    "read-write"
                } else {
                    "read-only"
                },
                "medium",
            );
            if json_out {
                print_json(&json!({
                    "bind": actual.to_string(),
                    "read_url": web_config.read_url(),
                    "write_url": web_config.write_url(),
                    "token_file": token_path.display().to_string(),
                }))?;
            } else {
                println!("Zentrion web observer (loopback only)");
                println!("  read-only: {}", web_config.read_url());
                if let Some(url) = web_config.write_url() {
                    println!("  read/write: {url}");
                } else {
                    println!("  read/write: disabled (use --allow-input)");
                }
                println!("  tokens:    {}", token_path.display());
                eprintln!("press Ctrl+C to stop");
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .map_err(|e| map_err("cannot start web runtime", e))?;
            runtime
                .block_on(z_web::serve_on(listener, web_config, provider))
                .map_err(|e| map_err("web server failed", e))
        }
        other => Err(fail(format!("unknown web subcommand `{other}` (serve)"))),
    }
}
