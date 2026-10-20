//! `z remote` — SSH execution, shells, transfers and forwarding.

use super::*;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;
use z_remote::{ssh_config_hosts, ForwardRegistry, RemoteError, SshOptions, SshRunner, SshTarget};

pub fn remote(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--identity",
            "--jump",
            "--port",
            "--known-hosts",
            "--timeout",
            "--local-port",
            "--remote-host",
            "--remote-port",
        ],
    );
    match parsed.command("doctor") {
        "hosts" | "list" => {
            let hosts = ssh_config_hosts();
            if json_out {
                print_json(&json!({"hosts": hosts}))
            } else if hosts.is_empty() {
                println!("No Host entries in ~/.ssh/config.");
                Ok(())
            } else {
                for host in hosts {
                    println!("{host}");
                }
                Ok(())
            }
        }
        "exec" => {
            let rest = parsed.rest();
            let target = rest
                .first()
                .ok_or_else(|| fail("usage: z remote exec <target> <command...>"))?;
            let command = rest[1..].join(" ");
            if command.trim().is_empty() {
                return Err(fail("missing remote command"));
            }
            let target = SshTarget::parse(target).map_err(remote_err)?;
            let options = options(&parsed)?;
            let runner = SshRunner::new(options);
            let timeout = parsed
                .value("--timeout")
                .map(parse_seconds)
                .transpose()?
                .unwrap_or_else(z_remote::default_timeout);
            let output = runner
                .exec(&target, &command, timeout)
                .map_err(remote_err)?;
            let _ = write_audit(
                "user",
                "user",
                "remote.exec",
                &target.destination(),
                "allow",
                if output.success() { "ok" } else { "failed" },
                "medium",
            );
            if json_out {
                print_json(&serde_json::to_value(&output).unwrap_or(json!({})))?;
            } else {
                print!("{}", output.stdout);
                eprint!("{}", output.stderr);
                if output.timed_out {
                    return Err(fail("remote command timed out"));
                }
            }
            if !output.success() {
                return Err(fail(format!(
                    "remote command exited with {:?}",
                    output.status
                )));
            }
            Ok(())
        }
        "shell" | "login" => {
            let target = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z remote shell <target>"))?;
            let target = SshTarget::parse(target).map_err(remote_err)?;
            let options = options(&parsed)?;
            let runner = SshRunner::new(options);
            let (program, args) = runner.login_command(&target).map_err(remote_err)?;
            let mut command = vec![program.display().to_string()];
            command.extend(args);
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            let info = client
                .create(json!({
                    "command": command,
                    "cwd": current_dir_string(),
                    "rows": 40,
                    "cols": 120,
                    "title": format!("ssh {}", target.destination()),
                }))
                .map_err(|e| map_err("cannot start remote session", e))?;
            let _ = write_audit(
                "user",
                "user",
                "remote.shell",
                &target.destination(),
                "allow",
                "ok",
                "medium",
            );
            if json_out {
                return print_json(&serde_json::to_value(&info).unwrap_or(json!({})));
            }
            println!("{}", info.id);
            super::session::attach_to(&client, &info.id, 0, false)
        }
        "upload" | "download" => {
            let rest = parsed.rest();
            let target = rest
                .first()
                .ok_or_else(|| fail("usage: z remote upload <target> <local> <remote>"))?;
            let local = rest
                .get(1)
                .ok_or_else(|| fail("missing local path"))?;
            let remote_path = rest
                .get(2)
                .ok_or_else(|| fail("missing remote path"))?;
            let target = SshTarget::parse(target).map_err(remote_err)?;
            let runner = SshRunner::new(options(&parsed)?);
            let timeout = parsed
                .value("--timeout")
                .map(parse_seconds)
                .transpose()?
                .unwrap_or_else(z_remote::default_timeout);
            let output = if parsed.command("upload") == "upload" {
                runner.upload(
                    &target,
                    Path::new(local),
                    remote_path,
                    parsed.flag("--recursive"),
                    timeout,
                )
            } else {
                runner.download(
                    &target,
                    remote_path,
                    Path::new(local),
                    parsed.flag("--recursive"),
                    timeout,
                )
            }
            .map_err(remote_err)?;
            let _ = write_audit(
                "user",
                "user",
                &format!("remote.{}", parsed.command("upload")),
                &target.destination(),
                "allow",
                if output.success() { "ok" } else { "failed" },
                "medium",
            );
            if json_out {
                print_json(&serde_json::to_value(&output).unwrap_or(json!({})))
            } else {
                print!("{}", output.stdout);
                eprint!("{}", output.stderr);
                if !output.success() {
                    return Err(fail(format!(
                        "transfer exited with {:?}",
                        output.status
                    )));
                }
                Ok(())
            }
        }
        "forward" => {
            let rest = parsed.rest();
            let target = rest
                .first()
                .ok_or_else(|| {
                    fail("usage: z remote forward <target> --local-port N --remote-host H --remote-port N")
                })?;
            let target = SshTarget::parse(target).map_err(remote_err)?;
            let local_port = parsed
                .value("--local-port")
                .ok_or_else(|| fail("--local-port is required"))?
                .parse::<u16>()
                .map_err(|_| fail("invalid --local-port"))?;
            let remote_host = parsed
                .value("--remote-host")
                .ok_or_else(|| fail("--remote-host is required"))?;
            let remote_port = parsed
                .value("--remote-port")
                .ok_or_else(|| fail("--remote-port is required"))?
                .parse::<u16>()
                .map_err(|_| fail("invalid --remote-port"))?;
            let runner = SshRunner::new(options(&parsed)?);
            let forward = runner
                .forward(&target, local_port, remote_host, remote_port)
                .map_err(remote_err)?;
            let registry = forward_registry()?;
            registry.add(forward.clone()).map_err(remote_err)?;
            let _ = write_audit(
                "user",
                "user",
                "remote.forward",
                &format!("{}:{}", target.destination(), forward.id),
                "allow",
                "ok",
                "medium",
            );
            if json_out {
                print_json(&serde_json::to_value(&forward).unwrap_or(json!({})))
            } else {
                println!(
                    "{} 127.0.0.1:{} -> {}:{} (pid {})",
                    forward.id,
                    forward.local_port,
                    forward.remote_host,
                    forward.remote_port,
                    forward.pid
                );
                Ok(())
            }
        }
        "forwards" => {
            let forwards = forward_registry()?.list();
            if json_out {
                print_json(&json!({"forwards": forwards}))
            } else if forwards.is_empty() {
                println!("No active port forwards.");
                Ok(())
            } else {
                for forward in forwards {
                    println!(
                        "{} 127.0.0.1:{} -> {}:{} via {} (pid {})",
                        forward.id,
                        forward.local_port,
                        forward.remote_host,
                        forward.remote_port,
                        forward.target,
                        forward.pid
                    );
                }
                Ok(())
            }
        }
        "stop-forward" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z remote stop-forward <id>"))?;
            let stopped = forward_registry()?
                .stop(id)
                .map_err(remote_err)?;
            if json_out {
                print_json(&json!({"stopped": stopped, "id": id}))
            } else if stopped {
                println!("stopped {id}");
                Ok(())
            } else {
                Err(fail(format!("forward `{id}` not found")))
            }
        }
        "doctor" => {
            let ssh = which("ssh");
            let scp = which("scp");
            let known_hosts = SshOptions::default()
                .known_hosts
                .filter(|path| path.exists());
            let forwards = forward_registry()?.list();
            if json_out {
                print_json(&json!({
                    "ssh": ssh,
                    "scp": scp,
                    "known_hosts": known_hosts,
                    "forwards": forwards,
                    "host_key_verification": "strict",
                }))
            } else {
                println!("Remote");
                println!("  ssh:        {}", ssh.as_deref().unwrap_or("NOT FOUND"));
                println!("  scp:        {}", scp.as_deref().unwrap_or("NOT FOUND"));
                println!(
                    "  known_hosts:{}",
                    known_hosts
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "not found (host keys must be added first)".into())
                );
                println!("  host keys:  strict verification, no auto-accept");
                println!("  forwards:   {}", forwards.len());
                Ok(())
            }
        }
        "hostkey" => {
            let host = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z remote hostkey <host>"))?;
            let target = SshTarget::parse(host).map_err(remote_err)?;
            let output = std::process::Command::new("ssh-keygen")
                .args(["-F", &target.host])
                .output()
                .map_err(|e| map_err("cannot run ssh-keygen", e))?;
            let known = output.status.success();
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            if json_out {
                print_json(&json!({"host": target.host, "known": known, "keys": text}))
            } else if known {
                print!("{text}");
                Ok(())
            } else {
                Err(fail(format!(
                    "host `{}` is not in known_hosts; verify its key out-of-band before connecting",
                    target.host
                )))
            }
        }
        other => Err(fail(format!(
            "unknown remote subcommand `{other}` (hosts|exec|shell|upload|download|forward|forwards|stop-forward|hostkey|doctor)"
        ))),
    }
}

fn options(parsed: &Parsed) -> ZenResult<SshOptions> {
    let mut options = SshOptions::default();
    if let Some(identity) = parsed.value("--identity") {
        options.identity = Some(PathBuf::from(identity));
    }
    options.jump = parsed.values_of("--jump").to_vec();
    if let Some(port) = parsed.value("--port") {
        options.port = Some(port.parse::<u16>().map_err(|_| fail("invalid --port"))?);
    }
    if let Some(known_hosts) = parsed.value("--known-hosts") {
        options.known_hosts = Some(PathBuf::from(known_hosts));
    }
    if let Some(timeout) = parsed.value("--timeout") {
        let seconds = parse_seconds(timeout)?;
        options.connect_timeout_seconds = seconds.as_secs().max(1);
    }
    Ok(options)
}

fn forward_registry() -> ZenResult<ForwardRegistry> {
    let path = ForwardRegistry::default_path()
        .ok_or_else(|| fail("cannot determine remote data directory"))?;
    Ok(ForwardRegistry::new(path))
}

fn parse_seconds(value: &str) -> ZenResult<Duration> {
    if let Some(seconds) = value.strip_suffix('s') {
        seconds
            .parse()
            .map(Duration::from_secs)
            .map_err(|_| fail("invalid timeout"))
    } else if let Some(minutes) = value.strip_suffix('m') {
        minutes
            .parse::<u64>()
            .map(|minutes| Duration::from_secs(minutes * 60))
            .map_err(|_| fail("invalid timeout"))
    } else {
        value
            .parse()
            .map(Duration::from_secs)
            .map_err(|_| fail("invalid timeout"))
    }
}

fn current_dir_string() -> String {
    std::env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| ".".into())
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn remote_err(error: RemoteError) -> ZenError {
    fail(error.to_string())
}
