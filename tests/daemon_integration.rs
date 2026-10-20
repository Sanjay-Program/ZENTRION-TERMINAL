//! End-to-end daemon test: real process, real TCP loopback, real policy gate.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn z_bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "z.exe" } else { "z" })
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct Daemon {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        Self::start_with_token(None)
    }

    fn start_with_token(token: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-daemon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::create_dir_all(dir.join("data")).unwrap();
        let port = free_port();
        let mut command = Command::new(z_bin());
        command
            .args(["daemon", "start", "--port", &port.to_string()])
            .env("ZENTRION_CONFIG_DIR", dir.join("config"))
            .env("ZENTRION_DATA_DIR", dir.join("data"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(token) = token {
            command.env("ZENTRION_DAEMON_TOKEN", token);
        }
        let child = command.spawn().expect("start daemon");
        let mut daemon = Self { child, port, dir };
        daemon.wait_ready();
        daemon
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon did not start listening");
    }

    fn request(&self, json: &str) -> serde_json::Value {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(json.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("valid JSON response")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn daemon_answers_status_with_real_metrics() {
    let daemon = Daemon::start();
    let response = daemon.request(r#"{"id":"t1","command":"status","args":[]}"#);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["request_id"], "t1");
    assert!(response["metrics"]["pid"].as_u64().unwrap_or(0) > 0);
    assert!(response["stdout"].as_str().unwrap().contains("zentrion"));
}

#[test]
fn daemon_denies_unpermitted_execution_and_never_runs_it() {
    let daemon = Daemon::start();
    let marker = daemon.dir.join("PWNED");
    let json = format!(
        r#"{{"id":"t2","command":"sh","args":["-c","touch {}"]}}"#,
        marker.display()
    );
    let response = daemon.request(&json);
    assert_eq!(response["status"], "denied");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists(), "denied command must not execute");
}

#[test]
fn daemon_rejects_invalid_json() {
    let daemon = Daemon::start();
    let response = daemon.request("{not json}");
    assert_eq!(response["status"], "error");
}

#[test]
fn daemon_requires_the_shared_token_when_configured() {
    let daemon = Daemon::start_with_token(Some("correct-horse-battery-staple"));
    let response = daemon.request(r#"{"id":"t3","command":"status","args":[]}"#);
    assert_eq!(response["status"], "error");
    assert!(response["error"]
        .as_str()
        .unwrap_or("")
        .contains("unauthorized"));

    let response = daemon.request(
        r#"{"id":"t4","command":"status","args":[],"token":"correct-horse-battery-staple"}"#,
    );
    assert_eq!(response["status"], "ok");
}
