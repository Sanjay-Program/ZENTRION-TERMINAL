//! End-to-end CLI tests (Phase 1 §31/§32).
//!
//! These run the real `z` binary in a temporary, isolated environment
//! (ZENTRION_CONFIG_DIR / ZENTRION_DATA_DIR) and assert on stdout, stderr
//! and exit codes. No network is used.

use std::path::{Path, PathBuf};
use std::process::Command;

fn z_bin() -> PathBuf {
    // target/<profile>/z, relative to the test binary location.
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("z")
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zen-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("proj")).unwrap();
        Self { dir }
    }

    fn cmd_in(&self, cwd: &Path) -> Command {
        let mut c = Command::new(z_bin());
        c.current_dir(cwd);
        c.env("ZENTRION_CONFIG_DIR", self.dir.join("config"));
        c.env("ZENTRION_DATA_DIR", self.dir.join("data"));
        c
    }

    fn project(&self) -> PathBuf {
        self.dir.join("proj")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(env: &Env, cwd: &Path, args: &[&str]) -> (String, String, i32) {
    let out = env
        .cmd_in(cwd)
        .args(args)
        .output()
        .expect("failed to run z");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn version_reports_platform_and_build() {
    let env = Env::new("version");
    let (out, _, code) = run(&env, &env.project(), &["version"]);
    assert_eq!(code, 0);
    assert!(out.contains("Zentrion"));
    assert!(out.contains("platform:"));
    assert!(out.contains("build type:"));
}

#[test]
fn version_json_is_valid() {
    let env = Env::new("version-json");
    let (out, _, code) = run(&env, &env.project(), &["version", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert!(v["platform"].is_string());
    assert!(v["architecture"].is_string());
}

#[test]
fn help_lists_commands() {
    let env = Env::new("help");
    let (out, _, code) = run(&env, &env.project(), &["--help"]);
    assert_eq!(code, 0);
    for cmd in [
        "version", "doctor", "status", "config", "init", "project", "policy", "audit", "run",
    ] {
        assert!(out.contains(cmd), "help should mention {cmd}");
    }
}

#[test]
fn doctor_runs_offline_and_exits_zero() {
    let env = Env::new("doctor");
    let (out, _, code) = run(&env, &env.project(), &["doctor"]);
    assert_eq!(code, 0);
    assert!(out.contains("no network") || out.contains("Network"));
}

#[test]
fn status_never_prints_secrets() {
    let env = Env::new("status");
    let (out, _, code) = run(&env, &env.project(), &["status"]);
    assert_eq!(code, 0);
    assert!(out.contains("never displayed"));
}

#[test]
fn init_creates_project_then_project_check_passes() {
    let env = Env::new("init");
    let proj = env.project();
    let (out, _, code) = run(&env, &proj, &["init", ".", "--name", "demo"]);
    assert_eq!(code, 0, "init failed: {out}");
    assert!(proj.join(".zentrion/policy.yaml").exists());
    assert!(proj.join(".zentrion/project.yaml").exists());

    let (out2, _, code2) = run(&env, &proj, &["project", "--check"]);
    assert_eq!(code2, 0, "project check failed: {out2}");
}

#[test]
fn init_refuses_to_overwrite() {
    let env = Env::new("init-twice");
    let proj = env.project();
    let (_, _, c1) = run(&env, &proj, &["init", ".", "--name", "demo"]);
    assert_eq!(c1, 0);
    let (_, err, c2) = run(&env, &proj, &["init", ".", "--name", "demo"]);
    assert_ne!(c2, 0, "second init must fail");
    assert!(err.contains("already contains"));
}

#[test]
fn invalid_project_name_rejected() {
    let env = Env::new("bad-name");
    let (_, err, code) = run(&env, &env.project(), &["init", ".", "--name", "../evil"]);
    assert_ne!(code, 0);
    assert!(err.contains("path separators") || err.contains("invalid"));
}

#[test]
fn run_is_denied_without_policy_grant() {
    let env = Env::new("run-deny");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    let (out, _, code) = run(&env, &proj, &["run", "echo", "hello"]);
    assert_eq!(code, 2, "policy denial should exit 2");
    assert!(out.contains("blocked") || out.contains("✗"));
}

#[test]
fn run_executes_when_policy_permits() {
    let env = Env::new("run-allow");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    // Grant `echo` in the project policy.
    let pol = proj.join(".zentrion/policy.yaml");
    let text = std::fs::read_to_string(&pol).unwrap().replace(
        "process:\n  spawn: []",
        "process:\n  spawn:\n    - \"echo\"",
    );
    std::fs::write(&pol, text).unwrap();

    let (out, _, code) = run(&env, &proj, &["run", "echo", "hello"]);
    assert_eq!(code, 0, "expected success, got {out}");
    assert!(out.contains("hello"));
}

#[test]
fn run_does_not_interpret_shell_metacharacters() {
    let env = Env::new("run-inject");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    let pol = proj.join(".zentrion/policy.yaml");
    let text = std::fs::read_to_string(&pol).unwrap().replace(
        "process:\n  spawn: []",
        "process:\n  spawn:\n    - \"echo\"",
    );
    std::fs::write(&pol, text).unwrap();

    let (out, _, code) = run(&env, &proj, &["run", "echo", "a; echo PWNED"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("a; echo PWNED"),
        "metacharacters must be literal: {out}"
    );
    // A shell would have run `echo PWNED` as a second command and emitted an
    // extra line. Expect exactly one non-empty output line.
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "expected one literal line, got: {lines:?}");
}

#[test]
fn audit_log_verifies_after_activity() {
    let env = Env::new("audit");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    run(&env, &proj, &["run", "echo", "x"]); // denied -> still audited
    let (out, _, code) = run(&env, &proj, &["audit", "verify"]);
    assert_eq!(code, 0);
    assert!(out.contains("verified") || out.contains("empty"));
}

#[test]
fn unknown_command_fails() {
    let env = Env::new("unknown");
    let (_, _, code) = run(&env, &env.project(), &["not-a-command"]);
    assert_ne!(code, 0);
}

#[test]
fn project_check_fails_outside_project() {
    let env = Env::new("noproj");
    let (_, _, code) = run(&env, &env.project(), &["project"]);
    assert_ne!(code, 0);
}

#[test]
fn config_get_and_set_roundtrip() {
    let env = Env::new("config");
    let proj = env.project();
    let (_, _, c1) = run(&env, &proj, &["config", "set", "log_level", "debug"]);
    assert_eq!(c1, 0);
    let (out, _, c2) = run(&env, &proj, &["config", "get", "log_level"]);
    assert_eq!(c2, 0);
    assert!(out.contains("debug"));
}

#[test]
fn config_rejects_invalid_log_level() {
    let env = Env::new("config-bad");
    let (_, err, code) = run(
        &env,
        &env.project(),
        &["config", "set", "log_level", "nonsense"],
    );
    assert_ne!(code, 0);
    assert!(err.contains("invalid log level"));
}

#[test]
fn config_cannot_set_unknown_keys() {
    let env = Env::new("config-unknown");
    let (_, err, code) = run(&env, &env.project(), &["config", "set", "secret_key", "x"]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown") || err.contains("non-settable"));
}
