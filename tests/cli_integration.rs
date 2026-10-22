//! End-to-end CLI tests (Phase 1 §31/§32).
//!
//! These run the real `z` binary in a temporary, isolated environment
//! (ZENTRION_CONFIG_DIR / ZENTRION_DATA_DIR) and assert on stdout, stderr
//! and exit codes. No network is used.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn z_bin() -> PathBuf {
    // target/<profile>/z, relative to the test binary location.
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "z.exe" } else { "z" })
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
fn audit_key_signs_future_events_and_verify_detects_edits() {
    let env = Env::new("audit-sign");
    let (out, _, code) = run(&env, &env.project(), &["audit", "key", "--json"]);
    assert_eq!(code, 0, "{out}");
    let key: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(key["public_key"].as_str().unwrap().len(), 64);

    // A denied command still produces an audit event.
    let _ = run(&env, &env.project(), &["run", "/bin/true"]);
    let (out, _, code) = run(&env, &env.project(), &["audit", "verify", "--json"]);
    assert_eq!(code, 0, "{out}");
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(report["ok"], true);
    assert_eq!(report["signatures"]["valid"], true);
    assert!(report["signatures"]["signed_events"].as_u64().unwrap() >= 1);

    // Editing a signature must fail verification.
    let log = env.dir.join("data/audit/events.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    let tampered = text.replacen("\"signature\":\"", "\"signature\":\"00", 1);
    assert_ne!(text, tampered);
    std::fs::write(&log, tampered).unwrap();
    let (out, _, code) = run(&env, &env.project(), &["audit", "verify", "--json"]);
    assert_ne!(code, 0, "tampered signature must fail: {out}");
}

#[test]
fn plugin_run_executes_a_real_wasm_module() {
    let env = Env::new("plugin-run");
    // A 79-byte module exporting memory/alloc/run that echoes its input.
    const MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x60, 0x01, 0x7f, 0x01,
        0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, 0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x03, 0x01,
        0x00, 0x01, 0x07, 0x18, 0x03, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x05,
        0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01, 0x0a, 0x13,
        0x02, 0x04, 0x00, 0x41, 0x00, 0x0b, 0x0c, 0x00, 0x20, 0x00, 0xad, 0x42, 0x20, 0x86, 0x20,
        0x01, 0xad, 0x84, 0x0b,
    ];
    let wasm = env.project().join("echo.wasm");
    std::fs::write(&wasm, MODULE).unwrap();
    std::fs::write(
        env.project().join("echo.wasm.json"),
        r#"{"name":"echo","version":"1.0.0","plugin_type":"wasm","entrypoint":"run","permissions":["log","network"]}"#,
    )
    .unwrap();

    let (out, err, code) = run(
        &env,
        &env.project(),
        &["plugin", "run", "echo.wasm", "--input", "hello-wasm"],
    );
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(out.contains("hello-wasm"), "{out}");

    let (out, _, code) = run(
        &env,
        &env.project(),
        &["plugin", "capabilities", "echo.wasm", "--json"],
    );
    assert_eq!(code, 0);
    let caps: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(caps["unsupported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "network"));
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

// ---------------------------------------------------------------------------
// Subsystem surfaces added after the first release: they must do real work,
// not print success.
// ---------------------------------------------------------------------------

#[test]
fn security_scan_finds_a_planted_credential_and_names_the_file() {
    let env = Env::new("scan-secret");
    let proj = env.project();
    let key = concat!("AKIA", "Q7W2", "E9R4", "T1Y6", "U3I8");
    std::fs::write(
        proj.join("config.env"),
        format!("AWS_ACCESS_KEY_ID={key}\n"),
    )
    .unwrap();
    let (out, _, code) = run(&env, &proj, &["security", "scan", "."]);
    assert_eq!(code, 0);
    assert!(out.contains("AWS access key"), "got: {out}");
    assert!(
        out.contains("config.env"),
        "finding should name the file: {out}"
    );
    assert!(!out.contains(key), "scan output must not echo the secret");
}

#[test]
fn security_sast_flags_dynamic_evaluation() {
    let env = Env::new("sast");
    let proj = env.project();
    std::fs::write(proj.join("app.js"), "eval(userInput);\n").unwrap();
    let (out, _, code) = run(&env, &proj, &["security", "sast"]);
    assert_eq!(code, 0);
    assert!(out.contains("dynamic code evaluation"), "got: {out}");
    assert!(out.contains("app.js"));
}

#[test]
fn security_posture_reports_a_verified_audit_chain() {
    let env = Env::new("posture");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "posture"]);
    let (out, _, code) = run(&env, &proj, &["security", "posture"]);
    assert_eq!(code, 0);
    assert!(out.contains("policy:"));
    assert!(out.contains("audit:"));
}

#[test]
fn theme_list_and_set_roundtrip_through_config() {
    let env = Env::new("theme");
    let proj = env.project();
    let (out, _, code) = run(&env, &proj, &["theme", "list"]);
    assert_eq!(code, 0);
    assert!(out.contains("dracula"));

    let (out, _, code) = run(&env, &proj, &["theme", "set", "dracula"]);
    assert_eq!(code, 0, "theme set failed: {out}");

    let (out, _, code) = run(&env, &proj, &["config", "get", "theme"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "dracula");

    let (_, err, code) = run(&env, &proj, &["theme", "set", "not-a-theme"]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown theme"));
}

#[test]
fn ai_inventory_reports_real_configuration_not_fake_models() {
    let env = Env::new("ai-inventory");
    let proj = env.project();
    let (out, _, code) = run(&env, &proj, &["ai", "inventory"]);
    assert_eq!(code, 0);
    assert!(!out.contains("gpt-4"), "must not invent providers: {out}");
    assert!(!out.contains("Claude"), "must not invent providers: {out}");
    assert!(
        out.contains("none configured") || out.contains("ollama"),
        "got: {out}"
    );
}

#[test]
fn do_routes_a_status_intent_to_the_real_status_command() {
    let env = Env::new("do-status");
    let (out, _, code) = run(&env, &env.project(), &["do", "what", "is", "my", "status"]);
    assert_eq!(code, 0);
    assert!(out.contains("Intent:"));
    assert!(out.contains("Zentrion status"));
}

#[test]
fn plugin_validation_rejects_a_non_wasm_file() {
    let env = Env::new("plugin-bad");
    let proj = env.project();
    let path = proj.join("evil.wasm");
    std::fs::write(&path, b"#!/bin/sh\necho pwned\n").unwrap();
    let (_, err, code) = run(&env, &proj, &["plugin", "inspect", path.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(
        err.contains("WebAssembly") || err.contains("bad magic"),
        "got: {err}"
    );
}

#[test]
fn plugin_validation_accepts_a_minimal_wasm_header() {
    let env = Env::new("plugin-ok");
    let proj = env.project();
    let path = proj.join("hello.wasm");
    std::fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
    let (out, _, code) = run(&env, &proj, &["plugin", "inspect", path.to_str().unwrap()]);
    assert_eq!(code, 0, "plugin inspect failed: {out}");
    // Inspect validates only: this header has no memory/alloc/run, so if it
    // tried to execute, the command would fail instead of printing a report.
    assert!(out.contains("Validated plugin"), "{out}");
    assert!(
        out.contains("plugin run"),
        "inspect should point at the capability-gated runner: {out}"
    );
}

#[test]
fn tls_engine_is_wired_and_reports_failure_honestly() {
    let env = Env::new("tls-engine");
    let (out, _, code) = run(&env, &env.project(), &["--json", "engine", "info", "tls"]);
    assert_eq!(code, 0, "{out}");
    let info: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(info["capabilities"]["supported"], true);
    assert!(info["capabilities"]["description"]
        .as_str()
        .unwrap()
        .contains("rustls"));

    // A refused port must be reported as a failed inspection, not fabricated
    // certificate data, and the CLI itself succeeds with a status object.
    let (out, _, code) = run(
        &env,
        &env.project(),
        &["--json", "engine", "run", "tls", "inspect", "127.0.0.1:1"],
    );
    assert_eq!(code, 0, "{out}");
    let result: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(result["engine"], "tls");
    assert_eq!(result["status"], "failed");
}

#[test]
fn upgrade_without_a_manifest_fails_honestly() {
    let env = Env::new("upgrade");
    let (_, err, code) = run(&env, &env.project(), &["upgrade", "check"]);
    assert_ne!(code, 0);
    assert!(err.contains("update channel"), "got: {err}");
}

#[test]
fn daemon_status_without_a_daemon_fails_clearly() {
    let env = Env::new("daemon-down");
    let (_, err, code) = run(
        &env,
        &env.project(),
        &["daemon", "status", "--port", "29199"],
    );
    assert_ne!(code, 0);
    assert!(err.contains("not reachable"), "got: {err}");
}

#[test]
fn code_status_detects_a_cargo_project() {
    let env = Env::new("code-status");
    let proj = env.project();
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n",
    )
    .unwrap();
    let (out, _, code) = run(&env, &proj, &["code", "status"]);
    assert_eq!(code, 0);
    assert!(out.contains("rust (cargo)"));
    assert!(out.contains("cargo test"));
}

#[test]
fn code_allow_grants_the_detected_toolchain_explicitly() {
    let env = Env::new("code-allow");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n",
    )
    .unwrap();
    let (out, _, code) = run(&env, &proj, &["code", "allow"]);
    assert_eq!(code, 0, "code allow failed: {out}");
    let policy = std::fs::read_to_string(proj.join(".zentrion/policy.yaml")).unwrap();
    assert!(policy.contains("cargo"));
}

#[test]
fn network_probe_requires_explicit_permission() {
    let env = Env::new("net-deny");
    let (_, err, code) = run(&env, &env.project(), &["network", "dns", "localhost"]);
    assert_eq!(code, 2);
    assert!(
        err.contains("policy") || err.contains("not allow"),
        "got: {err}"
    );
}

#[test]
fn cloud_scan_flags_world_open_ingress() {
    let env = Env::new("cloud-scan");
    let proj = env.project();
    std::fs::write(
        proj.join("main.tf"),
        "resource \"aws_security_group\" \"x\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n",
    )
    .unwrap();
    let (out, _, code) = run(&env, &proj, &["cloud", "scan", "."]);
    assert_eq!(code, 0);
    assert!(
        out.contains("0.0.0.0/0") || out.contains("internet"),
        "got: {out}"
    );
}

#[test]
fn vault_secret_names_are_listed_but_values_are_not() {
    let env = Env::new("vault");
    let proj = env.project();
    let marker = concat!("SUPER", "SECRET", "-VALUE-", "123456");
    let (_, err, code) = run(&env, &proj, &["config", "set-secret", "demo_key", marker]);
    assert_eq!(code, 0, "set-secret failed: {err}");

    let (out, _, code) = run(&env, &proj, &["config", "list-secrets"]);
    assert_eq!(code, 0);
    assert!(out.contains("demo_key"));
    assert!(
        !out.contains(marker),
        "secret value must never be printed: {out}"
    );

    let (out, _, code) = run(&env, &proj, &["config", "delete-secret", "demo_key"]);
    assert_eq!(code, 0);
    assert!(out.contains("Deleted"));
    let (out, _, _) = run(&env, &proj, &["config", "list-secrets"]);
    assert!(out.contains("No secrets") || !out.contains("demo_key"));
}

#[test]
fn dependency_sbom_reads_the_manifest() {
    let env = Env::new("sbom-deps");
    let proj = env.project();
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.2.0\"\n\n[dependencies]\nserde = \"1\"\nregex = \"1\"\n",
    )
    .unwrap();
    let (out, _, code) = run(&env, &proj, &["sbom", "--deps"]);
    assert_eq!(code, 0, "sbom failed: {out}");
    assert!(out.contains("demo"));
    assert!(out.contains("serde"));
    assert!(out.contains("regex"));
}

#[test]
fn code_test_runs_through_the_broker_when_allowed() {
    let env = Env::new("code-run");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[workspace]\n",
    )
    .unwrap();
    // The generated project policy denies process spawning; code allow grants
    // the detected toolchain explicitly.
    let (out, _, code) = run(&env, &proj, &["code", "allow"]);
    assert_eq!(code, 0, "code allow failed: {out}");
    let (out, _, code) = run(&env, &proj, &["run", "cargo", "--version"]);
    assert_eq!(code, 0, "brokered cargo failed: {out}");
    assert!(out.contains("cargo"), "got: {out}");
}

#[cfg(unix)]
#[test]
fn mcp_connect_performs_a_real_handshake() {
    let env = Env::new("mcp");
    let script = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method = req.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "integration-server", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "Echo input", "inputSchema": {"type": "object"}}]}
    else:
        result = {}
    if "id" in req:
        print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)
"#;
    let (out, err, code) = run(
        &env,
        &env.project(),
        &["mcp", "connect", "--allow", "python3", "-u", "-c", script],
    );
    assert_eq!(code, 0, "mcp connect failed: {out}\n{err}");
    assert!(out.contains("integration-server"), "got: {out}");
    assert!(out.contains("echo"), "got: {out}");
}

#[test]
fn bundled_native_tools_require_an_explicit_allowlist() {
    let env = Env::new("bundled");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);

    let (_, err, code) = run(&env, &proj, &["run", "z-sysinfo"]);
    assert_eq!(code, 2, "bundled tool must be denied by default: {err}");
    assert!(
        err.contains("allowlist") || err.contains("blocked"),
        "got: {err}"
    );

    let pol = proj.join(".zentrion/policy.yaml");
    let text = std::fs::read_to_string(&pol)
        .unwrap()
        .replace("tools:\n  allow: []", "tools:\n  allow:\n    - z-sysinfo");
    std::fs::write(&pol, text).unwrap();
    let (out, _, code) = run(&env, &proj, &["run", "z-sysinfo"]);
    assert_eq!(code, 0, "allowlisted bundled tool failed: {out}");
    assert!(out.contains("OS:"));
}

#[test]
fn bundled_network_tools_require_network_permission() {
    let env = Env::new("bundled-net");
    let proj = env.project();
    run(&env, &proj, &["init", ".", "--name", "demo"]);
    let pol = proj.join(".zentrion/policy.yaml");
    let text = std::fs::read_to_string(&pol)
        .unwrap()
        .replace("tools:\n  allow: []", "tools:\n  allow:\n    - z-curl");
    std::fs::write(&pol, text).unwrap();
    let (_, err, code) = run(&env, &proj, &["run", "z-curl", "https://example.com"]);
    assert_eq!(code, 2, "network must be denied: {err}");
    assert!(err.contains("network"), "got: {err}");
}

#[test]
fn remote_scans_require_network_permission() {
    let env = Env::new("scan-remote");
    let (_, err, code) = run(&env, &env.project(), &["scan", "example.com"]);
    assert_eq!(code, 2, "remote scan must be policy-gated: {err}");
    assert!(
        err.contains("policy") || err.contains("not allow"),
        "got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn mcp_server_startup_requires_process_permission() {
    let env = Env::new("mcp-deny");
    let (_, err, code) = run(
        &env,
        &env.project(),
        &["mcp", "connect", "python3", "-c", "print(1)"],
    );
    assert_eq!(code, 2, "MCP server should be policy-gated: {err}");
    assert!(
        err.contains("policy") || err.contains("not allow"),
        "got: {err}"
    );
}

// --- Terminal, workspace, context, checkpoint, workflow and security --------

#[test]
fn config_rejects_unknown_key_with_line_number() {
    let env = Env::new("cfg-unknown");
    let file = env.dir.join("bad.toml");
    std::fs::write(&file, "[ui]\ntheme = \"dracula\"\nnot_a_key = 1\n").unwrap();
    let (_, err, code) = run(
        &env,
        &env.project(),
        &["config", "validate", "--file", file.to_str().unwrap()],
    );
    assert_ne!(code, 0);
    assert!(err.contains("not_a_key"), "{err}");
    assert!(err.contains(":3:"), "{err}");
}

#[test]
fn config_imports_windows_terminal_font_and_binding() {
    let env = Env::new("cfg-import");
    let file = env.dir.join("settings.json");
    std::fs::write(
        &file,
        r#"{"profiles":{"defaults":{"font":{"face":"Cascadia Code","size":14}}},"keybindings":[{"keys":"alt+2","command":"newTab"}]}"#,
    )
    .unwrap();
    let (out, err, code) = run(
        &env,
        &env.project(),
        &["config", "import", file.to_str().unwrap(), "--write"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("font_family"), "{out}");
    let written = std::fs::read_to_string(env.dir.join("config/config.toml")).unwrap();
    assert!(written.contains("Cascadia Code"));
    assert!(written.contains("alt+2"));
}

#[test]
fn context_indexes_and_packs_with_citations() {
    let env = Env::new("context");
    let root = env.project();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn payment_total(amount: u64) -> u64 { amount * 2 }\n",
    )
    .unwrap();
    let (_, err, code) = run(&env, &root, &["context", "index", "."]);
    assert_eq!(code, 0, "{err}");
    let (out, err, code) = run(
        &env,
        &root,
        &["context", "pack", "payment", "--budget", "400"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("src/lib.rs:"), "{out}");
    assert!(out.contains("payment_total"), "{out}");
    let (out, _, code) = run(&env, &root, &["context", "search", "payment"]);
    assert_eq!(code, 0);
    assert!(out.contains("src/lib.rs"));
}

#[test]
fn checkpoint_rolls_back_and_removes_added_files() {
    let env = Env::new("checkpoint");
    let root = env.project();
    std::fs::write(root.join("file.txt"), "original\n").unwrap();
    let (out, err, code) = run(&env, &root, &["checkpoint", "create", "."]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim();
    assert!(id.starts_with("cp_"), "{out}");
    std::fs::write(root.join("file.txt"), "modified\n").unwrap();
    std::fs::write(root.join("added.txt"), "added\n").unwrap();
    let (out, err, code) = run(&env, &root, &["checkpoint", "diff", id, "."]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("Modified file.txt") || out.contains("Modified"),
        "{out}"
    );
    assert!(out.contains("added.txt"), "{out}");
    let (_, err, code) = run(
        &env,
        &root,
        &["checkpoint", "restore", id, ".", "--no-backup"],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::read_to_string(root.join("file.txt")).unwrap(),
        "original\n"
    );
    assert!(!root.join("added.txt").exists());
}

#[test]
fn checkpoint_restore_hunk_reverts_only_the_selected_hunk() {
    let env = Env::new("checkpoint-hunk");
    let root = env.project();
    let original: String = (1..=20).map(|i| format!("line{i:02}\n")).collect();
    std::fs::write(root.join("numbers.txt"), &original).unwrap();
    let (out, err, code) = run(&env, &root, &["checkpoint", "create", "."]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim();
    assert!(id.starts_with("cp_"), "{out}");

    let modified = original
        .replace("line02", "CHANGED02")
        .replace("line19", "CHANGED19");
    std::fs::write(root.join("numbers.txt"), &modified).unwrap();
    let (diff, err, code) = run(&env, &root, &["checkpoint", "diff", id, "."]);
    assert_eq!(code, 0, "{err}");
    assert!(diff.matches("@@").count() >= 2, "{diff}");

    let (_, err, code) = run(
        &env,
        &root,
        &[
            "checkpoint",
            "restore",
            id,
            "--hunk",
            "numbers.txt:0",
            "--no-backup",
        ],
    );
    assert_eq!(code, 0, "{err}");
    let after = std::fs::read_to_string(root.join("numbers.txt")).unwrap();
    assert!(after.contains("line02"), "{after}");
    assert!(!after.contains("CHANGED02"), "{after}");
    assert!(
        after.contains("CHANGED19"),
        "second hunk must stay: {after}"
    );
}

#[test]
fn workflow_runs_approval_condition_and_parallel() {
    let env = Env::new("workflow");
    let root = env.project();
    let file = root.join("wf.yaml");
    std::fs::write(
        &file,
        r#"
name: it
steps:
  - id: hello
    run: "echo hello"
  - id: gate
    approve: "proceed"
  - id: after
    run: "echo after"
    when: "steps.gate.approved"
  - id: fan
    parallel:
      - id: a
        run: "echo a"
      - id: b
        run: "echo b"
"#,
    )
    .unwrap();
    let (out, err, code) = run(
        &env,
        &root,
        &["workflow", "run", file.to_str().unwrap(), "--approve"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Succeeded"), "{out}");
    assert!(out.contains("gate"), "{out}");
    let (out, _, code) = run(&env, &root, &["audit", "verify"]);
    assert_eq!(code, 0);
    assert!(out.contains("verified"), "{out}");
}

#[test]
fn security_blocks_out_of_scope_before_execution() {
    let env = Env::new("security");
    let root = env.project();
    let (out, err, code) = run(
        &env,
        &root,
        &[
            "engagement",
            "create",
            "--name",
            "IT",
            "--client",
            "Acme",
            "--authorization",
            "Signed authorization for integration testing",
            "--authorized-by",
            "tester",
            "--scope",
            "example.com",
            "--rule",
            "stay in scope",
        ],
    );
    assert_eq!(code, 0, "{err}");
    let id = out.trim().to_string();
    let marker = root.join("marker");
    let command = format!("touch {}", marker.display());
    let (_, err, code) = run(
        &env,
        &root,
        &[
            "engagement",
            "run",
            &id,
            &command,
            "--target",
            "evil.example",
        ],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("out of scope") || err.contains("blocked"),
        "{err}"
    );
    assert!(!marker.exists(), "out-of-scope command must not run");
    let (out, _, code) = run(&env, &root, &["engagement", "verify", &id]);
    assert_eq!(code, 0);
    assert!(out.contains("valid"), "{out}");
}

#[test]
fn session_daemon_records_blocks_and_replays() {
    if !cfg!(unix) {
        return;
    }
    let env = Env::new("session");
    let root = env.project();
    let socket = env.dir.join("session.sock");
    // Point the client at an isolated socket; the CLI spawns the daemon.
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd
        .args([
            "session",
            "create",
            "--shell",
            "/bin/bash",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("create session");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(id.starts_with("s_"));
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "input", &id, "echo integration-block"]);
    assert!(cmd.status().unwrap().success());
    // Blocks are persisted asynchronously by the daemon's writer thread; poll
    // instead of assuming a fixed delay.
    let mut value = serde_json::Value::Null;
    let mut found = false;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut cmd = env.cmd_in(&root);
        cmd.env("ZENTRION_SESSION_SOCKET", &socket);
        cmd.args(["--json", "session", "attach", &id]);
        let out = cmd.output().unwrap();
        assert!(out.status.success());
        value = serde_json::from_slice(&out.stdout).unwrap();
        found = value["blocks"].as_array().unwrap().iter().any(|block| {
            block["command"]
                .as_str()
                .map(|command| command.contains("echo integration-block"))
                .unwrap_or(false)
        });
        if found {
            break;
        }
    }
    assert!(
        value["contents"]
            .as_str()
            .unwrap()
            .contains("integration-block"),
        "screen contents missing command output"
    );
    assert!(found, "command block was not recorded: {value:#}");
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "close", &id, "--force"]);
    assert!(cmd.status().unwrap().success());
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "stop"]);
    let _ = cmd.status();
}

#[test]
fn persisted_scrollback_survives_daemon_shutdown() {
    if !cfg!(unix) {
        return;
    }
    let env = Env::new("scrollback-persist");
    let root = env.project();
    let socket = env.dir.join("session.sock");
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd
        .args([
            "session",
            "create",
            "--shell",
            "/bin/bash",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("create session");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(id.starts_with("s_"));

    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "input", &id, "echo persisted-marker-42"]);
    assert!(cmd.status().unwrap().success());
    std::thread::sleep(std::time::Duration::from_millis(800));

    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "stop"]);
    let _ = cmd.status();

    // The daemon is gone; both commands read the durable snapshot directly.
    let (history, err, code) = run(&env, &root, &["session", "history"]);
    assert_eq!(code, 0, "{err}");
    assert!(history.contains(&id), "history: {history}");

    let (scrollback, err, code) = run(
        &env,
        &root,
        &["session", "scrollback", &id, "--tail", "131072"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        scrollback.contains("persisted-marker-42"),
        "scrollback did not contain the command output: {scrollback}"
    );
}

#[test]
fn agent_runs_are_owned_by_the_session_daemon_and_survive_cli_exit() {
    if !cfg!(unix) {
        return;
    }
    let env = Env::new("agent-daemon");
    let root = env.project();
    let socket = env.dir.join("session.sock");
    let adapters = env.dir.join("data/agents");
    std::fs::create_dir_all(&adapters).unwrap();
    std::fs::write(
        adapters.join("slow.yaml"),
        r##"
version: 1
id: slow
name: Slow Agent
command: /bin/sh
args: ["-c", "echo agent-started; sleep 2; echo agent-done"]
detect: {binaries: [], env: []}
events: {mode: screen, status_patterns: []}
permissions: {default_profile: agent-readonly, allow_write: false, allow_network: false}
ui: {badge: SL, color: "#fff"}
"##,
    )
    .unwrap();
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd
        .args(["agent", "run", "slow", "--prompt", "hello", "--detach"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(id.starts_with("a_"), "{id}");

    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd.args(["agent", "list"]).output().unwrap();
    assert!(out.status.success());
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains(&id), "{listing}");
    assert!(listing.contains("running"), "{listing}");

    // The CLI process that launched the agent is gone; the daemon keeps it.
    std::thread::sleep(std::time::Duration::from_millis(2600));
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd.args(["agent", "list"]).output().unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains(&id), "{listing}");
    assert!(listing.contains("done"), "{listing}");

    let trace = env
        .dir
        .join("data/agents/traces")
        .join(format!("{id}.jsonl"));
    assert!(trace.exists(), "agent trace missing");
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "stop"]);
    let _ = cmd.status();
}

#[test]
fn models_ask_uses_configured_provider_and_records_usage() {
    let env = Env::new("models-ask");
    let script = r#"
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n))
        assert body["messages"][-1]["content"] == "hello models"
        payload = json.dumps({
            "choices": [{"message": {"content": "mock answer"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), H)
print(server.server_port, flush=True)
server.serve_forever()
"#;
    let mut child = Command::new("python3")
        .args(["-u", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 is required for the mock provider");
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut port = String::new();
    reader.read_line(&mut port).unwrap();
    let port = port.trim().to_string();
    assert!(!port.is_empty());
    let config = env.dir.join("config/config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[models]
default = "local/test/mock"
budget_usd_per_day = 0.0
allow_cloud = false
cache = false

[models.providers."local/test"]
kind = "local"
models = ["mock"]
caps = ["chat"]
cost_per_mtok = 0.0
context = 4096
base_url = "http://127.0.0.1:{port}/v1"
"#
        ),
    )
    .unwrap();
    let (out, err, code) = run(&env, &env.project(), &["models", "ask", "hello models"]);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("mock answer"), "{out}");
    assert!(err.contains("local/test/mock"), "{err}");
    let (out, _, code) = run(&env, &env.project(), &["--json", "models", "usage"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["requests"], 1, "{value}");
    assert_eq!(value["budget_usd"], 0.0);
}

#[test]
fn remote_exec_and_upload_use_openssh_with_strict_host_keys() {
    if !cfg!(unix) {
        return;
    }
    let env = Env::new("remote");
    let bin = env.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["ssh", "scp"] {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\necho \"{name}:$@\"\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let root = env.project();
    let local = root.join("upload.txt");
    std::fs::write(&local, "payload").unwrap();

    let mut cmd = env.cmd_in(&root);
    cmd.env("PATH", &path_env);
    let out = cmd
        .args(["remote", "exec", "deploy@example.com", "uname", "-a"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("StrictHostKeyChecking=yes"), "{stdout}");
    assert!(stdout.contains("deploy@example.com"), "{stdout}");
    assert!(stdout.contains("uname -a"), "{stdout}");

    let mut cmd = env.cmd_in(&root);
    cmd.env("PATH", &path_env);
    let out = cmd
        .args([
            "remote",
            "upload",
            "example.com",
            local.to_str().unwrap(),
            "/tmp/upload.txt",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("scp:"), "{stdout}");
    assert!(stdout.contains("example.com:/tmp/upload.txt"), "{stdout}");
    assert!(stdout.contains("StrictHostKeyChecking=yes"), "{stdout}");

    let mut cmd = env.cmd_in(&root);
    cmd.env("PATH", &path_env);
    let out = cmd
        .args(["remote", "exec", "example.com", "true", "--port", "2222"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("-p 2222"));
}

#[test]
fn web_observer_serves_read_only_and_write_tokens() {
    if !cfg!(unix) {
        return;
    }
    let env = Env::new("web");
    let root = env.project();
    let socket = env.dir.join("session.sock");
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    let out = cmd
        .args([
            "session",
            "create",
            "--shell",
            "/bin/bash",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let sid = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let mut server = env.cmd_in(&root);
    server.env("ZENTRION_SESSION_SOCKET", &socket);
    server
        .args(["web", "serve", "--allow-input"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = server.spawn().expect("spawn web server");
    let token_path = env.dir.join("data/web/tokens.json");
    let mut tokens = serde_json::Value::Null;
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&token_path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                tokens = value;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!tokens.is_null(), "web token file was not written");
    let read = tokens["read"].as_str().unwrap();
    let write = tokens["write"].as_str().unwrap();
    let base = tokens["read_url"]
        .as_str()
        .unwrap()
        .split("/?")
        .next()
        .unwrap();
    let script = r#"
import json, sys, urllib.request, urllib.parse, base64, time
base, sid, read, write = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def get(path, token):
    separator = '&' if '?' in path else '?'
    return json.load(urllib.request.urlopen(base + path + separator + 'token=' + urllib.parse.quote(token)))
sessions = get('/api/sessions', read)
assert any(s['id'] == sid for s in sessions), sessions
payload = base64.b64encode(b'echo web-e2e\r').decode()
req = urllib.request.Request(base + '/api/input?token=' + urllib.parse.quote(write), data=json.dumps({'session_id': sid, 'data': payload}).encode(), headers={'content-type': 'application/json'})
assert urllib.request.urlopen(req).status == 200
time.sleep(0.7)
snapshot = get('/api/session/' + sid, read)
assert 'web-e2e' in snapshot['contents'], snapshot['contents']
stream_req = urllib.request.Request(base + '/api/session/' + sid + '/stream?token=' + urllib.parse.quote(read))
with urllib.request.urlopen(stream_req) as stream_resp:
    assert 'text/event-stream' in stream_resp.headers.get('content-type', '')
    first_line = stream_resp.readline().decode()
    assert first_line.startswith('data:'), first_line
print('ok')
"#;
    let output = Command::new("python3")
        .args(["-c", script, base, &sid, read, write])
        .output()
        .expect("python3 is required for the web test");
    let _ = child.kill();
    let _ = child.wait();
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "close", &sid, "--force"]);
    let _ = cmd.status();
    let mut cmd = env.cmd_in(&root);
    cmd.env("ZENTRION_SESSION_SOCKET", &socket);
    cmd.args(["session", "stop"]);
    let _ = cmd.status();
    assert!(
        output.status.success(),
        "web test failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ok"));
}

#[test]
fn notebook_runs_parameterized_shell_and_markdown_cells_and_exports() {
    let env = Env::new("notebook");
    let root = env.project();
    let file = root.join("demo.notebook.yaml");
    std::fs::write(
        &file,
        r##"
version: 1
name: demo
description: Integration notebook
params:
  who:
    type: string
    default: world
cells:
  - id: intro
    kind: markdown
    source: "# Hello ${who}"
  - id: check
    kind: shell
    source: "echo notebook-${who}"
    timeout: 10s
"##,
    )
    .unwrap();
    let (out, err, code) = run(
        &env,
        &root,
        &[
            "notebook",
            "run",
            file.to_str().unwrap(),
            "--param",
            "who=team",
            "--no-ai",
            "--verbose",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Succeeded"), "{out}");
    assert!(out.contains("notebook-team"), "{out}");
    let run_id = out
        .lines()
        .find_map(|line| line.strip_prefix("Run:      "))
        .unwrap()
        .trim();
    let (export, err, code) = run(
        &env,
        &root,
        &[
            "notebook",
            "export",
            file.to_str().unwrap(),
            "--run",
            run_id,
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(export.contains("# Hello team"), "{export}");
    assert!(export.contains("notebook-team"), "{export}");
    let (out, _, code) = run(&env, &root, &["audit", "verify"]);
    assert_eq!(code, 0);
    assert!(out.contains("verified"), "{out}");
}

#[test]
fn ai_fix_and_explain_provide_diagnostics_and_proposals() {
    let env = Env::new("ai-fix");
    let root = env.project();

    let (out, err, code) = run(&env, &root, &["ai", "explain", "chmod +x script.sh"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Explanation for: chmod +x script.sh"), "{out}");

    let (out, err, code) = run(&env, &root, &["ai", "fix", "cargo: command not found"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("AI Terminal Diagnosis & Fix Proposal"),
        "{out}"
    );
    assert!(out.contains("Command 'cargo' not found"), "{out}");
    assert!(out.contains("Proposed Fix:"), "{out}");

    let mut cmd = env.cmd_in(&root);
    cmd.args(["--json", "ai", "fix", "permission denied: /var/log/syslog"]);
    let out = cmd.output().expect("runs ai fix json");
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json output");
    assert_eq!(parsed["summary"], "Permission denied");
    assert!(parsed["proposed_command"]
        .as_str()
        .unwrap()
        .contains("chmod"));
}
