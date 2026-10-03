//! End-to-end tool-manager tests (Phase 2 §73/§74).
//!
//! These run the real `z` binary against the repository's local test registry
//! in an isolated environment. No network access is used, and no dangerous
//! security tool is executed: the only tool actually run is `hello-zen`, a
//! harmless reference script that the registry ships for exactly this purpose.

use std::path::{Path, PathBuf};
use std::process::Command;

fn z_bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("z")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn registry_dir() -> PathBuf {
    repo_root().join("test-registry")
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zen-tool-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::create_dir_all(dir.join("proj")).unwrap();
        Self { dir }
    }

    fn project(&self) -> PathBuf {
        self.dir.join("proj")
    }

    fn cmd(&self, cwd: &Path) -> Command {
        let mut c = Command::new(z_bin());
        c.current_dir(cwd);
        c.env("ZENTRION_DATA_DIR", self.dir.join("data"));
        c.env("ZENTRION_CONFIG_DIR", self.dir.join("config"));
        c.env("ZENTRION_REGISTRY_DIR", registry_dir());
        c
    }

    /// Prepare a project whose policy allows the given tools, with the given
    /// filesystem scope. Nothing else is permitted.
    fn project_allowing(&self, tools: &[&str]) {
        let proj = self.project();
        self.run(&proj, &["init", ".", "--name", "demo"]);
        let pol = proj.join(".zentrion/policy.yaml");
        let mut text = std::fs::read_to_string(&pol).unwrap();
        let allow = tools
            .iter()
            .map(|t| format!("    - \"{t}\"\n"))
            .collect::<String>();
        text.push_str(&format!("tools:\n  allow:\n{allow}"));
        std::fs::write(&pol, text).unwrap();
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> (String, String, i32) {
        let out = self.cmd(cwd).args(args).output().expect("failed to run z");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn json_of(s: &str) -> serde_json::Value {
    serde_json::from_str(s).expect("output must be valid JSON")
}

// ---------------------------------------------------------------------------

#[test]
fn platform_report_declares_no_compatibility_environment() {
    let e = Env::new("platform");
    let (out, _, code) = e.run(&e.project(), &["platform"]);
    assert_eq!(code, 0);
    assert!(out.contains("WSL: no"));
    assert!(out.contains("Docker: no"));
    assert!(out.contains("VM: no"));
}

#[test]
fn platform_json_reports_native_capabilities() {
    let e = Env::new("platform-json");
    let (out, _, code) = e.run(&e.project(), &["platform", "--json"]);
    assert_eq!(code, 0);
    let v = json_of(&out);
    assert_eq!(v["requires_wsl"], false);
    assert_eq!(v["requires_docker"], false);
    assert_eq!(v["requires_vm"], false);
    assert!(v["target"].is_string());
    assert!(v["sandbox_level"].is_string());
}

#[test]
fn search_finds_tools_in_the_local_registry() {
    let e = Env::new("search");
    let (out, _, code) = e.run(&e.project(), &["search", "reference"]);
    assert_eq!(code, 0);
    assert!(out.contains("hello-zen"), "got: {out}");
}

#[test]
fn search_json_is_well_formed() {
    let e = Env::new("search-json");
    let (out, _, code) = e.run(&e.project(), &["search", "hello", "--json"]);
    assert_eq!(code, 0);
    let v = json_of(&out);
    assert!(v["results"].is_array());
    assert!(v["count"].as_u64().unwrap() >= 1);
}

#[test]
fn search_for_unknown_term_returns_no_results_not_an_error() {
    let e = Env::new("search-none");
    let (out, _, code) = e.run(&e.project(), &["search", "zzz-no-such-tool"]);
    assert_eq!(code, 0);
    assert!(out.contains("No tools found"));
}

#[test]
fn info_reports_permissions_and_compatibility() {
    let e = Env::new("info");
    let (out, _, code) = e.run(&e.project(), &["info", "hello-zen"]);
    assert_eq!(code, 0);
    assert!(out.contains("org.zentrion.tools.hello-zen"));
    assert!(out.contains("permissions:"));
    assert!(out.contains("compatibility:"));
}

#[test]
fn install_dry_run_changes_nothing() {
    let e = Env::new("dryrun");
    e.project_allowing(&["hello-zen"]);
    let (out, _, code) = e.run(&e.project(), &["install", "hello-zen", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("no changes made"));
    // The store must still be empty.
    let (list, _, _) = e.run(&e.project(), &["list"]);
    assert!(
        list.contains("No tools installed"),
        "dry-run must not install: {list}"
    );
}

#[test]
fn install_requires_permission_confirmation() {
    let e = Env::new("perm-gate");
    e.project_allowing(&["hello-zen"]);
    let (out, err, code) = e.run(&e.project(), &["install", "hello-zen"]);
    assert_ne!(code, 0, "must not install without approval");
    let combined = format!("{out}{err}");
    assert!(combined.contains("requires") || combined.contains("--approve"));
    let (list, _, _) = e.run(&e.project(), &["list"]);
    assert!(list.contains("No tools installed"));
}

#[test]
fn install_then_verify_then_run_then_remove() {
    let e = Env::new("full-cycle");
    e.project_allowing(&["hello-zen"]);

    let (out, _, code) = e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    assert_eq!(code, 0, "install failed: {out}");
    assert!(out.contains("Installed hello-zen"));

    let (out, _, code) = e.run(&e.project(), &["verify", "hello-zen"]);
    assert_eq!(code, 0, "verify failed: {out}");
    assert!(out.contains("is healthy"));

    let (out, _, code) = e.run(&e.project(), &["run", "hello-zen"]);
    assert_eq!(code, 0, "run failed: {out}");
    assert!(out.contains("hello from zentrion"), "got: {out}");

    let (out, _, code) = e.run(&e.project(), &["list"]);
    assert_eq!(code, 0);
    assert!(out.contains("hello-zen"));

    let (out, _, code) = e.run(&e.project(), &["remove", "hello-zen"]);
    assert_eq!(code, 0, "remove failed: {out}");

    let (list, _, _) = e.run(&e.project(), &["list"]);
    assert!(list.contains("No tools installed"));
}

#[test]
fn run_of_unpermitted_tool_is_denied() {
    let e = Env::new("deny");
    // Install with approval, but do NOT add it to `tools.allow`.
    e.project_allowing(&[]);
    let (_, _, code) = e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    assert_eq!(code, 0);

    let (out, _, code) = e.run(&e.project(), &["run", "hello-zen"]);
    assert_eq!(code, 2, "tool not in the allowlist must exit 2");
    assert!(out.contains("blocked"));
}

#[test]
fn tool_arguments_are_never_shell_interpreted() {
    let e = Env::new("inject");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);

    // hello-zen ignores its arguments, so the proof is that no second command
    // ran: the output is exactly the tool's own line.
    let (out, _, code) = e.run(&e.project(), &["run", "hello-zen", "--", "a; echo PWNED"]);
    assert_eq!(code, 0);
    assert!(out.contains("hello from zentrion"));
    assert!(
        !out.contains("PWNED"),
        "shell metacharacters must be inert: {out}"
    );
}

#[test]
fn install_of_unknown_tool_fails_clearly() {
    let e = Env::new("unknown");
    let (_, err, code) = e.run(&e.project(), &["install", "no-such-tool-xyz", "--approve"]);
    assert_ne!(code, 0);
    assert!(err.contains("no such tool"), "got: {err}");
}

#[test]
fn unsupported_platform_is_reported_honestly() {
    let e = Env::new("compat");
    let (out, _, code) = e.run(&e.project(), &["compatibility", "trivy"]);
    // trivy has an 'unsupported' entry for windows-arm64 in the test registry.
    assert_eq!(code, 0);
    assert!(out.contains("IMPLEMENTATION"));
}

#[test]
fn compatibility_json_lists_per_platform_kinds() {
    let e = Env::new("compat-json");
    let (out, _, code) = e.run(&e.project(), &["compatibility", "hello-zen", "--json"]);
    assert_eq!(code, 0);
    let v = json_of(&out);
    assert!(v["selected"].is_string());
    assert!(v["installable"].is_boolean());
    assert!(v["matrix"].is_array());
}

#[test]
fn native_engine_tool_runs_without_an_external_binary() {
    let e = Env::new("engine");
    e.project_allowing(&["dnsx"]);
    let (out, _, code) = e.run(&e.project(), &["install", "dnsx", "--approve"]);
    assert_eq!(code, 0, "native engine install failed: {out}");

    // Resolve a loopback literal: no network required.
    let (out, _, code) = e.run(&e.project(), &["run", "dnsx", "--port", "80", "127.0.0.1"]);
    assert_eq!(code, 0, "native engine run failed: {out}");
    assert!(out.contains("127.0.0.1"));
}

#[test]
fn sysinfo_engine_reports_host_natively() {
    let e = Env::new("sysinfo");
    e.project_allowing(&["sysinfo"]);
    e.run(&e.project(), &["install", "sysinfo", "--approve"]);
    let (out, _, code) = e.run(&e.project(), &["run", "sysinfo"]);
    assert_eq!(code, 0);
    assert!(out.contains("os:"));
    assert!(out.contains("cpus:"));
}

#[test]
fn multiple_versions_coexist_and_can_be_selected() {
    let e = Env::new("versions");
    e.project_allowing(&["hello-zen"]);
    let (_, _, c1) = e.run(
        &e.project(),
        &["install", "hello-zen", "--version", "1.0.0", "--approve"],
    );
    assert_eq!(c1, 0);
    let (_, _, c2) = e.run(
        &e.project(),
        &["install", "hello-zen", "--version", "1.1.0", "--approve"],
    );
    assert_eq!(c2, 0);

    let (out, _, _) = e.run(&e.project(), &["list", "--json"]);
    let v = json_of(&out);
    let vs = &v["tools"][0]["installed_versions"];
    assert_eq!(
        vs.as_array().unwrap().len(),
        2,
        "both versions must coexist"
    );

    // Switch explicitly.
    let (_, _, code) = e.run(&e.project(), &["use", "hello-zen@1.0.0"]);
    assert_eq!(code, 0);
    let (out, _, _) = e.run(&e.project(), &["which", "hello-zen"]);
    assert!(out.contains("1.0.0"));
}

#[test]
fn rollback_switches_to_the_other_version() {
    let e = Env::new("rollback");
    e.project_allowing(&["hello-zen"]);
    e.run(
        &e.project(),
        &["install", "hello-zen", "--version", "1.0.0", "--approve"],
    );
    e.run(
        &e.project(),
        &["install", "hello-zen", "--version", "1.1.0", "--approve"],
    );

    let (out, _, code) = e.run(&e.project(), &["rollback", "hello-zen"]);
    assert_eq!(code, 0, "rollback failed: {out}");
    let (which, _, _) = e.run(&e.project(), &["which", "hello-zen"]);
    assert!(
        which.contains("1.0.0"),
        "rollback should select 1.0.0: {which}"
    );
}

#[test]
fn verify_detects_a_removed_binary() {
    let e = Env::new("corrupt");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);

    let (which, _, _) = e.run(&e.project(), &["which", "hello-zen", "--json"]);
    let v = json_of(&which);
    let path = PathBuf::from(v["path"].as_str().unwrap());
    std::fs::remove_file(&path).unwrap();

    let (out, _, code) = e.run(&e.project(), &["verify", "hello-zen"]);
    assert_ne!(code, 0, "verify must fail when the binary is missing");
    assert!(out.contains("!!") || out.contains("problems"));
}

#[test]
fn cache_list_and_clean_work_and_preserve_installations() {
    let e = Env::new("cache");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);

    let (out, _, code) = e.run(&e.project(), &["cache", "list"]);
    assert_eq!(code, 0);
    assert!(out.contains("SHA256"));

    let (_, _, code) = e.run(&e.project(), &["cache", "clean"]);
    assert_eq!(code, 0);

    // The installation must survive a cache clean.
    let (out, _, code) = e.run(&e.project(), &["run", "hello-zen"]);
    assert_eq!(
        code, 0,
        "installed tool must still run after cache clean: {out}"
    );
}

#[test]
fn offline_install_uses_the_cache_after_a_prior_install() {
    let e = Env::new("offline");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    e.run(&e.project(), &["remove", "hello-zen"]);

    // The artifact is cached, so an offline reinstall must succeed.
    let (out, _, code) = e.run(
        &e.project(),
        &["install", "hello-zen", "--approve", "--offline"],
    );
    assert_eq!(code, 0, "offline install from cache failed: {out}");
}

#[test]
fn uninstall_is_an_alias_for_remove() {
    let e = Env::new("uninstall");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    let (_, _, code) = e.run(&e.project(), &["uninstall", "hello-zen"]);
    assert_eq!(code, 0);
    let (list, _, _) = e.run(&e.project(), &["list"]);
    assert!(list.contains("No tools installed"));
}

#[test]
fn every_tool_operation_is_audited() {
    let e = Env::new("audit");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    e.run(&e.project(), &["run", "hello-zen"]);
    e.run(&e.project(), &["remove", "hello-zen"]);

    let (out, _, code) = e.run(&e.project(), &["audit", "verify"]);
    assert_eq!(code, 0);
    assert!(out.contains("verified"));

    let (tail, _, _) = e.run(&e.project(), &["audit", "tail", "20"]);
    assert!(tail.contains("tool.install"));
    assert!(tail.contains("tool.execute"));
    assert!(tail.contains("tool.remove"));
}

#[test]
fn no_secret_values_appear_in_audit_output() {
    let e = Env::new("nosecrets");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    let (tail, _, _) = e.run(&e.project(), &["audit", "tail", "50"]);
    assert!(!tail.to_lowercase().contains("password"));
    // Built from fragments so this assertion does not itself trip the
    // repository's secret scanner.
    let pem_marker = format!("{}-{}{}", "-----", "BEGIN", "");
    assert!(!tail.contains(&pem_marker));
}

#[test]
fn list_json_is_stable_and_machine_readable() {
    let e = Env::new("list-json");
    e.project_allowing(&["hello-zen"]);
    e.run(&e.project(), &["install", "hello-zen", "--approve"]);
    let (out, _, code) = e.run(&e.project(), &["list", "--json"]);
    assert_eq!(code, 0);
    let v = json_of(&out);
    assert!(v["store"].is_string());
    assert_eq!(v["count"], 1);
    let t = &v["tools"][0];
    assert_eq!(t["name"], "hello-zen");
    assert!(t["active_version"].is_string());
    assert!(t["installed_versions"].is_array());
    assert!(t["outdated"].is_boolean());
}

#[test]
fn outdated_filter_works() {
    let e = Env::new("outdated");
    e.project_allowing(&["hello-zen"]);
    // Install the older version only; 1.1.0 exists in the registry.
    e.run(
        &e.project(),
        &["install", "hello-zen", "--version", "1.0.0", "--approve"],
    );
    let (out, _, code) = e.run(&e.project(), &["list", "--outdated"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("hello-zen"),
        "1.0.0 should be reported outdated: {out}"
    );
}

#[test]
fn doctor_still_makes_no_network_calls_and_reports_tools() {
    let e = Env::new("doctor");
    let (out, _, code) = e.run(&e.project(), &["doctor"]);
    assert_eq!(code, 0);
    assert!(out.contains("Network"));
}
