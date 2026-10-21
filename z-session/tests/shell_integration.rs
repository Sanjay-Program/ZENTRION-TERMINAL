use z_config::ShellIntegration;
use z_session::{SessionHandle, SessionOptions};

#[test]
fn bash_shell_integration_records_a_command_block() {
    let dir = std::env::temp_dir().join(format!("zint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let integration = dir.join("integration");
    z_session::ensure_scripts(&integration).unwrap();
    let opts = SessionOptions {
        shell: "/bin/bash".into(),
        cwd: dir.clone(),
        env: Vec::new(),
        rows: 24,
        cols: 100,
        scrollback: 1000,
        title: None,
        integration: ShellIntegration::Bash,
        integration_dir: Some(integration),
        command_file: dir.join("cmd"),
        login: false,
        heuristic_blocks: false,
        command: None,
        scrollback_dir: None,
    };
    let session = SessionHandle::spawn(opts, None).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(800));
    assert!(
        session.is_alive(),
        "bash exited: {:?}",
        session.snapshot().contents
    );
    session.input(b"echo debug-ok\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let contents = session.snapshot().contents;
    assert!(contents.contains("debug-ok"));
    session.close(true).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
