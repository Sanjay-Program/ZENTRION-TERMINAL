//! Zentrion performance harness.
//!
//! Measures the paths that make a terminal feel fast: VT parsing throughput,
//! screen search, block persistence/FTS search, audit append cost and CLI
//! startup. Thresholds are deliberately conservative so a shared CI runner can
//! pass while a real regression (an order of magnitude) still fails.
//!
//! Run: `cargo run --release -p z-bench -- --check`

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use chrono::Utc;
use z_audit::AuditLog;
use z_blocks::{Block, BlockStatus, BlockStore, Session};
use z_vt::{SearchOptions, Terminal};

struct Metric {
    name: &'static str,
    value: f64,
    unit: &'static str,
    limit: f64,
    lower_is_better: bool,
    skipped: bool,
}

impl Metric {
    fn passed(&self) -> bool {
        if self.skipped {
            return true;
        }
        if self.lower_is_better {
            self.value <= self.limit
        } else {
            self.value >= self.limit
        }
    }

    fn render(&self) -> String {
        if self.skipped {
            return format!("{:<22} {:>10}  (skipped)", self.name, "-");
        }
        let comparator = if self.lower_is_better { "<=" } else { ">=" };
        format!(
            "{:<22} {:>10.2} {:<8} {comparator} {:.0}  {}",
            self.name,
            self.value,
            self.unit,
            self.limit,
            if self.passed() { "ok" } else { "FAIL" }
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let check = args.iter().any(|a| a == "--check");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    // Debug builds are 5-20x slower; keep the gate meaningful in release only.
    let factor = if cfg!(debug_assertions) { 8.0 } else { 1.0 };

    let metrics = vec![
        bench_vt_parse(factor),
        bench_raw_vt100(factor),
        bench_screen_search(factor),
        bench_block_insert(factor),
        bench_block_search(factor),
        bench_audit_append(factor),
        bench_startup(factor),
    ];

    let failed: Vec<&Metric> = metrics.iter().filter(|m| !m.passed()).collect();
    if json {
        let value = serde_json::json!({
            "profile": profile,
            "ok": failed.is_empty(),
            "metrics": metrics.iter().map(|m| serde_json::json!({
                "name": m.name,
                "value": m.value,
                "unit": m.unit,
                "limit": m.limit,
                "lower_is_better": m.lower_is_better,
                "skipped": m.skipped,
                "pass": m.passed(),
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        println!("Zentrion performance ({profile} build)");
        for metric in &metrics {
            println!("{}", metric.render());
        }
        if !failed.is_empty() {
            println!();
            for metric in &failed {
                println!(
                    "FAIL: {} = {:.2} {}",
                    metric.name, metric.value, metric.unit
                );
            }
        }
    }
    if check && !failed.is_empty() {
        std::process::exit(1);
    }
}

fn bench_vt_parse(factor: f64) -> Metric {
    let data = vt_stream();
    let started = Instant::now();
    let mut terminal = Terminal::new(40, 120, 10_000);
    for chunk in data.chunks(8192) {
        let _ = terminal.process(chunk);
    }
    let seconds = started.elapsed().as_secs_f64().max(0.000_001);
    Metric {
        name: "vt_parse",
        value: (data.len() as f64 / (1024.0 * 1024.0)) / seconds,
        unit: "MiB/s",
        limit: 6.0 / factor,
        lower_is_better: false,
        skipped: false,
    }
}

fn bench_raw_vt100(factor: f64) -> Metric {
    let data = vt_stream();
    let started = Instant::now();
    let mut parser = vt100::Parser::new(
        std::num::NonZeroU16::new(40).unwrap(),
        std::num::NonZeroU16::new(120).unwrap(),
        10_000,
    );
    for chunk in data.chunks(8192) {
        parser.process(chunk);
    }
    let seconds = started.elapsed().as_secs_f64().max(0.000_001);
    Metric {
        name: "raw_vt100",
        value: (data.len() as f64 / (1024.0 * 1024.0)) / seconds,
        unit: "MiB/s",
        limit: 7.0 / factor,
        lower_is_better: false,
        skipped: false,
    }
}

fn bench_screen_search(factor: f64) -> Metric {
    let data = vt_stream();
    let mut terminal = Terminal::new(40, 120, 10_000);
    for chunk in data.chunks(8192) {
        let _ = terminal.process(chunk);
    }
    let options = SearchOptions {
        pattern: "needle".to_string(),
        max_results: 500,
        ..Default::default()
    };
    let started = Instant::now();
    let hits = terminal.search(&options).unwrap_or_default();
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    std::hint::black_box(hits);
    Metric {
        name: "screen_search",
        value: elapsed,
        unit: "ms",
        limit: 400.0 * factor,
        lower_is_better: true,
        skipped: false,
    }
}

fn bench_block_insert(factor: f64) -> Metric {
    let store = BlockStore::open_in_memory().expect("in-memory block store");
    let session = Session {
        id: "bench".into(),
        title: "bench".into(),
        shell: "/bin/bash".into(),
        cwd: "/tmp".into(),
        created_at: Utc::now(),
        closed_at: None,
        status: "open".into(),
        workspace_id: None,
        agent_id: None,
        metadata: serde_json::Value::Null,
    };
    store.upsert_session(&session).expect("session");
    let count = 5_000u64;
    let started = Instant::now();
    for i in 0..count {
        let block = Block {
            id: format!("b{i}"),
            session_id: "bench".into(),
            seq: i,
            command: format!("cargo test --package crate_{} needle-{}", i % 40, i % 500),
            cwd: "/tmp".into(),
            shell: "/bin/bash".into(),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: Some(0),
            status: BlockStatus::Ok,
            duration_ms: Some(12),
            output_hash: None,
            output_bytes: Some(128),
            agent_id: None,
            policy_decision: Some("allow".into()),
            approval_id: None,
            tags: Vec::new(),
            risk: Some("low".into()),
            parent_block_id: None,
        };
        store
            .insert(&block, b"compiling crate ... ok\nrunning 12 tests ... ok\n")
            .expect("insert block");
    }
    let seconds = started.elapsed().as_secs_f64().max(0.000_001);
    Metric {
        name: "block_insert",
        value: count as f64 / seconds,
        unit: "blocks/s",
        limit: 400.0 / factor,
        lower_is_better: false,
        skipped: false,
    }
}

fn bench_block_search(factor: f64) -> Metric {
    let store = BlockStore::open_in_memory().expect("in-memory block store");
    let session = Session {
        id: "bench".into(),
        title: "bench".into(),
        shell: "/bin/bash".into(),
        cwd: "/tmp".into(),
        created_at: Utc::now(),
        closed_at: None,
        status: "open".into(),
        workspace_id: None,
        agent_id: None,
        metadata: serde_json::Value::Null,
    };
    store.upsert_session(&session).expect("session");
    for i in 0..3_000u64 {
        let block = Block {
            id: format!("s{i}"),
            session_id: "bench".into(),
            seq: i,
            command: format!("rg --line-number needle-{} src/", i % 100),
            cwd: "/tmp".into(),
            shell: "/bin/bash".into(),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: Some(0),
            status: BlockStatus::Ok,
            duration_ms: Some(5),
            output_hash: None,
            output_bytes: Some(64),
            agent_id: None,
            policy_decision: None,
            approval_id: None,
            tags: Vec::new(),
            risk: None,
            parent_block_id: None,
        };
        store
            .insert(&block, b"src/lib.rs:42:needle\n")
            .expect("insert");
    }
    let started = Instant::now();
    let hits = store.search("needle", 50).expect("search");
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    std::hint::black_box(hits);
    Metric {
        name: "block_search",
        value: elapsed,
        unit: "ms",
        limit: 200.0 * factor,
        lower_is_better: true,
        skipped: false,
    }
}

fn bench_audit_append(factor: f64) -> Metric {
    let dir = std::env::temp_dir().join(format!(
        "zbench-audit-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("audit dir");
    let path = dir.join("events.jsonl");
    let mut log = AuditLog::open(&path).expect("audit log");
    let count = 1_000u64;
    let started = Instant::now();
    for i in 0..count {
        log.append(
            "bench",
            "system",
            "benchmark.append",
            &format!("bench:{i}"),
            None,
            "allow",
            "ok",
            "LOW",
            "bench",
        )
        .expect("append audit event");
    }
    let seconds = started.elapsed().as_secs_f64().max(0.000_001);
    let _ = std::fs::remove_dir_all(&dir);
    Metric {
        name: "audit_append",
        value: count as f64 / seconds,
        unit: "events/s",
        limit: 80.0 / factor,
        lower_is_better: false,
        skipped: false,
    }
}

fn bench_startup(factor: f64) -> Metric {
    let Some(bin) = find_z_binary() else {
        return Metric {
            name: "cli_startup",
            value: 0.0,
            unit: "ms",
            limit: 0.0,
            lower_is_better: true,
            skipped: true,
        };
    };
    let mut samples = Vec::new();
    for _ in 0..7 {
        let started = Instant::now();
        let status = std::process::Command::new(&bin)
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        if status.map(|s| s.success()).unwrap_or(false) {
            samples.push(elapsed);
        }
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = samples.get(samples.len() / 2).copied().unwrap_or(0.0);
    Metric {
        name: "cli_startup",
        value: median,
        unit: "ms",
        limit: 1200.0 * factor,
        lower_is_better: true,
        skipped: samples.is_empty(),
    }
}

fn find_z_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("Z_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join(profile)
        .join(if cfg!(windows) { "z.exe" } else { "z" });
    path.is_file().then_some(path)
}

/// Deterministic, policy-exercising terminal stream: SGR, cursor moves,
/// scrolling, titles and a searchable needle.
fn vt_stream() -> Vec<u8> {
    let mut data = Vec::with_capacity(8 * 1024 * 1024);
    for i in 0..60_000u32 {
        write!(
            data,
            "\x1b[{}m{:>6}  the quick brown fox jumps over the lazy dog {} {}\x1b[0m\r\n",
            30 + (i % 8),
            i,
            i % 97,
            if i % 1_000 == 0 { "needle" } else { "" }
        )
        .expect("in-memory write");
        if i % 50 == 0 {
            data.extend_from_slice(b"\x1b[2K\x1b[1A");
        }
    }
    data.extend_from_slice(b"\x1b]0;bench\x07\x1b[2J\x1b[H");
    data
}
