//! `z blocks`, `z context` and `z checkpoint`.

use super::*;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

pub fn blocks(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--limit",
            "--session",
            "--cwd",
            "--agent",
            "--tag",
            "--days",
            "--output",
        ],
    );
    let store =
        z_blocks::BlockStore::open_default().map_err(|e| map_err("cannot open block store", e))?;
    match parsed.command("list") {
        "list" => {
            let limit = parsed
                .value("--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(30);
            let filter = z_blocks::BlockFilter {
                session_id: parsed.value("--session").map(str::to_string),
                cwd: parsed.value("--cwd").map(str::to_string),
                agent_id: parsed.value("--agent").map(str::to_string),
                tag: parsed.value("--tag").map(str::to_string),
                exit_nonzero: parsed.flag("--failed"),
                status: None,
                since: None,
                until: None,
                limit: Some(limit),
                offset: None,
            };
            let blocks = store
                .list(&filter)
                .map_err(|e| map_err("cannot list blocks", e))?;
            if json_out {
                return print_json(&json!({"blocks": blocks}));
            }
            if blocks.is_empty() {
                println!("No blocks recorded. Run a command in a session with shell integration.");
            }
            for block in blocks {
                println!("{}", block.header());
                println!("  id: {}", block.id);
                if let Some(hash) = &block.output_hash {
                    println!(
                        "  output: {} bytes, {}",
                        block.output_bytes.unwrap_or(0),
                        hash
                    );
                }
            }
            Ok(())
        }
        "search" => {
            let query = parsed.rest().join(" ");
            if query.trim().is_empty() {
                return Err(fail("usage: z blocks search <query>"));
            }
            let limit = parsed
                .value("--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(20);
            let hits = store
                .search(&query, limit)
                .map_err(|e| map_err("search failed", e))?;
            if json_out {
                return print_json(&json!({"hits": hits}));
            }
            if hits.is_empty() {
                println!("No matches for `{query}`.");
            }
            for hit in hits {
                println!("{}  [{}]", hit.block.header(), hit.block.id);
                println!("  {}", hit.snippet.replace('\n', " "));
            }
            Ok(())
        }
        "show" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z blocks show <block-id>"))?;
            let block = store
                .get(id)
                .map_err(|e| map_err("cannot read block", e))?
                .ok_or_else(|| fail(format!("block `{id}` not found")))?;
            let output = store
                .output(id)
                .map_err(|e| map_err("cannot read block output", e))?;
            if parsed.flag("--output") || parsed.flag("--plain") {
                let mut bytes = output.clone();
                if parsed.flag("--plain") {
                    bytes = z_blocks::strip_ansi(&String::from_utf8_lossy(&output)).into_bytes();
                }
                std::io::stdout()
                    .write_all(&bytes)
                    .map_err(|e| map_err("cannot write output", e))?;
                return Ok(());
            }
            if json_out {
                return print_json(&json!({
                    "block": block,
                    "output": String::from_utf8_lossy(&output),
                }));
            }
            println!("{}", block.header());
            println!("  id:        {}", block.id);
            println!("  session:   {}", block.session_id);
            println!("  exit:      {:?}", block.exit_code);
            println!("  risk:      {:?}", block.risk);
            println!("  policy:    {:?}", block.policy_decision);
            if let Some(hash) = &block.output_hash {
                println!("  hash:      {hash}");
            }
            println!("--- output ---");
            std::io::stdout()
                .write_all(&output)
                .map_err(|e| map_err("cannot write output", e))?;
            Ok(())
        }
        "stats" => {
            let stats = store
                .stats()
                .map_err(|e| map_err("cannot read block stats", e))?;
            if json_out {
                print_json(&serde_json::to_value(&stats).unwrap_or(json!({})))
            } else {
                println!("Blocks:  {}", stats.blocks);
                println!("Sessions:{}", stats.sessions);
                println!("Output:  {} bytes", stats.output_bytes);
                if let Some(oldest) = stats.oldest {
                    println!("Oldest:  {oldest}");
                }
                if let Some(newest) = stats.newest {
                    println!("Newest:  {newest}");
                }
                Ok(())
            }
        }
        "verify" => {
            let bad = store
                .verify_outputs(10_000)
                .map_err(|e| map_err("verification failed", e))?;
            if json_out {
                print_json(&json!({"verified": bad.is_empty(), "corrupt": bad}))
            } else if bad.is_empty() {
                println!("All stored block outputs match their recorded hashes.");
                Ok(())
            } else {
                println!("Corrupt output for {} block(s):", bad.len());
                for id in bad {
                    println!("  {id}");
                }
                Err(fail("block output verification failed"))
            }
        }
        "export" => {
            let text = store
                .export_json(&z_blocks::BlockFilter {
                    limit: Some(10_000),
                    ..Default::default()
                })
                .map_err(|e| map_err("cannot export blocks", e))?;
            if let Some(path) = parsed.value("--output") {
                std::fs::write(path, &text).map_err(|e| map_err("cannot write export", e))?;
                if !json_out {
                    println!("exported blocks to {path}");
                }
            } else {
                println!("{text}");
            }
            Ok(())
        }
        "import" => {
            let path = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z blocks import <file.json>"))?;
            let text =
                std::fs::read_to_string(path).map_err(|e| map_err("cannot read import file", e))?;
            let count = store
                .import_json(&text)
                .map_err(|e| map_err("cannot import blocks", e))?;
            if json_out {
                print_json(&json!({"imported": count}))
            } else {
                println!("imported {count} block(s)");
                Ok(())
            }
        }
        "gc" => {
            let days = parsed
                .value("--days")
                .and_then(|value| value.parse().ok())
                .unwrap_or(30);
            let removed = store
                .delete_older_than(days)
                .map_err(|e| map_err("retention failed", e))?;
            if json_out {
                print_json(&json!({"removed": removed, "days": days}))
            } else {
                println!("removed {removed} block(s) older than {days} days");
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown blocks subcommand `{other}` (list|search|show|stats|verify|export|import|gc)"
        ))),
    }
}

fn context_options() -> ZenResult<(z_config::ContextConfig, z_context::IndexOptions)> {
    let config = load_config()?.config;
    let context = config.context.clone();
    let options = z_context::IndexOptions {
        max_file_bytes: context.max_file_bytes,
        max_files: context.max_files,
        ignore: context.ignore.clone(),
        follow_symlinks: false,
        use_git: true,
        include_hidden: false,
    };
    Ok((context, options))
}

pub fn context(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--budget", "--pin", "--limit", "--path"]);
    let (context_config, options) = context_options()?;
    match parsed.command("status") {
        "index" => {
            let path = parsed
                .value("--path")
                .map(PathBuf::from)
                .or_else(|| parsed.rest().first().map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("."));
            let mut index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            if !json_out {
                eprintln!("indexing {} ...", path.display());
            }
            let stats = index
                .index_dir_with_progress(&path, &options, |count, file| {
                    if count > 0 && count % 1_000 == 0 {
                        eprintln!("  {count} files ({file})");
                    }
                })
                .map_err(|e| map_err("indexing failed", e))?;
            let _ = write_audit(
                "user",
                "user",
                "context.index",
                &stats.root,
                "allow",
                "ok",
                "low",
            );
            if json_out {
                print_json(&serde_json::to_value(&stats).unwrap_or(json!({})))
            } else {
                println!("Indexed {}", stats.root);
                println!("  new:       {}", stats.indexed);
                println!("  updated:   {}", stats.updated);
                println!("  unchanged: {}", stats.unchanged);
                println!("  removed:   {}", stats.removed);
                println!("  skipped:   {}", stats.skipped);
                println!("  symbols:   {}", stats.symbols);
                println!("  bytes:     {}", stats.bytes);
                println!("  duration:  {}ms", stats.duration_ms);
                for error in stats.errors.iter().take(10) {
                    println!("  warning:   {error}");
                }
                Ok(())
            }
        }
        "search" => {
            let query = parsed.rest().join(" ");
            if query.trim().is_empty() {
                return Err(fail("usage: z context search <query>"));
            }
            let index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            let limit = parsed
                .value("--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(20);
            let hits = index
                .search(&query, limit)
                .map_err(|e| map_err("search failed", e))?;
            if json_out {
                return print_json(&json!({"hits": hits}));
            }
            if hits.is_empty() {
                println!("No matches (is the repository indexed? run `z context index`).");
            }
            for hit in hits {
                println!("{}:{}  [{}]", hit.path, hit.line, hit.language);
                println!("  {}", hit.snippet);
            }
            Ok(())
        }
        "pack" => {
            let query = parsed.rest().join(" ");
            if query.trim().is_empty() {
                return Err(fail(
                    "usage: z context pack <query> [--budget N] [--pin file]",
                ));
            }
            let index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            let budget = parsed
                .value("--budget")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_else(|| (context_config.model_context_tokens as f64 * 0.6) as usize);
            let mut query = z_context::ContextQuery::new(query, budget);
            query.pins = parsed.values_of("--pin").to_vec();
            query.max_items = parsed
                .value("--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(12);
            let pack = z_context::build_context(&index, &query)
                .map_err(|e| map_err("cannot build context pack", e))?;
            if json_out {
                print_json(&serde_json::to_value(&pack).unwrap_or(json!({})))
            } else {
                print!("{}", pack.render());
                Ok(())
            }
        }
        "symbols" => {
            let file = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z context symbols <indexed-file>"))?;
            let index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            let entry = index
                .file_entry(file)
                .map_err(|e| map_err("cannot read index entry", e))?
                .ok_or_else(|| fail(format!("`{file}` is not indexed")))?;
            if json_out {
                print_json(
                    &json!({"file": entry.path, "language": entry.language, "symbols": entry.symbols}),
                )
            } else {
                println!("{} ({})", entry.path, entry.language);
                for symbol in entry.symbols {
                    println!("  {:>5}  {:<10} {}", symbol.line, symbol.kind, symbol.name);
                }
                Ok(())
            }
        }
        "status" => {
            let mut index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            let status = index
                .status()
                .map_err(|e| map_err("cannot read status", e))?;
            if json_out {
                let value = serde_json::to_value(&status).unwrap_or(json!({}));
                print_json(&value)
            } else {
                println!("Index:     {}", status.path);
                println!("Root:      {}", status.root.as_deref().unwrap_or("-"));
                println!("Files:     {}", status.files);
                println!("Symbols:   {}", status.symbols);
                println!("Bytes:     {}", status.bytes);
                println!("Stale:     {}", status.stale);
                Ok(())
            }
        }
        "clear" => {
            let mut index = z_context::RepoIndex::open_default()
                .map_err(|e| map_err("cannot open index", e))?;
            index
                .clear()
                .map_err(|e| map_err("cannot clear index", e))?;
            if !json_out {
                println!("context index cleared");
            }
            Ok(())
        }
        other => Err(fail(format!(
            "unknown context subcommand `{other}` (index|search|pack|symbols|status|clear)"
        ))),
    }
}

pub fn checkpoint(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--file", "--days", "--output"]);
    let store = z_checkpoint::CheckpointStore::default_store()
        .ok_or_else(|| fail("cannot determine checkpoint directory"))?;
    match parsed.command("list") {
        "create" => {
            let path = parsed
                .rest()
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let manifest = store
                .snapshot(
                    &path,
                    &z_checkpoint::CheckpointOptions {
                        sign: parsed.flag("--sign"),
                        ..Default::default()
                    },
                )
                .map_err(|e| map_err("checkpoint failed", e))?;
            write_audit(
                "user",
                "user",
                "checkpoint.create",
                &manifest.id,
                "allow",
                "ok",
                "medium",
            )?;
            if json_out {
                print_json(&serde_json::to_value(&manifest).unwrap_or(json!({})))
            } else {
                println!("{}", manifest.id);
                eprintln!(
                    "checkpoint {}: {} files, {} bytes, tree {}",
                    manifest.id,
                    manifest.files.len(),
                    manifest.total_bytes,
                    manifest.tree_hash
                );
                if manifest.signature.is_some() {
                    eprintln!("  signed with Ed25519");
                }
                Ok(())
            }
        }
        "list" => {
            let manifests = store
                .list()
                .map_err(|e| map_err("cannot list checkpoints", e))?;
            if json_out {
                print_json(&json!({"checkpoints": manifests}))
            } else if manifests.is_empty() {
                println!("No checkpoints.");
                Ok(())
            } else {
                for manifest in manifests {
                    println!(
                        "{}  {}  {} files  {}{}",
                        manifest.id,
                        manifest.created_at,
                        manifest.files,
                        manifest.repo,
                        if manifest.signed { "  [signed]" } else { "" }
                    );
                }
                Ok(())
            }
        }
        "show" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z checkpoint show <id>"))?;
            let manifest = store
                .load(id)
                .map_err(|e| map_err("cannot load checkpoint", e))?;
            if json_out {
                print_json(&serde_json::to_value(&manifest).unwrap_or(json!({})))
            } else {
                println!("Checkpoint {}", manifest.id);
                println!("  repo:     {}", manifest.repo);
                println!("  created:  {}", manifest.created_at);
                println!("  by:       {}", manifest.created_by);
                println!(
                    "  base:     {}",
                    manifest.base_commit.as_deref().unwrap_or("-")
                );
                println!("  tree:     {}", manifest.tree_hash);
                println!("  files:    {}", manifest.files.len());
                println!("  bytes:    {}", manifest.total_bytes);
                println!("  signature:{:?}", manifest.signature.is_some());
                for file in manifest.files.iter().take(200) {
                    println!("  {}  {}", file.hash, file.path);
                }
                Ok(())
            }
        }
        "diff" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z checkpoint diff <id> [path]"))?;
            let path = parsed
                .rest()
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let diff = store
                .diff_current(id, &path)
                .map_err(|e| map_err("diff failed", e))?;
            if json_out {
                return print_json(&serde_json::to_value(&diff).unwrap_or(json!({})));
            }
            if diff.files.is_empty() {
                println!("No changes since checkpoint.");
            }
            for file in &diff.files {
                println!(
                    "{:?} {} (+{} -{})",
                    file.status, file.path, file.additions, file.deletions
                );
                for hunk in &file.hunks {
                    println!(
                        "@@ -{},{} +{},{} @@",
                        hunk.old_start, hunk.old_lines, hunk.new_start, hunk.new_lines
                    );
                    for line in &hunk.lines {
                        println!("{}{}", line.kind, line.text);
                    }
                }
            }
            println!(
                "{} file(s), +{} -{}",
                diff.files.len(),
                diff.total_additions,
                diff.total_deletions
            );
            Ok(())
        }
        "restore" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z checkpoint restore <id> [path]"))?;
            let path = parsed
                .rest()
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let manifest = store
                .load(id)
                .map_err(|e| map_err("cannot load checkpoint", e))?;
            if !parsed.flag("--no-backup") {
                if let Ok(backup) = store.snapshot(
                    &path,
                    &z_checkpoint::CheckpointOptions {
                        created_by: format!("pre-restore-{id}"),
                        ..Default::default()
                    },
                ) {
                    if !json_out {
                        eprintln!("saved pre-restore backup checkpoint {}", backup.id);
                    }
                }
            }
            let files: Vec<String> = parsed.values_of("--file").to_vec();
            let report = if !files.is_empty() {
                store
                    .restore_files(&manifest.id, &path, &files)
                    .map_err(|e| map_err("restore failed", e))?
            } else if parsed.flag("--relocated") {
                store
                    .restore_relocated(&manifest.id, &path)
                    .map_err(|e| map_err("restore failed", e))?
            } else {
                store
                    .restore(&manifest.id, &path)
                    .map_err(|e| map_err("restore failed", e))?
            };
            write_audit(
                "user",
                "user",
                "checkpoint.restore",
                &manifest.id,
                "allow",
                "ok",
                "high",
            )?;
            if json_out {
                print_json(&serde_json::to_value(&report).unwrap_or(json!({})))
            } else {
                println!(
                    "restored {} file(s), deleted {}, verified {}, {} bytes",
                    report.restored, report.deleted, report.verified, report.bytes
                );
                Ok(())
            }
        }
        "sign" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z checkpoint sign <id>"))?;
            let manifest = store
                .sign_manifest(id)
                .map_err(|e| map_err("cannot sign checkpoint", e))?;
            write_audit(
                "user",
                "user",
                "checkpoint.sign",
                &manifest.id,
                "allow",
                "ok",
                "low",
            )?;
            if json_out {
                print_json(&json!({
                    "id": manifest.id,
                    "public_key": manifest.signature.as_ref().map(|s| s.public_key.clone()),
                }))
            } else {
                println!(
                    "signed {} with Ed25519 key {}",
                    manifest.id,
                    manifest
                        .signature
                        .as_ref()
                        .map(|signature| signature.public_key.as_str())
                        .unwrap_or("-")
                );
                Ok(())
            }
        }
        "verify" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z checkpoint verify <id>"))?;
            let manifest = store
                .load(id)
                .map_err(|e| map_err("cannot load checkpoint", e))?;
            let valid = store.signature_valid(&manifest);
            if json_out {
                print_json(&json!({
                    "id": manifest.id,
                    "signature": valid,
                    "tree_hash": manifest.tree_hash,
                }))
            } else {
                match valid {
                    Some(true) => println!("signature valid"),
                    Some(false) => return Err(fail("signature INVALID")),
                    None => println!("checkpoint is not signed"),
                }
                println!("tree {}", manifest.tree_hash);
                Ok(())
            }
        }
        "gc" => {
            let days = parsed
                .value("--days")
                .and_then(|value| value.parse().ok())
                .unwrap_or(30);
            let report = store.gc(days).map_err(|e| map_err("gc failed", e))?;
            if json_out {
                print_json(&serde_json::to_value(&report).unwrap_or(json!({})))
            } else {
                println!(
                    "removed {} manifest(s), {} blob(s), reclaimed {} bytes",
                    report.manifests_removed, report.blobs_removed, report.bytes_reclaimed
                );
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown checkpoint subcommand `{other}` (create|list|show|diff|restore|sign|verify|gc)"
        ))),
    }
}
