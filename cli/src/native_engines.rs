//! Zentrion-native tool engines.
//!
//! A tool whose manifest declares `execution.native_engine` is implemented by
//! the runtime itself rather than by an external binary. This is how Zentrion
//! provides genuinely portable functionality with no shell, no `dig`, no
//! `curl`, and no compatibility environment (Phase 2 §17/§18/§24).

use serde_json::json;
use z_core::error::{Area, ZenError, ZenResult};

pub fn available_engines() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "dns.resolve",
            "Resolve A/AAAA records using the OS resolver",
        ),
        ("platform.info", "Report platform and native capabilities"),
        ("process.info", "Inspect a process by pid"),
        ("sysinfo", "Report CPU, memory and host information"),
        (
            "tls.inspect",
            "Inspect a TLS endpoint: certificate, SANs, expiry, cipher and trust",
        ),
    ]
}

pub fn run_engine(engine: &str, args: Vec<String>, json_out: bool) -> ZenResult<()> {
    match engine {
        "dns.resolve" => dns_resolve(args, json_out),
        "platform.info" => crate::tools_cmd::platform_report(json_out),
        "process.info" => process_info(args, json_out),
        "sysinfo" => sysinfo(json_out),
        "tls.inspect" => tls_inspect(args, json_out),
        other => Err(
            ZenError::new(Area::Reg, 300, format!("unknown native engine '{other}'"))
                .with_remediation(format!(
                    "Available engines: {}",
                    available_engines()
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
        ),
    }
}

fn dns_resolve(args: Vec<String>, json_out: bool) -> ZenResult<()> {
    // Parse structured arguments. Options consume the following token, so the
    // hostname is the first positional argument that is not an option value.
    // (Naively taking "the first non-dash token" picks up the option's value.)
    let mut host: Option<String> = None;
    let mut port: u16 = 443;
    let mut record: Option<z_native::dns::RecordType> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| ZenError::new(Area::Cfg, 306, "--port requires a value"))?;
                port = val
                    .parse::<u16>()
                    .map_err(|_| ZenError::new(Area::Cfg, 307, format!("invalid port '{val}'")))?;
                i += 2;
            }
            "--type" | "-t" => {
                let val = args.get(i + 1).ok_or_else(|| {
                    ZenError::new(Area::Cfg, 310, "--type requires a record type")
                })?;
                record = Some(z_native::dns::RecordType::parse(val).ok_or_else(|| {
                    ZenError::new(
                        Area::Cfg,
                        311,
                        format!("unsupported DNS record type '{val}'"),
                    )
                    .with_remediation("Use A, AAAA, CNAME, MX, TXT, NS, SOA or PTR.")
                })?);
                i += 2;
            }
            "--json" => {
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(
                    ZenError::new(Area::Cfg, 308, format!("unknown option '{other}'"))
                        .with_remediation("Usage: dnsx [--port N] [--type TYPE] <hostname>"),
                );
            }
            other => {
                if host.is_none() {
                    host = Some(other.to_string());
                } else {
                    return Err(ZenError::new(
                        Area::Cfg,
                        309,
                        "only one hostname may be given",
                    ));
                }
                i += 1;
            }
        }
    }

    let host = host.ok_or_else(|| {
        ZenError::new(
            Area::Cfg,
            301,
            "usage: dnsx [--port N] [--type TYPE] <hostname>",
        )
    })?;

    let outcome = match record {
        Some(record) => z_native::dns::lookup(&host, record),
        None => z_native::dns::resolve_addresses(&host, port),
    };

    match outcome {
        z_native::dns::DnsOutcome::Records(records) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "host": host,
                        "records": records.iter().map(|r| json!({
                            "type": r.record_type, "value": r.value, "ttl": r.ttl,
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                for r in &records {
                    println!("{:<6} {}", r.record_type, r.value);
                }
            }
            Ok(())
        }
        z_native::dns::DnsOutcome::Unsupported(msg) => {
            Err(ZenError::new(Area::Net, 302, format!("unsupported: {msg}")))
        }
        z_native::dns::DnsOutcome::Failed(msg) => Err(ZenError::new(
            Area::Net,
            303,
            format!("resolution failed: {msg}"),
        )),
    }
}

fn tls_inspect(args: Vec<String>, json_out: bool) -> ZenResult<()> {
    let mut target: Option<String> = None;
    let mut port: u16 = 443;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--port" | "-p" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| ZenError::new(Area::Cfg, 320, "--port requires a value"))?;
                port = value.parse().map_err(|_| {
                    ZenError::new(Area::Cfg, 321, format!("invalid port '{value}'"))
                })?;
                index += 2;
            }
            "--json" => index += 1,
            other if other.starts_with('-') => {
                return Err(
                    ZenError::new(Area::Cfg, 322, format!("unknown option '{other}'"))
                        .with_remediation("Usage: tlsx [--port N] <host[:port]>"),
                );
            }
            other => {
                if target.is_some() {
                    return Err(ZenError::new(
                        Area::Cfg,
                        323,
                        "only one TLS target may be given",
                    ));
                }
                target = Some(other.to_string());
                index += 1;
            }
        }
    }
    let target = target
        .ok_or_else(|| ZenError::new(Area::Cfg, 324, "usage: tlsx [--port N] <host[:port]>"))?;
    let (host, port) = split_tls_target(&target, port);
    match z_native::tls::inspect(&host, port) {
        z_native::tls::TlsOutcome::Info(info) => {
            if json_out {
                println!("{}", serde_json::to_string_pretty(&*info)?);
            } else {
                println!("host:       {}:{}", info.host, info.port);
                println!(
                    "version:    {}",
                    info.tls_version.as_deref().unwrap_or("unknown")
                );
                println!(
                    "cipher:     {}",
                    info.cipher.as_deref().unwrap_or("unknown")
                );
                println!(
                    "trusted:    {}",
                    match info.certificate_trusted {
                        Some(true) => "yes",
                        Some(false) => "NO (untrusted chain)",
                        None => "unknown",
                    }
                );
                println!(
                    "hostname:   {}",
                    match info.hostname_matches {
                        Some(true) => "matches certificate",
                        Some(false) => "DOES NOT MATCH certificate",
                        None => "unknown",
                    }
                );
                println!(
                    "subject:    {}",
                    info.peer_certificate_subject.as_deref().unwrap_or("?")
                );
                println!(
                    "issuer:     {}",
                    info.peer_certificate_issuer.as_deref().unwrap_or("?")
                );
                println!(
                    "expires:    {}",
                    info.certificate_expires.as_deref().unwrap_or("?")
                );
                println!("SANs:       {}", info.subject_alt_names.join(", "));
            }
            Ok(())
        }
        z_native::tls::TlsOutcome::Unsupported(message) => {
            Err(ZenError::new(Area::Net, 325, message))
        }
        z_native::tls::TlsOutcome::Failed(message) => Err(ZenError::new(
            Area::Net,
            326,
            format!("TLS inspection failed: {message}"),
        )),
    }
}

fn split_tls_target(target: &str, default_port: u16) -> (String, u16) {
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("tls://"))
        .unwrap_or(target);
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some((host, tail)) = stripped.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|value| value.parse().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, value)) if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), value.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

fn process_info(args: Vec<String>, json_out: bool) -> ZenResult<()> {
    let pid: u32 = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(std::process::id);

    let insp = z_native::process::inspector();
    match insp.inspect(pid) {
        z_native::process::InspectOutcome::Found(p) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "pid": p.pid,
                        "name": p.name,
                        "path": p.path.map(|x| x.display().to_string()),
                        "parent_pid": p.parent_pid,
                        "user": p.user,
                        "state": p.state,
                    }))?
                );
            } else {
                println!("pid:        {}", p.pid);
                println!("name:       {}", p.name);
                if let Some(path) = &p.path {
                    println!("path:       {}", path.display());
                }
                if let Some(pp) = p.parent_pid {
                    println!("parent:     {pp}");
                }
                if let Some(u) = &p.user {
                    println!("user:       {u}");
                }
                println!("state:      {}", p.state);
            }
            Ok(())
        }
        z_native::process::InspectOutcome::NotFound => Err(ZenError::new(
            Area::Pr,
            304,
            format!("no such process: {pid}"),
        )),
        z_native::process::InspectOutcome::Unsupported(msg) => Err(ZenError::new(
            Area::Pr,
            305,
            format!("process inspection unsupported on this platform: {msg}"),
        )),
    }
}

fn sysinfo(json_out: bool) -> ZenResult<()> {
    let s = z_native::sysinfo::system_info();
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "os": s.os,
                "os_version": s.os_version,
                "arch": s.arch,
                "cpus": s.cpu_count,
                "memory_total_mb": s.memory_total_mb,
                "memory_available_mb": s.memory_available_mb,
                "hostname": s.hostname,
            }))?
        );
    } else {
        println!("os:        {} {}", s.os, s.os_version);
        println!("arch:      {}", s.arch);
        println!("cpus:      {}", s.cpu_count);
        match s.memory_total_mb {
            Some(m) => println!(
                "memory:    {m} MB total, {} MB available",
                s.memory_available_mb.unwrap_or(0)
            ),
            None => println!("memory:    not reported on this platform"),
        }
        println!("hostname:  {}", s.hostname);
    }
    Ok(())
}
