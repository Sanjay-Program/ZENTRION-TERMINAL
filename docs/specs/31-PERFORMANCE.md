# 31 — PERFORMANCE

Targets measured on a reference machine: 4-core/8GB SSD x64 Linux, warm caches.
The TARGET/MINIMUM/STRETCH columns are goals; the measured table below is what
the current tree actually reaches.

| Metric | TARGET | MINIMUM (accept) | STRETCH |
|---|---|---|---|
| `z version` cold start | 300 ms | 600 ms | 100 ms |
| `z version` warm | 100 ms | 250 ms | 50 ms |
| broker policy evaluation (single request) | 1 ms | 5 ms | 0.2 ms |
| runtime startup (daemon) | 500 ms | 1 s | 200 ms |
| idle memory (CLI) | 30 MB | 80 MB | 15 MB |
| idle CPU (daemon) | 0% (event-driven) | <1% | 0% |
| install size (core, no tools/models) | 40 MB | 80 MB | 20 MB |
| tool install (nmap via package manager) | bounded by package manager; Zentrion overhead ≤ 500 ms | 2 s | 200 ms |
| audit write overhead per event | 0.5 ms | 2 ms | 0.1 ms |
| local model load (8B q4, from disk) | hardware-bound — reported, not promised | — | — |

Anti-goals: no busy-polling daemons; no always-on network; sandbox creation
budget ≤ 150 ms on Linux (namespace setup dominates; measured in Phase 3).

## Measured (release, Linux x86_64, 2026-10-21)

Run: `Z_BIN=target/release/z cargo run --release -p z-bench -- --check`

| Benchmark | Measured | Gate |
|---|---|---|
| Policy-checked VT parsing | ~11 MiB/s | ≥ 6 MiB/s |
| Raw `vt100` parser | ~12 MiB/s | ≥ 7 MiB/s |
| Screen search (10k-line scrollback) | 0.6–0.9 ms | ≤ 400 ms |
| Block insert (in-memory SQLite) | ~4,000 blocks/s | ≥ 400 blocks/s |
| Block FTS search (3k blocks) | ~5 ms | ≤ 200 ms |
| Audit append (durable, fsync) | ~55,000 events/s | ≥ 80 events/s |
| `z version` warm startup | ~6 ms | ≤ 1,200 ms |

The gates are order-of-magnitude tripwires, not micro-benchmarks: shared CI
runners are noisy. `bench/` contains the harness; the `Performance gate` CI job
runs it on every push and pull request. Startup already beats the stretch goal;
VT throughput is bounded by the `vt100` screen model, not by Zentrion policy
scanning (the two measure within noise of each other).
