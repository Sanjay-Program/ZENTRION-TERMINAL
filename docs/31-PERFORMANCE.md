# 31 — PERFORMANCE

Targets measured on a reference machine: 4-core/8GB SSD x64 Linux, warm caches.
All numbers are **goals to be validated by benchmarks in Phase 2**, not claims.

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

Benchmarks live in `tests/bench/`; CI records trends; regressions > 20% block
merge on the broker/policy paths.
