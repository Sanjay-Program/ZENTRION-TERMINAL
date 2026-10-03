# Development

## Layout

```
zentrion/
├── core/         z-core: error, config, host probe, fs, process, runtime
├── policy/       policy model, strict parser, layer merge, evaluator
├── capability/   capability store (issue/check/revoke/expire)
├── audit/        hash-chained audit log + SHA-256
├── identity/     actor identity and local-user resolution
├── projects/     project scaffolding and validation
├── exec/         execution broker (the single choke point)
├── cli/          the `z` binary and all commands
├── tests/        end-to-end CLI integration tests
├── scripts/      build, test, lint, format, package, install
├── docs/         user documentation
└── .github/      CI workflows
```

Dependency direction is strictly downward and acyclic:

```
cli → exec → {policy, capability, identity, audit, core}
projects → {core, policy}
policy, capability, audit, identity → core
```

## Commands

```sh
scripts/build.sh [release]   # build
scripts/test.sh              # run all tests
scripts/lint.sh              # clippy with -D warnings
scripts/format.sh [--check]  # rustfmt
scripts/package.sh           # produce a distributable tarball
./scripts/check-no-secrets.sh
```

## Adding a policy scope

1. Add fields to `policy/src/model.rs` with `#[serde(deny_unknown_fields)]`.
2. Validate the scope in `policy/src/parser.rs::validate_scopes`.
3. Handle it in `policy/src/eval.rs::evaluate` and `classify_risk`.
4. Update `policy/src/merge.rs::merge` (intersection only — never union).
5. Add conformance vectors in the `tests` module.
6. Update `docs/schemas/policy-v1.json` in the Phase 0 docs.
7. Update `SECURITY-MODEL.md` and the CLI reference.

A new action must never default to ALLOW.

## Adding a command

1. Add a variant to `enum Commands` in `cli/src/main.rs`.
2. Implement it in `cli/src/commands.rs`, supporting `--json`.
3. If it can affect the host, route it through `z_exec::Broker` — never call
   the process or filesystem APIs directly from the CLI.
4. Add an integration test in `tests/cli_integration.rs`.
5. Document it in `docs/CLI.md`.

## Testing conventions

- Unit tests live next to the code in `#[cfg(test)] mod tests`.
- Integration tests run the real binary in an isolated `ZENTRION_CONFIG_DIR`
  and `ZENTRION_DATA_DIR`, so they never touch developer state.
- Security-relevant behaviour needs an explicit test asserting the *refusal*,
  not just the success path.
- Tests must not require network access.

## Code standards

- `cargo fmt` clean, `cargo clippy -- -D warnings` clean.
- No `unwrap()` on user-supplied input in non-test code.
- Errors are `ZenError` with a plain-language message and, where useful, a
  suggested action.
- Every security-relevant failure path fails *closed*.
