# CLI reference

All commands accept:

- `--json` — machine-readable output
- `--project <path>` — use this project instead of discovering the nearest one

Exit codes: `0` success · `1` usage · `2` denied by policy · `3` approval
rejected · `4` sandbox failure · `5` integrity failure · `6` network ·
`7` internal · `130` interrupted.

---

## `z version`

Version, runtime version, platform, architecture, build type.

```sh
z version
z version --json
```

---

## `z help`

`z help`, `z --help`, or `z <command> --help`.

---

## `z doctor`

Read-only health check. **Performs no network calls.**

Checks: OS and architecture, platform support, shell, executable path, whether
`z` is on `PATH`, config validity, data-directory writability, project
validity, and policy validity.

```sh
z doctor
z doctor --json
```

---

## `z status`

Runtime, configuration location, project, effective policy, audit state and
platform. Never prints secrets.

```sh
z status
```

---

## `z config`

```sh
z config get                     # all safe keys
z config get log_level
z config set log_level debug
z config set telemetry_enabled true
z config path                    # where config is stored
```

Settable keys: `log_level` (`trace|debug|info|warn|error`),
`telemetry_enabled` (`true|false`). Unknown keys are rejected. Secrets are
never stored in configuration.

---

## `z init [path] [--name N]`

Creates `.zentrion/` with six manifests. Refuses to overwrite an existing
project.

```sh
z init my-project
z init . --name existing-dir-project
```

An explicitly supplied `--name` is validated strictly and never silently
rewritten: `--name '../evil'` is an error, not `evil`.

---

## `z project [--check]`

Displays project name, root, config path, runtime, policy and platform.
`--check` validates the manifests and exits non-zero if anything is missing.

```sh
z project
z project --check
```

---

## `z policy <show|validate|test>`

```sh
z policy validate
z policy show
z policy test filesystem.read ./src/main.rs
z policy test process.spawn echo
```

`test` is a dry run — it reports ALLOW, DENY or REQUIRE_APPROVAL, the risk
level, and the reason, without executing anything.

---

## `z audit <tail|verify>`

```sh
z audit                 # verify the chain
z audit verify
z audit tail 50
```

`verify` recomputes the SHA-256 hash chain and reports the first broken link
if the log has been modified.

---

## `z run <program> [args...] [--approve]`

Executes a program through the broker. **Never invokes a shell.**

```sh
z run echo hello
z run echo 'a; echo PWNED'        # literal text; no second command runs
z run git status
z run rm -rf build --approve      # HIGH risk requires explicit approval
```

The program must be listed under `process.spawn` in the project policy. If it
is not, the command is denied with exit code 2 and a plain-language
explanation. Arguments are passed verbatim.

`--approve` is required for HIGH and CRITICAL risk actions. It never widens
the policy — it only confirms an already-permitted action.

---

## `z lockdown`

Reports lockdown state. In Phase 1 there are no agents or daemons to
terminate; this becomes a real kill-switch in Phase 3.
