# Quickstart

Five minutes from install to a useful, safe workflow.

## 1. Check your environment

```sh
z doctor
```

Confirms your OS, architecture, shell, config/data directories, and whether
your platform is supported. Runs fully offline.

## 2. Create a project

```sh
z init my-project
cd my-project
```

This writes `.zentrion/` with six manifests:

| File | Purpose |
|---|---|
| `project.yaml` | project identity, languages, platform requirements |
| `policy.yaml` | what may be read, written, executed; network; secrets |
| `tools.yaml` | pinned tools (empty in Phase 1) |
| `ai.yaml` | AI provider/model settings (unused in Phase 1) |
| `environment.yaml` | environment profiles |
| `secrets.yaml` | secret *handles* only — never values |

## 3. Inspect the defaults

```sh
z status
z project
z policy validate
```

The default policy is deny-by-default: workspace read/write only, no network,
no secrets, no admin, **no process spawning**.

## 4. Try to run something (and be blocked)

```sh
z run echo hello
```

```
✗ Zentrion blocked this command.
    What was attempted:  run 'echo hello'
    Why blocked:         process.spawn []
    Policy:              .zentrion/policy.yaml (process.spawn)
    Risk:                MEDIUM
    Options:
      (1) add the program to `process.spawn` in .zentrion/policy.yaml
      (2) run a different, permitted command
      (3) cancel
    Audit:               ev_00000001 recorded
```

Exit code is `2` for a policy denial.

## 5. Allow one specific program

Edit `.zentrion/policy.yaml`:

```yaml
process:
  spawn:
    - "echo"
```

Now:

```sh
z policy test process.spawn echo     # dry-run the decision first
z run echo hello                     # runs
z run echo 'a; echo PWNED'           # semicolon is literal — no shell
z run curl example.com               # still denied — not on the list
```

## 6. Check the audit trail

```sh
z audit tail        # recent decisions
z audit verify      # verify the hash chain
```

Every decision — allow, deny and approval-required — is recorded.

## 7. Predict a decision without acting

```sh
z policy test filesystem.read ./src/main.rs
z policy test network.connect host:example.com:443
```

## What is not available yet

Sandboxing, secrets, AI, agents, MCP, plugins, and tool installation arrive in
later phases. See [Known limitations](../README.md#known-limitations).
