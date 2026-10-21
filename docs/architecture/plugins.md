# Plugins Architecture

## Current state

Zentrion validates **and executes** WASM plugins in a capability-gated
wasmtime host. Validation and execution are separate steps: `inspect`/`load`
never run a module, and `run` re-validates before instantiation.

`z plugin inspect <path.wasm>`:

1. Checks the `\0asm` magic and version 1 header.
2. Reads an optional sibling manifest (`<file>.wasm.json`) with name, version,
   entrypoint and declared permissions.
3. Computes a SHA-256 digest of the artifact.
4. Reports what was validated and how execution would proceed.

`z plugin list [dir]` validates every `.wasm` file in the plugin directory.

`z plugin run <path.wasm> [--input TEXT] [--fuel N] [--memory BYTES]`:

1. Re-validates the artifact and manifest.
2. Instantiates with fuel and a linear-memory limit (`StoreLimits`).
3. Calls `alloc(len) -> ptr`, writes the input into the exported `memory`,
   then calls the manifest entrypoint (`run` by default) with `(ptr, len)`.
4. Reads `(ptr << 32) | len` from the returned `i64`, bounded by the output cap.
5. Persists declared `kv:write` state under the user data directory and writes
   an audit record for the run (success or failure).

## Host ABI

Only four host functions exist, all under the `zentrion` module:

| Import | Capability required | Behaviour |
|---|---|---|
| `log(ptr,len)` | `log` | Appends a bounded (4 KiB) log message. |
| `clock_ms() -> i64` | `clock` | Unix time in milliseconds. |
| `kv_get(key_ptr,key_len,out_ptr,out_len) -> i32` | `kv:read` | Reads persisted per-plugin state. |
| `kv_set(key_ptr,key_len,val_ptr,val_len) -> i32` | `kv:write` | Writes persisted per-plugin state. |

There is deliberately **no** filesystem, network, process, environment or
secret import. A module that imports one fails instantiation, which is reported
as an execution error rather than silently granted.

## Limits and trust

- Fuel (`--fuel`, default 20 million) bounds CPU; exhaustion traps.
- Linear memory (`--memory`, default 64 MiB) is bounded by `StoreLimits`.
- Input and output are capped (1 MiB by default); logs and KV entries are
  bounded; KV state is written with mode `0600`.
- Declared permissions are required but are not trust: the manifest is not
  signed yet, so treat a plugin like any other local executable you chose to
  run. Publisher signatures and a registry trust model remain future work.

## Why the ABI is small

A tiny ABI is auditable and cannot be used to pivot into the host. Richer
plugins (HTTP, files, tools) should be composed by invoking `z` commands under
the execution broker, not by widening the in-process host surface.
