# Plugins Architecture

## Current state

Zentrion validates WASM plugin artifacts but does **not** execute them.

`z plugin inspect <path.wasm>`:

1. Checks the `\0asm` magic and version 1 header.
2. Reads an optional sibling manifest (`<file>.wasm.json`) with name, version,
   entrypoint and declared permissions.
3. Computes a SHA-256 digest of the artifact.
4. Reports exactly what was validated and states that no execution occurred.

`z plugin list [dir]` validates every `.wasm` file in the plugin directory.

## Why no execution yet

Running untrusted WebAssembly safely requires:

- an embedded runtime (wasmtime/wasmi) and a stable ABI;
- explicit capability grants for filesystem, network and process access;
- resource limits and a mediation path through the execution broker;
- a manifest trust model (signatures, publisher identity).

Shipping none of that and calling plugins “loaded” would be a security lie.
The validation layer is the foundation for a later runtime.
