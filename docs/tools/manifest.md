# Tool manifest

A manifest describes one tool at one version. It is JSON, versioned, and
strictly validated — **unknown keys are rejected**, so a typo cannot silently
drop a security-relevant field.

## Full example

```json
{
  "schema_version": "1",
  "id": "org.zentrion.tools.hello-zen",
  "name": "hello-zen",
  "display_name": "Hello Zentrion",
  "version": "1.0.0",
  "description": "Harmless reference tool",
  "publisher": { "name": "Zentrion", "id": "pub_zentrion" },
  "license": "Apache-2.0",
  "homepage": "https://example.invalid/hello-zen",
  "redistribution": "permitted",
  "categories": ["development", "testing"],
  "tags": ["reference", "demo"],
  "platforms": [
    {
      "os": "linux",
      "arch": "x86_64",
      "abi": "gnu",
      "url": "https://example.invalid/hello-zen-1.0.0.tar",
      "sha256": "e3b0c442...",
      "size": 10240,
      "kind": "native"
    }
  ],
  "permissions": {
    "network": false,
    "filesystem": "none",
    "process": true,
    "raw_sockets": false,
    "system_info": false,
    "requires_elevation": false
  },
  "execution": { "binary": "bin/hello-zen", "arguments": [] },
  "dependencies": [],
  "signature_required": false
}
```

## Fields

### Identity

| Field | Required | Rules |
|---|---|---|
| `schema_version` | yes | must be `"1"` |
| `id` | yes | reverse-DNS, lowercase, must end with `.<name>` |
| `name` | yes | `[a-z0-9_-]`, max 64, used as the store directory name |
| `version` | yes | semantic version |
| `display_name` | no | max 128 |

Tools are identified by reverse-DNS id, **not** by display name:
`org.zentrion.tools.nmap`, not `nmap`. The policy, the store and `z run` use
the short `name`; the id is the stable identity.

### Publisher and licensing

| Field | Notes |
|---|---|
| `publisher.id` | `[A-Za-z0-9_.-]`, stable identity |
| `publisher.name` | human label |
| `publisher.key_id` | signing key fingerprint, when signatures are used |
| `license` | SPDX-ish string; recorded, not enforced |
| `redistribution` | `permitted` \| `upstream-only` \| `prohibited` |

`redistribution` is metadata: Zentrion does not rehost an artifact whose
licence forbids it. An `upstream-only` tool points at the vendor's own
download location.

### Platforms

At least one entry is required. Each is validated:

| Check | Rule |
|---|---|
| URL scheme | `https://` or `file://` only. **`http://` is refused** — the manifest and the artifact would share a tamperable channel, so a checksum inside it proves nothing. |
| `sha256` | `sha256:<64 hex>` or a bare 64-char hex digest |
| `size` | greater than zero (except for `reimplemented`) |
| ABI | required for `native`/`external_dependency` on Windows/Linux; forbidden on macOS |
| duplicates | one entry per (os, arch, abi) |
| `unsupported` | must not point at an artifact |
| `external_dependency` | must name `requires` |

### Permissions

Declared, **never automatically granted**.

| Field | Default | Notes |
|---|---|---|
| `network` | `false` | escalates execution risk to HIGH |
| `filesystem` | `"none"` | `none` \| `project` \| `home` \| `full` |
| `process` | `false` | |
| `raw_sockets` | `false` | privileged; always HIGH or CRITICAL |
| `system_info` | `false` | |
| `requires_elevation` | `false` | **requires** `elevation_reason`, and the preview shows it |

A permission set containing network, process, raw sockets, broad filesystem
access or elevation is "sensitive": installing it requires `--approve`.

### Execution

```json
"execution": { "binary": "bin/hello-zen", "arguments": ["--color"] }
```

- `binary` is relative to the installed tool directory. Absolute paths and
  `..` are rejected.
- For a runtime-provided tool, use `native_engine` and leave `binary` empty:

```json
"execution": { "binary": "", "native_engine": "dns.resolve" }
```

Available engines: `dns.resolve`, `sysinfo`, `process.info`, `platform.info`.

### Dependencies

A list of tool ids. Self-dependency is rejected. Phase 2 records dependencies
and refuses a manifest that names an unknown one, but does not yet resolve a
full dependency graph — see [installation.md](installation.md).

## Validation errors

Every rejection names the problem and suggests a fix, for example:

```
ZEN-REG-7045 tool id 'org.zentrion.tools.other' must end with the tool name 'echo'
ZEN-SEC-7062 artifact url must use https:// or file://, got 'http://evil.invalid/x'
ZEN-REG-7020 a tool requesting elevation must explain why (elevation_reason)
```

## Writing manifests

Keep them in a directory and index them:

```
python3 scripts/build-tool-index.py <tools-dir> <output-index.json> [registry-name]
```

The index builder performs the same identity, version and category checks, so
an index that builds is one the client will accept.
