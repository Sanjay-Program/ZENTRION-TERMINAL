# Developing tools for Zentrion

## Layout

```
my-tool/
  manifest.json      the tool manifest
  src/               source
  build/             produces the artifact
  tests/             your own tests
```

## 1. Write the manifest

Start from the schema in [manifest.md](manifest.md). The two things people get
wrong:

- `id` must be reverse-DNS **and end with `name`**.
- Artifact URLs must be `https://` or `file://`. `http://` is refused.

```json
{
  "schema_version": "1",
  "id": "com.example.tools.mytool",
  "name": "mytool",
  "version": "1.0.0",
  "publisher": { "name": "Example Ltd", "id": "pub_example" },
  "license": "MIT",
  "categories": ["development"],
  "platforms": [
    { "os": "linux",   "arch": "x86_64", "abi": "gnu",  "url": "https://…", "sha256": "…", "size": 1234, "kind": "native" },
    { "os": "macos",   "arch": "arm64",                 "url": "https://…", "sha256": "…", "size": 1234, "kind": "native" },
    { "os": "windows", "arch": "x86_64", "abi": "msvc", "url": "https://…", "sha256": "…", "size": 1234, "kind": "native" }
  ],
  "permissions": { "network": false, "filesystem": "project", "process": true },
  "execution": { "binary": "bin/mytool" }
}
```

Note the ABI rules: required on Windows/Linux for native artifacts, forbidden on
macOS.

## 2. Declare the minimum permissions

Permissions are what the user is asked to approve at install time. Ask for
nothing you do not need; a tool requesting `network` or `raw_sockets` is
escalated to HIGH risk and needs explicit approval every time it runs.

`requires_elevation: true` additionally **requires** an `elevation_reason`
string that the user sees.

## 3. Choose an artifact format

| Format | When |
|---|---|
| Single executable | Simplest. Written directly to `bin/`. |
| `.tar` / `.tar.gz` | Multiple files. Extraction is strictly validated. |

`.zip` and `.tar.zst` are refused in this build — the error says so rather than
attempting a partial extraction.

The declared `execution.binary` must exist in the extracted tree. Installation
fails otherwise, which is a useful early signal that your packaging is wrong.

## 4. Test locally

```sh
# build your index
python3 scripts/build-tool-index.py ./tools ./registry/index.json my-registry

# point zentrion at it
export ZENTRION_REGISTRY_DIR=$PWD/registry

z search mytool
z info mytool
z install mytool --dry-run
z install mytool --approve
z verify mytool
z run mytool -- --help
z remove mytool
```

Run against an isolated store while developing:

```sh
export ZENTRION_DATA_DIR=/tmp/zen-dev
```

## 5. What the client will reject

A non-exhaustive list, so you can predict the failure:

| Rejection | Cause |
|---|---|
| unknown field | a typo, or a field from a newer schema |
| `id` must end with the tool name | mismatch between `id` and `name` |
| artifact url must use https:// or file:// | you used `http://` |
| native artifacts on Windows/Linux must declare an ABI | missing `abi` |
| macOS artifacts must not declare an ABI | you set one |
| a tool requesting elevation must explain why | missing `elevation_reason` |
| an 'unsupported' platform entry must not point at an artifact | remove the URL |
| an 'external_dependency' entry must name the dependency | missing `requires` |
| duplicate platform entry | two entries for the same (os, arch, abi) |
| unknown category | see the category list below |

## Categories

`development` `security` `network` `web` `cloud` `devops` `database` `ai`
`ml` `data` `osint` `forensics` `privacy` `mobile` `reverse-engineering`
`testing` `system`

## Runtime-provided tools (no artifact)

If the capability is something the Zentrion runtime already provides, declare a
native engine instead of shipping a binary:

```json
"platforms": [
  { "os": "linux", "arch": "x86_64", "abi": "gnu",
    "url": "file:///dev/null", "sha256": "<hash of empty>",
    "kind": "reimplemented" }
],
"execution": { "binary": "", "native_engine": "dns.resolve" }
```

Available engines are listed by `z_native_engines::available_engines()`.

## Licensing

Record the real licence and set `redistribution` honestly:

- `permitted` — Zentrion may host the artifact.
- `upstream-only` — point at the vendor's own download location; do not expect
  us to mirror it.
- `prohibited` — do not submit an artifact URL at all.

Do not submit an artifact you have no right to redistribute.

## Security tools

Defensive and authorized-testing tooling is welcome. Manifests must not
describe workflows that target systems the user does not own, and no tool may
attempt to conceal activity from a system's owner.

## Roadmap for tool authors

Not in Phase 2, but planned: a `zentrion-tool-sdk` providing logging, HTTP,
DNS, filesystem, process, configuration and policy helpers via a `ToolContext`,
so tools do not each reimplement HTTP. See `docs/03-SYSTEM-ARCHITECTURE.md`.
