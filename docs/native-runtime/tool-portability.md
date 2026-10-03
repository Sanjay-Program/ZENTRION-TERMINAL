# Tool portability

## The honesty requirement

It is not true that every Linux security tool runs natively on Windows and
macOS. Zentrion does not claim it. Every tool/platform combination is
classified, and the classification is shown to the user.

## Levels

| Level | Stars | Meaning | Installable |
|---|---|---|---|
| **Native** | ★★★★★ | An artifact built for this exact OS + arch + ABI | yes |
| **Adapted** | ★★★★☆ | A platform-equivalent implementation supplied for this target | yes, with a notice |
| **Portable** | ★★★☆☆ | A self-contained artifact valid on this target | yes |
| **Reimplemented** | ★★★☆☆ | The Zentrion runtime provides the capability itself | yes |
| **External dependency** | ★★☆☆☆ | Needs something the user installs deliberately | yes, with explicit opt-in |
| **Unsupported** | ★☆☆☆☆ | No safe implementation exists on this target | **no** |

(The star ratings are defined once, in `compat::ImplementationKind::stars`, and
a test asserts they match this table.)

## Resolution order

Native-first. The first match wins:

1. `native` artifact for the exact target
2. `portable` artifact for the target
3. `adapted` artifact for the target
4. `reimplemented` entry (runtime-provided)
5. `external_dependency` entry
6. `unsupported`

An `unsupported` entry never masks a better option that exists for the same
target.

## ABI matters

OS + architecture is not sufficient. A `linux-x86_64` artifact linked against
musl will not run on a glibc host. Zentrion records and checks the ABI:

```
linux-x86_64-gnu     linux-x86_64-musl
windows-x86_64-msvc  windows-x86_64-wingnu
macos-arm64          (no ABI variant)
```

An ABI-bound artifact that omits its ABI is rejected as underspecified.

## No implicit compatibility environment

This is the rule the codebase enforces, in `compat::assert_no_implicit_compat`:

- An `unsupported` tool cannot be forced — there is no override flag.
- An `external_dependency` tool requires explicit opt-in and names its
  dependency in the manifest.
- Nothing installs WSL, a container runtime, or a VM.

When a tool is unavailable, the user sees:

```
Compatibility: nmap 0.0.0
  current platform: windows-arm64
  implementation:   ★☆☆☆☆ Unsupported — no implementation is available for windows-arm64
  installable:      NO
  available on:     linux-x86_64-gnu, macos-arm64, windows-x86_64-msvc
```

## Trying it

```
z compatibility <tool>          # human-readable per-platform table
z compatibility <tool> --json   # machine-readable
```

Example for a tool that is only partly covered:

```
$ z compatibility trivy
  OS         ARCH       ABI          IMPLEMENTATION
  linux      x86_64     gnu          Native
  macos      arm64      -            Native
  windows    arm64      msvc         Unsupported
```

## Zentrion-native implementations

For functionality that would otherwise be Linux-only, the preferred answer is
a Zentrion implementation rather than a compatibility shim. Phase 2 ships
three, all usable with no external binary:

| Tool | Engine | Provides |
|---|---|---|
| `dnsx` | `dns.resolve` | A/AAAA resolution via the OS resolver |
| `sysinfo` | `sysinfo` | CPU, memory, hostname |
| `procinfo` | `process.info` | Process inspection by pid |

These are declared in a manifest with `execution.native_engine` and no
`binary`. `z run dnsx --port 80 127.0.0.1` resolves entirely inside the
runtime.

## What is not yet provided natively

Honest list of gaps: HTTP client, TLS inspection, port scanning, packet
capture, filesystem watching. These are Phase 3+ engines. Tools needing them
are currently `external_dependency` or not listed at all.
