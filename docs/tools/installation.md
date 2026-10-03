# Installation

## The pipeline

`z install <tool>` runs this sequence. Every step must pass; a failure aborts
and leaves the previous state intact.

```
 1. resolve the tool and version
 2. load and validate the registry manifest  (strict schema)
 3. check trust level                        (revoked = refuse)
 4. resolve platform + architecture + ABI    (native-first)
 5. build the plan                           (--dry-run stops here)
 6. signature policy check                   (before any bytes move)
 7. fetch bytes                              (cache first, then loader)
 8. verify SHA-256                           (mismatch -> quarantine)
 9. store in the verified cache
10. extract into a staging directory         (safe extraction)
11. validate the declared executable exists
12. move staging into the version directory  (atomic rename)
13. write manifest.json + metadata.json
14. activate the version                     (atomic pointer write)
15. audit                                     (hash-chained event)
```

Steps 8 and 11 are the ones that matter most: nothing is written from an
artifact that failed its checksum, and nothing is activated whose declared
executable is missing.

## Preview first

```
$ z install nmap --dry-run
Install preview (no changes made)
  tool:         nmap 0.0.0
  id:           org.zentrion.tools.nmap
  platform:     linux-x86_64-gnu
  implementation: external_dependency — requires an external dependency
  publisher:    Upstream (trust: community-verified)
  license:      NPSL
  artifact:     https://nmap.org/
  sha256:       sha256:0000...
  permissions:
    network:    yes
    filesystem: none
    process:    yes
    raw sockets: yes (privileged)
  destination:  /home/you/.local/share/zentrion/tools/nmap/0.0.0
```

A dry run performs **no** filesystem writes and **no** network access.

## Permission confirmation

If a tool requests network, process spawning, raw sockets, broad filesystem
access, or elevation, the install stops and shows the permissions:

```
$ z install nmap
nmap requires:
  network:    yes
  filesystem: none
  process:    yes
  raw sockets: yes (privileged)
  elevation:  required (raw socket capture)

Re-run with --approve to confirm these permissions.
```

`--approve` is a **confirmation**, not a widening of policy. Installing a tool
never makes it runnable; see "Installation is not permission" below.

## Verification failures

A checksum mismatch is the interesting case:

```
$ z install example
✗ ZEN-SEC-6004 checksum mismatch: expected 4f3a…, got 9c21…
  Suggested action: The artifact does not match its manifest. It has been quarantined.
```

The artifact is written to `<data>/quarantine/<sha256>.quarantined` with a
header recording the expected checksum, the URL and the reason. It is never
executed, and the cache does not retain it under the expected name — so a
later install re-fetches rather than silently using poison.

## Cache behaviour

- After a successful verification the artifact is stored at
  `cache/artifacts/<sha256>`.
- On a later install the cache is used **only after re-verification**. A
  planted file with the right name but wrong bytes is rejected.
- `z cache clean` removes cached artifacts. Installed tools live under
  `tools/`, not `cache/`, so they are untouched.

## Offline

```
z install <tool> --offline
```

- If the artifact is in the verified cache, the install proceeds.
- If not, it fails with a clear message. It does not fall back to another
  source, and it does not reach the network.

## Idempotence and versions

- Reinstalling an already-installed version reports `already installed` and
  changes nothing.
- Multiple versions coexist:

```
tools/hello-zen/1.0.0/
tools/hello-zen/1.1.0/
tools/hello-zen/active      -> "1.1.0"
```

- Select one explicitly with `z use hello-zen@1.0.0`.
- The `active` pointer is written to a temporary file and renamed, so a crash
  cannot leave a half-written pointer.

## Version requirements

`--version` accepts semantic-version requirements:

| Syntax | Meaning |
|---|---|
| `1.2.3` | exactly 1.2.3 |
| `=1.2.3` | exactly (explicit) |
| `>=1.2` | at least 1.2.0 |
| `<=1.2` | at most 1.2.0 |
| `>1.2` / `<1.2` | strictly greater / less |
| `^1.2.3` | compatible: `>=1.2.3`, same major |
| `~1.2.3` | patch-level: `>=1.2.3`, same major.minor |
| `*` | any |

The highest satisfying version is chosen. Pre-releases sort below their
release, so `1.0.1-rc1` loses to `1.0.1`.

## Update and rollback

```
z update            # all tools with a newer version available
z update nmap       # one tool
z rollback nmap     # switch back to the other installed version
```

Update installs the newer version through the same verified pipeline and keeps
the previous version installed, so a rollback is a pointer change rather than
a re-download.

## Removal

```
z remove nmap                  # all versions
z remove nmap --version 1.0.0  # one version
z uninstall nmap               # alias
```

Removal only ever deletes inside the tool store, under a path built from a
validated tool name and a validated version. Tool names and versions that
contain a path separator or `..` are rejected before any filesystem call, so a
crafted name cannot reach user files.

## Installation is not permission

This is deliberate and worth stating plainly:

> Installing a tool does **not** allow it to run.

Execution requires the tool to be named in the policy:

```yaml
tools:
  allow:
    - "nmap"
```

Without that, `z run nmap` exits 2 and says why. The manifest's declared
permissions inform the *install* prompt; they never grant a *run* capability.

## Failure behaviour

| Situation | Result |
|---|---|
| Network unavailable, artifact not cached | clear error, nothing changed |
| Checksum mismatch | quarantine, error, previous version untouched |
| Archive contains traversal/symlink | extraction refused, nothing written |
| Declared executable missing | install refused, nothing activated |
| Disk full mid-extract | staging removed, previous version intact |
| Interrupted (Ctrl+C) | staging is a temp dir outside the store, so it is never active |
| Signature required but unavailable | fail closed |
| Already installed version | idempotent no-op |
