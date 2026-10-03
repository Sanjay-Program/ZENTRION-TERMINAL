# Tool security

What Zentrion actually verifies, and what it does not.

## Verified

### Checksum (SHA-256)

Every artifact is hashed before anything is written, and compared against the
manifest. A mismatch quarantines the artifact and aborts the install. The
implementation is covered by the standard SHA-256 test vectors.

### Manifest validation

Manifests and index entries are untrusted input and are validated strictly:

- unknown keys rejected (`deny_unknown_fields`)
- identifier, version, tag and length limits
- `http://` artifact URLs refused outright
- checksums must parse as real digests
- ABI rules enforced per platform
- `unsupported` entries must not point at artifacts
- `external_dependency` entries must name the dependency
- tool `id` must end with the tool `name`

### Archive extraction

An archive is the classic escape vector. All of the following are refused
**before** anything is written:

| Attack | Handling |
|---|---|
| `../../../../startup` | rejected: path traversal |
| `/etc/cron.d/evil` | rejected: absolute path |
| `..\..\evil` (backslashes) | rejected: normalized then checked |
| `C:\Windows\evil.exe` | rejected: drive letter |
| NUL byte in a name | rejected |
| symlink entry | rejected (this is how extraction escapes) |
| hardlink entry | rejected |
| device/fifo entry | rejected |
| extended headers | rejected (not misinterpreted) |
| >10 000 entries | rejected: file-count bomb |
| >1 GiB total expansion | rejected: decompression bomb |
| >512 MiB single entry | rejected |
| depth > 32, component > 255 bytes | rejected |
| duplicate entries | rejected (ambiguous overwrite) |
| truncated archive | rejected: missing end-of-archive marker |
| header size ≠ extracted bytes | rejected: inconsistent length |

Extraction is two-phase: a plan is built and fully validated first, then
executed. A test asserts that an archive with one good entry followed by one
bad entry writes **nothing**.

### Staging and activation

Extraction happens in a private temp directory (mode 0700 on Unix), outside the
store. It is moved into place with an atomic rename only after every check
passes. A failed install therefore cannot leave a partially-installed tool
marked active, and it cannot disturb the currently active version.

### Executable validation

The declared `execution.binary` must exist after extraction, must be relative,
and must not be a symlink. On Unix it is chmod'd to 0755. A tool whose declared
binary is absent is refused.

### Path safety

- Tool names: `[A-Za-z0-9_.-]`, no leading dot, no separators, no `..`.
- Versions used as directory names must parse as semantic versions.
- Cache keys must be 64-character hex digests.
- Registry `manifest` paths must resolve inside the registry root.
- `canonical_within` resolves symlinks and refuses a path that escapes the
  tool directory.
- `z remove` refuses any path outside the tool store.

### No shell

There is no `sh -c`, `cmd /c`, `eval` or string concatenation in the process
layer. Arguments are a structured array. Tests assert that `;`, `&&`, `$( )`,
backticks, redirects, newlines, quotes and Unicode remain literal.

### Environment hygiene

`ZENTRION_SECRET` and `SSH_AUTH_SOCK` are removed from every child
environment. Secrets are never placed in the environment by default.

### Command injection at the registry boundary

The manifest is data, never a command. No field of a manifest is ever passed
to a shell. `execution.binary` is a relative path resolved inside the tool
directory, not a command string.

### Audit

Install, remove, update, rollback and execute all produce hash-chained audit
events. `z audit verify` recomputes the chain. The audit schema has no field
capable of holding a secret value.

## NOT verified — read this

### Signature verification: not implemented

**Zentrion cannot verify artifact signatures in Phase 2.** The interface exists
and returns `Unsupported`; it never reports a fake success.

Consequence: a manifest may set `"signature_required": true`, and such a tool
**fails closed** — it will not install, because the requirement cannot be met.

Consequence: for tools that do not require a signature, authenticity rests on
the checksum **plus the integrity of the channel the manifest travelled over**.
If a registry is compromised and serves both a malicious manifest and a
matching artifact, the checksum will match. This is the single most important
limitation of Phase 2.

### Trust levels are labels, not verification

`official`, `verified-publisher`, `community-verified`, `unknown`, `revoked` are
recorded in the index. `revoked` blocks installation; `unknown` requires
`--approve`. The other levels are **claims by the registry**, not
cryptographically verified facts. Signature verification is what would make
them real.

### Sandboxing: not implemented

Policy decides whether a tool runs. Nothing confines it once running. A
permitted tool has the user's full privileges. See
[native-runtime/sandbox.md](../native-runtime/sandbox.md).

### Malware scanning: not implemented

Zentrion does not scan artifacts for malware and does not integrate with an
antivirus. It does not disable or bypass Windows Defender, Gatekeeper or any
other platform control.

### Correct statement of the guarantee

> Zentrion verifies package **integrity** (the artifact matches the manifest's
> checksum) and enforces a **trust model** (levels gate installation and
> execution). It does not verify **authenticity** cryptographically, and it
> does not scan for malware.

Not: "Zentrion makes malware impossible."

## Security tooling and authorization

Zentrion ships no tools and no default workflows that target systems the user
does not own. Registry entries for security tools describe legitimate
defensive and authorized-testing use. Running a scanner against a third party
without authorization is the user's legal responsibility, and Zentrion
implements no mechanism to conceal such activity.
