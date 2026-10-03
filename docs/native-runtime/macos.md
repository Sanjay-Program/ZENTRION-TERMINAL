# macOS

## Status

**All macOS code paths in Phase 2 are UNVERIFIED.** No macOS host was
available. Everything below is design intent.

## What is implemented

| Area | Implementation | Status |
|---|---|---|
| Platform target | OS + arch; ABI is `None` (macOS has no ABI variant) | written, unverified |
| Path resolution | `~/Library/Application Support/Zentrion` config+data, `~/Library/Caches/Zentrion` cache | written, unverified |
| OS version | Best-effort read of `SystemVersion.plist` as plain text | written, unverified |
| Executable detection | Unix permission bits (`mode & 0o111`) | written, unverified |
| Process execution | `std::process::Command`, direct, no shell | written, unverified |
| Sandbox level | `FilesystemNetwork` (Seatbelt profiles + rlimits; no syscall filter) | reported honestly |
| Process inspection | Not implemented — needs `libproc` (`proc_pidinfo`) | returns `Unsupported` |
| System memory | Not implemented — needs `sysctl hw.memsize` | returns `None` |

## Universal binaries and architecture

The platform resolver distinguishes `x86_64` and `arm64`, so a universal2
artifact must be listed for both targets. Where both a native slice and a
universal artifact exist, native is selected first (`NATIVE` beats `PORTABLE`
in the precedence order).

## Gatekeeper, quarantine, and code signing

- Zentrion does **not** instruct users to run `spctl --master-disable` or to
  bypass Gatekeeper, and does not strip quarantine attributes from downloaded
  artifacts.
- Downloads go through the normal filesystem, so macOS applies its own
  quarantine behaviour to them. If Gatekeeper blocks an artifact, that is the
  platform's decision and it is surfaced to the user rather than worked around.
- Signature verification of artifacts is **not implemented** (see
  `docs/tools/security.md`). A tool whose manifest sets
  `signature_required: true` therefore fails closed.

## What Phase 3 must do before macOS can be called supported

1. Build and test on macOS x64 and ARM64 in CI.
2. Implement process inspection via `libproc`.
3. Implement memory reporting via `sysctl`.
4. Verify Seatbelt profile generation for `LEVEL 2/3` sandboxing.
5. Test the universal2 selection logic against a real artifact.
