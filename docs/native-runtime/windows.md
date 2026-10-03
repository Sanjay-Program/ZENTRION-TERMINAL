# Windows

## Status

**All Windows code paths in Phase 2 are UNVERIFIED.** No Windows host was
available; the code compiles only on Windows targets and has not been built or
run. Treat everything below as design intent, not a verified claim.

## What is implemented

| Area | Implementation | Status |
|---|---|---|
| Platform target | OS + arch + ABI (`msvc` / `wingnu`) | written, unverified |
| Path resolution | `%APPDATA%\Zentrion` config, `%LOCALAPPDATA%\Zentrion` data | written, unverified |
| Executable detection | extension-based (`.exe`, `.cmd`, `.bat`, `.com`) since Windows has no executable bit | written, unverified |
| Process execution | `std::process::Command` — direct execution, no shell | written, unverified |
| Sandbox level | `ResourceLimits` (Job Objects are the ceiling; no syscall filter) | reported honestly |
| Process inspection | Not implemented — needs `CreateToolhelp32Snapshot` / `ntdll` | returns `Unsupported` |
| System memory | Not implemented — needs `GlobalMemoryStatusEx` | returns `None` |

## What is deliberately absent

- **No WSL.** Zentrion never installs, starts, or requires WSL. If a user has
  it and wants it, that is their choice; the tool manager does not use it.
- **No Cygwin/MSYS2.** Execution is direct.
- **No `cmd /c` or `powershell -Command`.** Arguments are passed as an array
  to `CreateProcess` via `std::process::Command`. There is no string
  concatenation and no shell interpretation anywhere in the process layer.
- **No antivirus interference.** Zentrion does not disable, bypass, or
  modify Windows Defender or any other security control, and does not
  instruct users to.
- **No forced elevation.** Nothing runs as Administrator by default. A tool
  manifest may set `requires_elevation: true`, which *requires* a written
  `elevation_reason`; the install preview shows it and the user must approve.

## Architectural honesty

Windows cannot provide Linux-grade confinement for arbitrary child processes.
Zentrion reports `SandboxLevel::ResourceLimits` for Windows rather than
claiming a filesystem or syscall sandbox it cannot deliver. This is the same
position taken in Phase 0 (`docs/10-SANDBOX-SPEC.md`).

## What Phase 3 must do before Windows can be called supported

1. Build and test on Windows x64 and ARM64 in CI.
2. Implement process inspection via Toolhelp32 (or ntdll), including the
   privilege boundary for other users' processes.
3. Implement memory reporting via `GlobalMemoryStatusEx`.
4. Verify the `file://` artifact path works with drive letters and UNC paths.
5. Test the archive extractor against Windows-specific path forms
   (`C:\`, `\\?\`, `\\server\share`) — the validator already rejects
   drive-letter and absolute forms, but this needs a real test run.
