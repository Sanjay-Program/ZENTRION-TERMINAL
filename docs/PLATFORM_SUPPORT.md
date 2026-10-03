# Platform Support

## Current honest status

| Platform | Architecture | Status | Notes |
|---|---|---|---|
| Linux | x64 | Stable in this workspace | Built and tested here |
| Linux | ARM64 | Experimental | Represented in code; not executed here |
| macOS | Intel | Planned | Declared, not executed here |
| macOS | Apple Silicon | Planned | Declared, not executed here |
| Windows | x64 | Planned | Declared, not executed here |
| Windows | ARM64 | Planned | Declared, not executed here |

## Installer formats

| Platform | Installer | Status |
|---|---|---|
| Linux | tar.gz + per-user shell install | Implemented |
| Linux | package manager formats | Planned |
| macOS | DMG | Planned |
| Windows | EXE/MSIX | Planned |

## Principles

- Do not claim compatibility until tested.
- Keep the matrix explicit about architecture and installer format.
- Prefer honesty over optimistic marketing copy.
