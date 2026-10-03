# Network

The Phase 3 foundation keeps networking native and explicit.

- DNS resolution is provided by the OS resolver.
- Plain HTTP requests can be issued without shelling out.
- HTTPS/TLS inspection is not yet wired in this slice and reports that fact
  honestly.
- Scans are profile-driven and do not imply unrestricted network access.

The current implementation is intentionally small and does not claim full
interface or routing inventory yet.