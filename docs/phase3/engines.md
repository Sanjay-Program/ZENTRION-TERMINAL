# Engines

Phase 3 introduces a native engine registry so the runtime can own reusable
analysis primitives instead of relying only on external tools.

Implemented in this slice:

- `dns` for resolver-backed host lookups
- `url` for URL component analysis
- `http` for plain HTTP/1.1 requests over `TcpStream`
- `tls` as an honest unsupported stub until a verified backend is wired in
- `process` for native process inspection
- `filesystem` for native metadata inspection
- `system` for host metadata
- `secrets`, `code`, `dependencies`, `assets`, `findings` as foundations

The registry is available through `z engine list`, `z engine info <name>` and
`z engine doctor`.