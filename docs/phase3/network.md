# Network

The Phase 3 foundation keeps networking native and explicit.

- DNS resolution uses the OS resolver for A/AAAA and a built-in wire-protocol
  client for CNAME/MX/TXT/NS/SOA/PTR (UDP, with TCP fallback when truncated).
- Plain HTTP requests can be issued without shelling out.
- TLS endpoints can be inspected natively: negotiated version/cipher, chain
  trust, subject/issuer/SANs, expiry and hostname match. Untrusted
  certificates are reported as untrusted, never as verified.
- Scans are profile-driven and do not imply unrestricted network access.

The current implementation is intentionally small and does not claim full
interface or routing inventory yet.