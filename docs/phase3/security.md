# Security

Phase 3 keeps the policy boundary and adds a native analysis boundary.

Security properties in this slice:

- commands remain structured; no shell is introduced
- findings are normalized and deduplicated
- secret scanning is pattern-based and does not print credentials by default
- unsupported operations are reported as unsupported rather than fabricated

Security limitations remain honest:

- TLS inspection is still missing as a verified backend
- sandbox enforcement is not part of this patch
- network enumeration is not yet complete