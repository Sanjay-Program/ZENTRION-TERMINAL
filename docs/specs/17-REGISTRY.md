# 17 — REGISTRY

## 17.1 Model

```
Client (z) ──TLS──▶ Registry API ──▶ Metadata store
                         │
                         ▼
                    Package source (upstream URLs / build artifacts)
                         │
                         ▼
Client-side verification (checksum, signature, provenance) ──▶ Installation
```

The registry is a **catalog**, not an execution authority. It never runs code;
the client independently verifies artifacts against publisher signatures, so a
compromised registry cannot serve trojanized packages (trust is anchored in
publisher keys, not the registry server).

## 17.2 Registry API (v1 sketch)

```
GET  /v1/packages?q=&category=&os=&arch=     → search results (metadata only)
GET  /v1/packages/{name}                     → versions, manifests, permissions
GET  /v1/packages/{name}/{version}/manifest  → signed manifest
GET  /v1/packages/{name}/{version}/artifact  → bytes (static, CDN-cacheable)
GET  /v1/publishers/{id}                     → publisher identity + key
POST /v1/reports                             → security reports (future)
```

Metadata responses are themselves signed by the registry; artifacts are signed
by the **publisher** (minisign/ed25519). Version selection: strict SemVer,
immutable published versions (no overwrite — republish requires new version).

## 17.3 Verification flow at install

```
fetch manifest → verify registry signature → check publisher key (TOFU pin +
web-of-trust later) → fetch artifact → verify publisher signature + checksum →
compare requested permissions vs manifest → consent prompt → install to
staging → quarantine profile on first run → activate
```

## 17.4 Malicious package response
- Report channel → takedown process (future, community + automated signals).
- Client-side: known-bad checksum list (revocation feed, signed) blocks install.
- Installed-but-later-flagged: `z tool alert` shows affected installs and suggests removal; capability revocation is instant.
- No claim of preventing all malware — mechanisms raise cost and enable detection/removal.

## 17.5 Offline behavior
Cached metadata allows browsing/installing previously cached artifacts;
network absence is surfaced, never silently bridged by unknown sources.
