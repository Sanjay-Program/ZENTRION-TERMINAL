# 28 — SDK

## 28.1 Common interface (defined once, implemented per language)

```ts
// TypeScript reference shape; same concepts in every SDK
interface Zentrion {
  readonly version: string;
  status(): Health;
  // Execution — the only way to affect the host
  exec(req: ExecRequest): Promise<ExecResult>;
  // Capability / policy introspection
  whoami(): ActorIdentity;
  listCapabilities(actor: string): Capability[];
  // Tools / projects
  tools(): ToolRegistry;
  projects(): ProjectApi;
  // AI
  ai: AiClient;               // gateway-mediated; same interface as CLI
  agents: AgentApi;           // create/inspect/kill
  secrets: SecretsApi;        // handle-based; values never returned by default
  audit: AuditApi;            // tail/verify/export
  scan(path: string): ScanReport;
}

interface ExecRequest {
  actor: ActorRef;            // must be an identity the SDK session owns
  action: string;             // "fs.read" etc.
  resource: string;           // scope expression
  reason?: string;            // shown in approval prompts / audit
  ttl?: Duration;
}
```

Rules for all SDKs:
- SDKs are **clients of the runtime** (over local IPC), not embedded libraries —
  security decisions stay in the runtime, one implementation, no per-language bypass.
- No SDK method grants capabilities; requesting a capability mirrors CLI consent flow.
- Language list: TypeScript + Python first (v1), Go, Rust, C++, Java later.
- Each SDK ships its JSON Schema types generated from `schemas/` (single source of truth).

## 28.2 Versioning
SDK SemVer tracks runtime API version; see 29.
