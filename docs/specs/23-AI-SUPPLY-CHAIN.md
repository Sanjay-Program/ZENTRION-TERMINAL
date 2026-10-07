# 23 — AI SUPPLY CHAIN

## 23.1 Graph model

```
Application
 └─ Agent
     └─ Model (provider)
         └─ MCP servers
             └─ Tools
                 └─ Packages
                     └─ Dependencies
                         └─ External APIs
```

Every edge is derivable from artifacts Zentrion already holds: agent registry
(agent → model), MCP registrations (agent → server), tool manifests (tool →
source/packages), lockfiles (package → deps), gateway logs (agent → external API
actually contacted).

## 23.2 Analysis capabilities
- **Inventory**: `z ai bom` (22) — the nodes.
- **Edges**: `z ai supply-chain --dot` renders the full graph; each edge annotated with trust level and data flow (does data leave the machine?).
- **Risk queries**: "which external endpoints can agent X reach transitively?", "which components changed since last release?", "does any path from my code reach a community-trust MCP server?"
- **Change detection**: diff of the graph between two points in time → new nodes flagged in CI.

## 23.3 Data-flow annotation
Each edge records whether **code, prompts, or data** flow across it and to
where (local / BYOK cloud / Zentrion cloud). This makes "where does my code
go?" answerable with a command rather than an audit.

## 23.4 Limits
- Visibility covers only components that run through Zentrion. A model or
  tool invoked outside the runtime is invisible — documented honestly.
- Transitive dependencies of MCP servers (e.g., npm tree of an npx server)
  are included at the package level when lockfiles are available; dynamic
  installs are flagged as "unresolved".
