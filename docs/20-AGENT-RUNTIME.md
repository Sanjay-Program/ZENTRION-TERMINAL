# 20 — AGENT RUNTIME

## 20.1 Agent execution loop

```
User intent
   → Agent created (identity, policy, capabilities, limits, TTL)
   → Model plans (ProposedAction[])
   → for each action: Gateway validates → Policy → Capability → Risk →
       [auto | approval | denied]
   → Sandbox executes tool (or rejects)
   → Result fed back to model
   → loop until done | limits hit | denied too often | user stops
   → audit summary, agent terminated, capabilities revoked
```

```mermaid
sequenceDiagram
    participant U as User
    participant A as Agent Runtime
    participant M as Model (via Gateway)
    participant B as Broker
    participant T as Tool (sandboxed)
    U->>A: start("refactor module X", policy, limits)
    A->>A: create identity agt_x + capabilities
    loop until done/limits
        A->>M: plan(state)
        M-->>A: [ToolCall(fs.write ./src/**)]
        A->>B: exec(request)
        B-->>A: granted → A->>T: run
        T-->>A: result
        M returns next step...
    end
    A->>A: revoke capabilities, audit summary
```

## 20.2 Agent identity

```
AgentIdentity {
  id: agt_<random>
  name: "refactor-agent"
  project_id, user_id
  model: ModelRef, provider: ProviderId
  policy_ref, capabilities: Capability[]
  created_at, expires_at (hard TTL), status: active|paused|done|killed|expired
  resources: {cpu_pct, mem_mb, runtime, net_mode, max_tool_calls}
}
```

Lifecycle: `created → active → (paused | done | killed | expired) → audited →
capabilities revoked`. A killed agent cannot be resumed; a new agent = new
identity (no zombie privilege).

## 20.3 Memory & context
- Session memory: conversation + tool results, size-capped, local only.
- Persistent memory: opt-in, project-scoped, stored locally, inspectable
  (`z agent inspect`), never sent to providers except as explicit user action.
- No shared memory between agents by default.

## 20.4 Resource governor (see also 09 policy example)
Enforced per agent: cpu %, memory MB, wall time, network mode (none/
allowlist/full), max tool calls, max file writes, max bytes written. Enforced
by: sandbox (cgroups/rlimits/job objects) + broker-side counters. Breach →
agent paused with clear report.

## 20.5 Approval & termination
- HIGH/CRITICAL actions → approval queue (`z status` shows pending); timeout
  = deny, agent pauses.
- `z agent kill <id>` immediate; `z lockdown` kills all + revokes.
- Agents cannot spawn other agents in v1 (no privilege amplification).

## 20.6 Failure behavior
Model provider fails → agent pauses, state preserved, resumable. Tool fails →
error returned to model as tool result (model may adapt within policy). Too
many consecutive denials (configurable, default 5) → agent stops and reports.
