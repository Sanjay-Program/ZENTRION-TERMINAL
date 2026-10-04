# Agents

Agents are a higher-level layer over the existing command, registry, policy and
audit model. They plan work, select tools, hand off to specialist roles and
record traces, but they do not get a private bypass around the broker.

## Runtime shape

The `agents` crate now models:

| Concept | Purpose |
|---|---|
| `AgentProfile` | Name, role, model, max iterations, allowed tools and handoffs |
| `AgentToolPolicy` | Per-agent allowlist for commands such as `z doctor`, `z status`, `z search`, `z info` and `z bundle plan` |
| `GuardrailDecision` | Allow/block result with a human-readable reason |
| `AgentTrace` | Ordered events for goal receipt, model replies, guardrail checks and completion |
| `AgentHandoff` | Planner-to-operator, planner-to-reviewer and planner-to-documenter routing labels |

The default `security-lab-planner` profile is deliberately conservative. It can
plan against the local catalog and status commands, but unknown tools are turned
into blocked observations unless policy is expanded explicitly.

## Safety flow

1. The planner receives a user goal.
2. The model proposes a plan or a safe tool action.
3. The tool guardrail checks the requested command against the profile allowlist.
4. Allowed actions are represented as dry-run style observations.
5. Blocked actions are fed back to the model with the reason.
6. Trace events preserve the decision path for UI, audit and debugging.

This mirrors the platform rule used everywhere else: planning can be helpful and
fast, but host effects must remain explicit, inspectable and policy-bound.

## Useful commands

```
z bundle list
z bundle plan web
z ai explain
z audit tail
```

## Related docs

- [Phase 3 implementation report](PHASE-3-IMPLEMENTATION-REPORT.md)
- [Security model](SECURITY_MODEL.md)
- [Tool system](tools/README.md)
