# AI

Phase 3 starts the AI boundary as a controlled analysis layer rather than a
shell escape hatch.

Current state:

- `z ai analyze` reads the latest local scan report.
- `z ai privacy` reports that the current foundation is local-only.
- No remote provider or API key storage is wired in this slice.

The AI output is intentionally structured so future providers can be inserted
without changing the runtime control plane.