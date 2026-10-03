# Findings

Findings are normalized into a common schema:

- id
- title
- severity
- confidence
- asset
- evidence
- description
- recommendation
- source
- timestamp

Finding deduplication uses a stable fingerprint derived from the title,
severity, asset, evidence and source.