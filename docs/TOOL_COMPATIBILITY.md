# Tool Compatibility

This document describes the current compatibility policy rather than claiming
full platform support for every tool.

## Rules

- A tool must declare its supported platforms and architectures.
- Native tools are preferred where they exist.
- Unknown or revoked tools are not treated as equivalent to official tools.
- A tool may be installable but still blocked from execution by policy.

## Current status

- Compatibility metadata exists in the tool registry and installer pipeline.
- The repository does not yet ship a complete public compatibility matrix for
  every available tool.
- Platform labels in tool output are honest about unsupported combinations.

## What users should expect

- If a tool is not available on the current platform, the UI should say so.
- If a tool has a known fallback, it should be shown explicitly.
- If a tool requires external dependencies, that should be disclosed before
  installation.
