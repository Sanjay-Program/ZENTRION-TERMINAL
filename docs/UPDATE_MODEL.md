# Update Model

## What updates today

- The Rust workspace can be rebuilt from source.
- The tool/runtime layer supports update and rollback operations.
- The packaging script emits a new release archive and checksum.

## What a future release update should do

1. Fetch signed release metadata.
2. Verify checksum and signature.
3. Download the correct platform artifact.
4. Stage the update.
5. Swap atomically.
6. Roll back if the update fails.

## Storage preservation

Updates must only replace application files: the executable, bundled
documentation and installer-managed integration files. They must not delete or
rewrite durable user storage.

Durable storage includes:

- configuration,
- audit logs,
- installed tools,
- sessions and history,
- agent/project memory,
- scan reports.

Use `z storage show` to inspect the paths and `z storage policy` to show the
retention contract. Cache is disposable, but normal updates still leave it in
place unless the user explicitly runs a cache-cleaning command.

## Current limitations

- Automated self-update is not yet a complete end-user workflow in this repo.
- Signed update metadata is not yet available here.
- Website-driven update channels are not implemented.
