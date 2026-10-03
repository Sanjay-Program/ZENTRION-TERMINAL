# Registry

## A catalogue, not an execution authority

The registry serves metadata. It never runs code, and installing from it is not
"trusting the registry" — the client verifies artifacts against the checksums
in the manifest.

## Local registry (used by default in development)

```
my-registry/
  index.json
  tools/
    hello-zen-1.0.0.json
    nmap-catalog.json
  artifacts/            # only for artifacts Zentrion may redistribute
    hello-zen-1.0.0.tar
```

Point the client at one with `--registry <dir>` or `ZENTRION_REGISTRY_DIR`.
This is what the test suite uses: no cloud service is required.

## Index format

```json
{
  "schema_version": "1",
  "registry_name": "zentrion-test",
  "tools": [
    {
      "id": "org.zentrion.tools.hello-zen",
      "name": "hello-zen",
      "version": "1.0.0",
      "display_name": "Hello Zentrion",
      "description": "Harmless reference tool",
      "categories": ["development", "testing"],
      "tags": ["reference"],
      "publisher_id": "pub_zentrion",
      "publisher_name": "Zentrion",
      "trust": "community-verified",
      "license": "Apache-2.0",
      "manifest": "tools/hello-zen-1.0.0.json"
    }
  ]
}
```

Index entries are validated on load: identifiers must be reverse-DNS, versions
must be semantic, and `manifest` paths must resolve **inside** the registry
root — a traversing path is rejected before any file is opened.

## Index and manifest must agree

If the index says version `1.0.0` and the manifest it points to says `2.0.0`,
the client refuses:

```
ZEN-REG-7221 index/manifest mismatch for hello-zen 1.0.0:
             index says org.zentrion.tools.hello-zen 1.0.0,
             manifest says org.zentrion.tools.hello-zen 2.0.0
```

This catches a stale index and, more importantly, an index that has been
tampered with to point a trusted name at a different manifest.

## Trust levels

| Level | Meaning | Behaviour |
|---|---|---|
| `official` | published by Zentrion | installs |
| `verified-publisher` | publisher identity checked out of band | installs |
| `community-verified` | community reviewed, self-declared | installs |
| `unknown` | known publisher, not verified | **requires `--approve`** |
| `revoked` | known bad | **blocked** |

`unknown` is never treated as trusted. `revoked` is refused at manifest load,
so a revoked version cannot be installed even by name.

**These are labels.** Zentrion does not currently verify them
cryptographically — see [security.md](security.md).

## Search

Search is offline and matches against local registry metadata only:

```
z search web security       # all terms must match (name, id, description, tags)
z search --category network
z search nmap --json
```

There is no web search, and no query is sent anywhere.

## Building an index

```
python3 scripts/build-tool-index.py <tools-dir> <output-index.json> [name]
```

The builder performs the same checks as the client (identity shape, schema
version, category validity, duplicate detection), so an index it produces is one
the client will accept.

## Remote registries

`RemoteRegistry` is defined but the transport is not compiled in by default.
Without the `http` feature, a remote registry reports:

```
ZEN-REG-7230 remote registries require the `http` feature, which is not enabled in this build
```

It does not silently return an empty catalogue.

## Development vs production

For Phase 2 the local registry is the supported path. A hosted registry is a
later phase, and when it arrives the same client-side verification applies: the
registry will be a distribution channel, not a trust anchor.
