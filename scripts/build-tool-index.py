#!/usr/bin/env python3
"""Build a registry index.json from a directory of tool manifests.

This is the developer tool behind `z dev build-tool-index`.

Each manifest is validated for the fields the index needs. The script does
NOT download or verify artifacts; it only indexes manifest metadata.
"""
import json
import os
import sys
import hashlib

CATEGORIES = {
    "development","security","network","web","cloud","devops","database","ai",
    "ml","data","osint","forensics","privacy","mobile","reverse-engineering",
    "testing","system",
}

def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("usage: build-tool-index.py <tools-dir> <output-index.json> [registry-name]")
        sys.exit(2)
    tools_dir, out_path = sys.argv[1], sys.argv[2]
    registry_name = sys.argv[3] if len(sys.argv) > 3 else "zentrion-local"

    if not os.path.isdir(tools_dir):
        fail(f"{tools_dir} is not a directory")

    entries = []
    seen = set()
    for name in sorted(os.listdir(tools_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(tools_dir, name)
        with open(path, "r", encoding="utf-8") as fh:
            try:
                m = json.load(fh)
            except json.JSONDecodeError as e:
                fail(f"{path}: invalid JSON: {e}")

        for field in ("schema_version","id","name","version","publisher","platforms"):
            if field not in m:
                fail(f"{path}: missing required field '{field}'")
        if m["schema_version"] != "1":
            fail(f"{path}: unsupported schema_version {m['schema_version']!r}")
        if not isinstance(m["platforms"], list) or not m["platforms"]:
            fail(f"{path}: 'platforms' must be a non-empty list")

        ident = m["id"]
        if ident.count(".") < 2:
            fail(f"{path}: id must be reverse-DNS, got {ident!r}")
        if not ident.endswith("." + m["name"]):
            fail(f"{path}: id must end with the tool name")

        for cat in m.get("categories", []):
            if cat not in CATEGORIES:
                fail(f"{path}: unknown category {cat!r}")

        key = (ident, m["version"])
        if key in seen:
            fail(f"{path}: duplicate {ident} {m['version']}")
        seen.add(key)

        publisher = m["publisher"]
        entries.append({
            "id": ident,
            "name": m["name"],
            "version": m["version"],
            "display_name": m.get("display_name"),
            "description": m.get("description"),
            "categories": m.get("categories", []),
            "tags": m.get("tags", []),
            "publisher_id": publisher.get("id", ""),
            "publisher_name": publisher.get("name", ""),
            "trust": m.get("trust", "community-verified"),
            "license": m.get("license"),
            "manifest": f"tools/{name}",
        })

    index = {
        "schema_version": "1",
        "registry_name": registry_name,
        "tools": entries,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
        fh.write("\n")
    print(f"wrote {out_path}: {len(entries)} entries")

if __name__ == "__main__":
    main()
