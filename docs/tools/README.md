# The tool system

Install, verify, run and remove tools through one interface on any platform.

```
z search nmap
z bundle list
z bundle plan web
z info nmap
z install nmap
z list
z run nmap -- --version
z remove nmap
z update
z verify nmap
```

## Principles

1. **Nothing is bundled.** The base install contains no security tools and no
   models. Tools are installed on demand and the base stays small.
2. **Every install is verified.** A SHA-256 checksum from the manifest must
   match before anything is extracted. A mismatch quarantines the artifact.
3. **Metadata is untrusted input.** Manifests are strictly validated; unknown
   keys are rejected; `http://` artifact URLs are refused.
4. **Nothing is executed by installing it.** Installation and permission are
   separate: a tool must also be named in the policy before it can run.
5. **Installation is transactional.** A failed install leaves the previous
   version untouched and never leaves a half-installed tool marked active.
6. **No implicit compatibility environment.** No WSL, no container, no VM.
7. **Bundles are plans first.** Curated packs group tools by workflow, but they
   print reviewable install commands instead of silently installing a lab.

## Command summary

| Command | Purpose |
|---|---|
| `z search <terms>` | Search registry metadata |
| `z bundle list` | Show curated workflow bundles |
| `z bundle show <name>` | Inspect one bundle and its tools |
| `z bundle plan <name>` | Print install previews for a bundle |
| `z info <tool>` | Metadata, permissions, compatibility |
| `z install <tool>` | Install (verified); `--dry-run` previews, `--offline` uses cache |
| `z list` | Installed tools; `--outdated`, `--json` |
| `z run <tool> -- <args>` | Execute through the broker |
| `z which <tool>` | Where it is installed |
| `z verify <tool>` | Health check |
| `z update [tool]` | Update one or all |
| `z rollback <tool>` | Return to the previous version |
| `z use <tool>@<ver>` | Select the active version |
| `z remove <tool>` | Uninstall (alias: `uninstall`) |
| `z compatibility <tool>` | Per-platform support |
| `z platform` | Native capability report |
| `z cache [list\|clean]` | Artifact cache |

`--json` on any of these produces machine-readable output with no prose mixed in.

## Curated bundles

Zentrion's bundled registry follows the same idea as Kali metapackages: start
from a workflow, then choose the tools. Bundles are local catalog entries; they
do not bypass trust, checksum, platform, policy or approval checks.

| Bundle | Purpose |
|---|---|
| `kali-top10` | Core security tools: Nmap, Metasploit, Wireshark, sqlmap, John, Aircrack-ng, Gobuster, Burp Suite, Hydra and Hashcat |
| `web` | Web proxying, crawling, fuzzing, fingerprinting, injection testing and template scanning |
| `recon` | Network, DNS and external attack-surface discovery |
| `devsecops` | Secret scanning, SAST, SBOM, vulnerability and signing workflows |
| `reverse` | Binary, firmware and malware-analysis starters |
| `forensics` | Memory, disk, packet and file triage |
| `wireless` | Wireless auditing and packet analysis |
| `security-lab` | Every curated registry entry |

Useful examples:

```
z bundle list
z bundle show devsecops
z bundle plan security-lab
z search scanner
```

## Where things live

```
<data dir>/                      (XDG / Library / LOCALAPPDATA)
  tools/<name>/<version>/        installed tool root
                          manifest.json    upstream manifest
                          metadata.json    our install record
                          bin/...          files
  tools/<name>/active            active version pointer (written atomically)
  cache/artifacts/<sha256>       verified artifact cache
  quarantine/<sha256>.quarantined failed verification
  tools.lock                     mutation lock
```

Paths are resolved per platform; nothing is hard-coded to `/home/user` or
`C:\Users\...`. `ZENTRION_DATA_DIR` overrides the data root.

## Further reading

- [manifest.md](manifest.md) — the tool manifest schema
- [installation.md](installation.md) — the install pipeline step by step
- [security.md](security.md) — what is verified and what is not
- [registry.md](registry.md) — the registry format and trust levels
- [development.md](development.md) — authoring tools for Zentrion
