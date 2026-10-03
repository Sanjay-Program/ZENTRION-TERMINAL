# 15 — TOOL SYSTEM

## 15.1 Categories
Development, AI, Security, Networking, Cloud, DevOps, Data, OSINT, Forensics,
Web Security, Mobile Security, Cloud Security, Privacy, Research.

Tools are **never bundled by default** — the base install ships zero security
tools and zero AI models. All tools are installed on demand from the registry.

## 15.2 Tool manifest (complete schema)

```yaml
apiVersion: zentrion.tool/v1
kind: Tool
metadata:
  name: nmap
  version: "7.95"
  description: Network exploration tool and security scanner
  license: NPSL            # license recorded, may restrict redistribution
  categories: [networking, security, osint]
  homepage: https://nmap.org

platforms: [linux, macos, windows]
architectures: [x64, arm64]

permissions:               # what the tool needs at runtime
  network: true
  filesystem: workspace    # none | workspace | home | system
  process: true
  raw_sockets: true        # triggers HIGH risk + approval

source:
  type: upstream           # upstream | mirror | build-from-source
  url: https://nmap.org/dist/nmap-7.95.tar.bz2
  method: package-manager  # package-manager | binary | source-build | script

integrity:
  checksum: sha256:...     # per artifact
  signature: minigpg:...   # optional publisher signature
  provenance: upstream-release   # upstream-release | reproducible-build | ci-verified

dependencies:
  - {name: libpcap, provided_by: system}

risk:
  level: HIGH              # computed by rules, reviewed by maintainers
  network: outbound
  notes: "raw socket scanning requires elevated privileges on some systems"

lifecycle:
  install_behavior: standalone-binary
  uninstall: remove-binary
  update_channel: stable
```

## 15.3 Source methods

| Method | Description | Security handling |
|---|---|---|
| `package-manager` | apt/dnf/brew/winget installs the distro package | trusted system channel; Zentrion records what was installed |
| `binary` | download prebuilt binary from URL | checksum + signature verify; quarantine on first run |
| `source-build` | build from source in sandbox | build happens in restricted sandbox; checksum of result pinned |
| `script` | vendor install script | script is pinned by checksum, reviewed metadata; **never executed unsigned** |

## 15.4 Runtime integration
Every tool run goes through the broker: `z run nmap -sV target` → risk
evaluation (raw sockets = HIGH) → sandbox profile `tool` → execution → audit.
Tools never gain capabilities beyond their manifest's `permissions` unless the
user grants more explicitly.

## 15.5 Authorized-use framing for security tools
Security tools are provided for **authorized testing and defensive work**.
Zentrion does not ship default workflows, presets, or tutorials targeting
systems the user does not own or have permission to test. Scanning the public
internet or third-party systems remains the user's legal responsibility.
