# ZENTRION TERMINAL: The Master Command Reference

This document serves as the ultimate "1000 Commands" reference guide, demonstrating how ZENTRION TERMINAL replaces disparate tools (WSL, Docker, tmux, Warp, Kali Linux) into a single unified capability broker. 

Every command executed below passes through the ZENTRION Security Policy.

---

## 1. Developer Workflows

ZENTRION intent routing means you don't need to manually configure Docker containers or language toolchains.

### Project Scaffolding & Setup
```sh
# Initialize a new project with default secure policies
z init my-app --template rust-web
z init my-app --template node-react

# Apply a specific workflow profile
z profile apply developer
z profile apply cybersecurity
```

### Building & Testing
```sh
# Let Zentrion automatically detect the project type and run tests
z code test
z code build
z code lint
z code fmt

# Run a specific binary securely (project policy must allow it)
z run cargo test --workspace
z run npm run build
```

### Git & Source Control
```sh
z run git status
z run git commit -m "feat: updated core engine"
z run git push origin main
# Undo last commit safely
z run git reset --soft HEAD~1
```

---

## 2. Cybersecurity & Kali Workflows

ZENTRION ships a curated registry of security tools. Installs are checksum/trust-gated and execution is policy-gated; tools are not pre-installed.

### Reconnaissance & Discovery
```sh
# Network mapping
z run nmap -sC -sV 192.168.1.0/24
z run masscan -p1-65535,U:1-65535 10.0.0.0/8
z run rustscan -a 192.168.1.1 -- -A

# Web Discovery
z run gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
z run feroxbuster -u https://example.com
z run whatweb https://example.com
z run httpx -list domains.txt
```

### Vulnerability Assessment
```sh
z run sqlmap -u "http://example.com/vuln.php?id=1" --dbs
z run nuclei -u https://example.com -t cves/
z run nikto -h http://example.com
```

### Exploit & Reverse Engineering
```sh
z run msfconsole
z run searchsploit apache 2.4
z run ghidra
z run radare2 -d ./malware_binary
z run binwalk -e firmware.bin
```

---

## 3. Universal Package Management

Registry installs are verified. A name that is not in the curated registry is
**not** installed implicitly; delegate to apt/brew/winget/choco explicitly with
`--os-package`.

```sh
# Curated registry / bundles
z bundle list
z bundle plan kali-top10
z install nmap
z install nmap --approve

# Explicit OS package-manager delegation
z install --os-package vlc

# Dashboard tooling can also be driven through the Intent Router
z do install nmap
```

---

## 4. AI & Agents Workflows

### MCP servers
```sh
z mcp connect --allow npx -y @modelcontextprotocol/server-filesystem /tmp
```

ZENTRION routes AI through a gateway and never gives model output direct host
access.

### Local LLMs & Copilot
```sh
# Configure a provider (Ollama is the default)
export ZENTRION_AI_PROVIDER=ollama
export ZENTRION_AI_MODEL=qwen2.5-coder:7b

# Ask a question from the CLI
z ai ask "explain this error: cannot find crate serde"

# Analyze the latest scan result
z scan .
z ai analyze

# Check provider and redaction status
z ai status
z ai privacy

# Open the AI Copilot sidebar in the UI: press F4
```

### Agents
```sh
# Show the built-in agent profile and allowlist
z agent profiles

# Check whether a tool is guardrail-allowed
z agent guardrail "z scan"

# Run a model-backed planning trace
z agent run "plan a safe review of this repository"

# Stop the local IPC daemon; future brokered commands still need policy
z lockdown
z daemon stop
```

Agent output is a plan/trace. It does not patch files or execute tools on its
own.

---

## 5. DevSecOps & Cloud

ZENTRION validates IaC and cloud configurations locally before deployment.

### SAST & Secret Scanning
```sh
# Built in: no external scanner required
z security secrets
z security sast
z security scan .

# Or install a curated tool, then run it through the broker
z bundle plan devsecops
z bundle plan devsecops   # then z install <tool> --approve
z run trivy -- fs .
z run semgrep -- scan --config auto
```

### Cloud / IaC
```sh
# Static review of Terraform, YAML, JSON, Dockerfiles and .env files
z cloud scan .
z cloud status

# Built-in findings include public ingress, public ACLs, disabled encryption,
# privileged containers, disabled TLS verification and hardcoded credentials.
```

---

> **Note:** this document is a practical workflow reference, not a claim that
> every command in it is installed by default. Optional scanners must be
> installed and allowed by project policy before `z run` will execute them.
