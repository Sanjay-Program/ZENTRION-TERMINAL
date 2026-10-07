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
z profile apply frontend-dev
```

### Building & Testing
```sh
# Let Zentrion automatically detect the project type and run tests
z code test
z code build
z code lint
z code format

# Run a specific binary securely
z run cargo -- test --workspace
z run npm -- run build
```

### Git & Source Control
```sh
z git status
z git commit -m "feat: updated core engine"
z git push origin main
# Undo last commit safely
z git reset --soft HEAD~1
```

---

## 2. Cybersecurity & Kali Workflows

ZENTRION comes pre-loaded with a massive registry of curated security tools. It verifies checksums and isolates execution.

### Reconnaissance & Discovery
```sh
# Network mapping
z run nmap -- -sC -sV 192.168.1.0/24
z run masscan -- -p1-65535,U:1-65535 10.0.0.0/8
z run rustscan -- -a 192.168.1.1 -- -A

# Web Discovery
z run gobuster -- dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
z run feroxbuster -- -u https://example.com
z run whatweb -- https://example.com
z run httpx -- -list domains.txt
```

### Vulnerability Assessment
```sh
z run sqlmap -- -u "http://example.com/vuln.php?id=1" --dbs
z run nuclei -- -u https://example.com -t cves/
z run nikto -- -h http://example.com
```

### Exploit & Reverse Engineering
```sh
z run metasploit -- msfconsole
z run searchsploit -- apache 2.4
z run ghidra
z run radare2 -- -d ./malware_binary
z run binwalk -- -e firmware.bin
```

---

## 3. Universal Package Management

ZENTRION can install *anything*. If a tool isn't in our curated security registry, the Intent Router falls back to your native OS package manager (`apt`, `brew`, `winget`).

```sh
# Install normal desktop applications seamlessly
z do install a pdf reader
z install vlc
z install google-chrome

# Install curated security bundles
z bundle plan kali-top10
z bundle install web-assessment
```

---

## 4. AI & Agents Workflows

ZENTRION is built for autonomous agents.

### Local LLMs & Copilot
```sh
# Start a local ollama inference server sandboxed
z run ollama -- serve

# Analyze a security scan result using AI
z scan .
z ai analyze

# Open the AI Copilot pane in the UI
# Press 'c' inside `z ui`
```

### Autonomous Agents
```sh
# Spawn an autonomous security researcher
z agent run "Analyze this repository for hardcoded secrets and patch them"

# List active agents
z agent list

# Emergency kill all agents
z agent kill --all
z lockdown
```

---

## 5. DevSecOps & Cloud

ZENTRION validates IaC and cloud configurations locally before deployment.

### SAST & Secret Scanning
```sh
z run gitleaks -- detect -v
z run trivy -- fs .
z run semgrep -- scan --config auto
```

### Cloud Security
```sh
# Scan AWS infrastructure via Terraform
z run checkov -- -d ./terraform
z run tfsec -- ./terraform
```

---

> **Note:** This is a living document. We are continuously expanding this to exactly 1,000 documented use-cases across 50 domains in upcoming patches.
