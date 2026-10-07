# ZENTRION TERMINAL Command Reference

ZENTRION TERMINAL provides a unified CLI that eliminates the need for separate security sandboxes (like Docker or WSL) or multiple tools. Every command is routed through an execution broker that verifies identity, policy, capability, and risk before any host effect occurs.

Below is a categorized reference for the most commonly used commands.

## Intent Routing (Natural Language)

ZENTRION TERMINAL interprets your intent and dynamically routes the capability.

*   `z code test` — Routes to the Developer Capability Graph to run tests.
*   `z do secure my project` — Analyzes natural language intent and routes to the appropriate cybersecurity or DevOps tools to secure your codebase.

## Runtime & Health

*   `z doctor` — Offline health check for OS, configuration, project, policy, and data directory.
*   `z status` — Prints runtime, project, policy, and audit status.
*   `z setup` — Initializes durable local storage and shows next steps.
*   `z storage show` — Displays storage paths and retention rules.
*   `z profile list` — Shows available adaptable workflow profiles (e.g., Developer, Security, AI).
*   `z profile apply <name>` — Applies a specific workflow profile.
*   `z platform` — Reports native platform capabilities and sandbox boundaries.

## Configuration & Project Management

*   `z config get <key>` — Retrieve a specific configuration value (e.g., `z config get log_level`).
*   `z config set <key> <value>` — Set a configuration value.
*   `z init <project-name>` — Scaffolds a new project directory with `.zentrion/` (policy, tools, AI config).
*   `z project --check` — Validates the current project's manifests.

## Policy & Execution

*   `z policy validate` — Validates the effective policy and checks for violations.
*   `z policy test <action> <resource>` — Tests if a specific action is allowed (e.g., `z policy test fs.read ./src/**`).
*   `z run <program> [args...]` — Runs a program through the execution broker (no shell invoked). Example: `z run python -- script.py`.
*   `z run <program> --approve` — Confirms a HIGH/CRITICAL risk action explicitly.

## Audit & Security

*   `z audit tail` — Shows the last 20 events in the audit log.
*   `z audit verify` — Verifies the SHA-256 hash chain to detect tampering.
*   `z scan <target>` — Runs a security scan. Examples:
    *   `z scan .` (Scans current directory)
    *   `z scan --profile web https://example.com` (Web application scan)
    *   `z scan --profile network 192.168.1.0/24` (Network scan)
*   `z finding list` — Lists findings from the most recent scan.
*   `z report latest` — Renders the latest scan report.

## AI & Agents

*   `z ai analyze` — Performs AI analysis on the most recent scan findings.
*   `z ai privacy` — Displays AI privacy status (what data goes where).
*   `z ai bom` — Generates an AI Bill of Materials for the project.
*   `z agent list` — Lists active and recent agents.
*   `z agent kill --all` — Terminates all active agents.

## Tool Registry

*   `z search <query>` — Searches the offline tool registry.
*   `z bundle plan <name>` — Prints dry-run install commands for a curated bundle (e.g., `z bundle plan kali-top10`).
*   `z install <tool>` — Installs a tool (checksum verified).
*   `z list` — Lists all installed tools.
*   `z update` — Updates all outdated tools.
*   `z remove <tool>` — Uninstalls a specific tool.

## Emergency Controls

*   `z lockdown` — Emergency stop: immediately kills all agents and revokes all live capabilities.

---
> **Tip:** Use `--help` on any command for detailed options, or `--json` for machine-readable output.
