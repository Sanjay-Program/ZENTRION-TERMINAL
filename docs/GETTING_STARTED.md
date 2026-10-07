# Getting Started with ZENTRION TERMINAL

Welcome to **ZENTRION TERMINAL**, the flagship product of [Zentrion Technologies](https://zentriontechnologies.com). 
This guide is designed for **everyone**—whether you are a beginner taking your first steps in a terminal, or an expert Cybersecurity Engineer deploying autonomous AI agents.

## 1. What makes ZENTRION different?
Traditional terminals (like Windows Command Prompt, macOS Terminal, or basic Linux shells) just send commands to your computer blindly. 

ZENTRION is a **Next-Generation Terminal Environment**. It acts as a shield and an assistant:
- **AI Copilot Built-In:** If you don't know a command, the built-in AI will help you figure it out.
- **Secure By Default:** If a malicious script or an uncontrolled AI tries to delete your files or make dangerous network calls, ZENTRION intercepts it using our advanced Policy Engine.
- **Universal Tooling:** You don't need to learn how to install complex developer or hacking tools. ZENTRION manages all of it for you.

## 2. Installation
If you haven't installed ZENTRION yet, please see our [Universal Installers Guide](../releases/README.md). We support Linux, macOS, and Windows.

## 3. Your First 5 Minutes

Once installed, open your normal terminal and type:
```sh
z-cli ui
```
This drops you into the **ZENTRION Command Center** (the TUI).

### The Essential Shortcuts (Desktop Style)
We threw away the complex, hard-to-remember Linux shortcuts. Use ZENTRION just like a normal desktop app:

*   **`Alt + S` (System Monitor):** Instantly see how much CPU and RAM your computer is using, and see what applications are slowing it down.
*   **`Alt + E` (Mini IDE):** Never leave the terminal! Press this to open a text editor with AI Auto-Complete.
*   **`Ctrl + P` (Command Palette):** Don't know what to type? Press `Ctrl+P` and type what you want to do (e.g., "scan my network", "secure my code").
*   **`Alt + C` (AI Copilot):** Opens a chat window on the right side of your screen. Ask it anything about coding or security.
*   **`0` (LAN Chat):** Switch to the Secure P2P LAN Chat tab. If any of your friends or coworkers are on the same Wi-Fi, you can chat with them instantly and securely without the internet.
*   **`9` (Deep Research):** Tell ZENTRION to research a complex topic, and watch its AI agents scrape the web for you.
*   **`Ctrl + Q` (Quit):** Exit safely.

## 4. Basic Commands

While the `z-cli ui` is the easiest way to use ZENTRION, you can also use it via the standard command line:

```sh
# Let ZENTRION check if your system is secure and ready
z doctor

# Download any tool in the world (VLC, Chrome, Nmap, Python)
z install <tool-name>

# Run a security scan on your current folder
z scan .

# Start an AI Agent to fix your code
z agent run "find the bug in this project and patch it"
```

## 5. Where to go next?
*   **Non-technical users:** Just press `Alt+C` in the UI and let the Copilot guide you!
*   **Developers & DevOps:** Read the [1000 Commands Reference](1000-COMMANDS-REFERENCE.md).
*   **Cybersecurity Professionals:** Read our [Security Model](SECURITY_MODEL.md) and learn about the local-first execution sandbox.

---
*Powered by [Zentrion Technologies](https://zentriontechnologies.com).*
