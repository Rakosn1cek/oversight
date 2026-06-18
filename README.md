# Oversight (v0.5.5)

[![GitHub stars](https://img.shields.io/github/stars/Rakosn1cek/oversight?style=flat&color=gold)](https://github.com/Rakosn1cek/oversight)
[![Discord](https://img.shields.io/badge/Discord-Join%20the%20Hub-7289da?style=flat&logo=discord&logoColor=white)](https://discord.gg/GFk45RdS)
![License](https://img.shields.io/github/license/Rakosn1cek/oversight)
![Rust](https://img.shields.io/badge/Language-Rust-orange)

Oversight is a terminal-based security intelligence tool designed to audit shell scripts and commands before they touch your system. It bridges the gap between "blind trust" and "manual auditing" by providing a high-speed, interactive analysis of both local files and remote scripts via Raw URLs.

## Oversight

<video src="assets/oversight.mp4" width="80%" controls></video>

## Screenshot 1

![Oversight TUI Interface in Action](assets/oversight1.png)

## Screenshot 2

![Oversight TUI Interface in Action](assets/oversight2.png)

## The Mission
Most system compromises happen because of a "leap of faith". Running a script from a GitHub or a forum post. Oversight gives you "X-ray vision" into these scripts, flagging malicious patterns and explaining the risks in plain English so you can make an informed decision.

## Features
* **Heuristic Entropy Engine**: Implementation of Shannon entropy calculations to identify obfuscated payloads, packed data, and encrypted strings that traditional regex scanners miss.
* **Malicious Lifecycle Tracking**: Advanced behavioural analysis that links related events across a script, such as the Fetch -> Permissions Change -> Execution chain typical of trojan installers.
* **Security Heat Map**: A vertical TUI sidebar providing a real-time visual overview of threat distribution throughout the file, allowing for rapid identification of "hot zones" in large scripts.
* **Behavioural Trace Summaries**: Context-aware reports for heuristic findings that list specific line numbers where suspicious ingress, execution, or persistence patterns were detected.
* **Anti-Forensic & Persistence Detection**: Monitoring for stealth behaviours including self-deletion (rm $0), history clearing, RAM-only execution (/dev/shm), and reboot hooks (crontab, systemd).
* **Weighted Risk Scoring**: Implements a 0 to 100 safety index that categorises scripts as Clean, Caution, or Dangerous based on weighted security findings.
* **Interactive Triage & Mitigation**: Allows users to "suppress" specific findings via the TUI, which visually sanitises the code view by commenting out risky lines and recalculates the risk score in real time.
* **Actionable Remediation**: Every security flag provides a specific "Fix Suggestion" to help users understand how to safely refactor or handle detected patterns.
* **Dynamic Rules Engine**: Patterns are externalised in `rules.json`, allowing for real-time security updates across different scripting languages without recompiling the binary.
* **Context-Aware Auditing**: Provides a multi-line code window (11 lines) around every finding, ensuring variable definitions and function headers are visible during the review.
* **Multi-Language Support**: Unified security analysis for Shell (.sh, .zsh), Python (.py), and Go (.go) source files, with a language-agnostic core capable of detecting system-level threats across most text-based projects.
* **Interactive TUI Dashboard**: A professional security console featuring syntax-highlighted findings linked directly to the code context for rapid triage.
* **Remote Fetching Engine**: Audit scripts directly from GitHub, Gist, or any raw URL without saving them to your disk via memory-only analysis.
* **Educational Auditing**: Every security flag includes a detailed explanation and external references to help users learn to spot and understand malicious patterns.
* **Refined Pattern Matching**: Intelligent regex engine using word boundaries to minimise false positives while identifying obfuscated threats.
* **Universal Shell Integration**: Native hooks for **Zsh**, **Bash**, and **Fish** to intercept potentially malicious commands in real-time before they execute.
* **Vulnerability Intelligence**: Integrated real-time scanning for known CVEs using the OSV.dev API, triggering automatically when supported package installation commands are detected.

## Dependencies
Oversight is built in Rust for speed and safety. The following are required for compilation and runtime:
- **Rust Toolchain:** (cargo, rustc) for building the engine.
- **OpenSSL:** Required by `reqwest` for secure remote fetching.
- **Crates:** `ratatui` (TUI), `tokio` (Async runtime), `reqwest` (HTTP), `clap` (CLI parser), `regex`, `serde`, and `serde_json`.
- **Serde:** Required for JSON ruleset parsing.

## Installation & Setup

1. **Clone the repo:**
`git clone https://github.com/Rakosn1cek/oversight.git` 
`cd oversight`

2. **Run the Automated Installer:**
The installer handles compilation, moves the binary to ~/.local/bin, and injects the necessary hooks into your shell configuration (.zshrc, .bashrc, or config.fish).

```zsh
chmod +x install.sh
./install.sh
```
3. **Reload your shell:**

`source ~/.zshr` or your respective shell config

## Files & Locations
- **Binary**: ~/.local/bin/oversight
- **Rules Database**: ~/.local/share/oversight/rules.json
- **Shell Hooks**: ~/.local/share/oversight/oversight.[zsh|bash|fish]

**Usage**
- **Audit a local script**: `oversight ./install.sh`
- **Audit a remote URL**: `oversight https://raw.githubusercontent.com/user/repo/main/setup.sh`
- **Live Protection**: Commands like `curl ... | bash` are intercepted automatically to offer an audit.

**Keybinds**:
- Use **Up/Down Arrow Keys** to navigate through the left panel findings.
- When highlighting a global `[GLOB]` behavior finding, navigation controls dynamically switch to vertically scroll the **Highlights** view panel.
- Press **Left Arrow Key** to jump focus back to the primary findings list view.
- Press **[S]** to toggle line suppression, comment out flagged lines, and re-balance risk metrics in real time.

---

> *Note: Oversight is an advisory tool. While it uses robust regex pattern matching, no security tool is 100% bulletproof. Always use the "Final Verdict" as a guide and review the highlighted code manually if you are unsure about a source.*

> *Note2: Oversight is still in active development; therefore, no guarantee is provided regarding its functionality or system impact at this stage.*

## Support & Contributions
If you would like to support or contribute to the project you are more than welcome.

If you would like to discuss or ask questions about Oversight please join my Discord server [Rakosn1cek](https://discord.gg/GFk45RdS)

## License
MIT © 2026 Rakosn1cek. Attribution is required for any redistribution or derivative works.
 
