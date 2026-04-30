# Oversight (v0.3.5)

[![GitHub stars](https://img.shields.io/github/stars/Rakosn1cek/oversight?style=flat&color=gold)](https://github.com/Rakosn1cek/oversight)
[![Discord](https://img.shields.io/badge/Discord-Join%20the%20Hub-7289da?style=flat&logo=discord&logoColor=white)](https://discord.gg/GFk45RdS)
![License](https://img.shields.io/github/license/Rakosn1cek/oversight)
![Rust](https://img.shields.io/badge/Language-Rust-orange)

Oversight is a terminal-based security intelligence tool designed to audit shell scripts and commands before they touch your system. It bridges the gap between "blind trust" and "manual auditing" by providing a high-speed, interactive analysis of both local files and remote scripts via Raw URLs.

## The Mission
Most system compromises happen because of a "leap of faith". Running a script from a GitHub or a forum post. Oversight gives you "X-ray vision" into these scripts, flagging malicious patterns and explaining the risks in plain English so you can make an informed decision.

## Features
* **Dynamic Rules Engine**: Patterns are externalised in `rules.json`, allowing for real-time security updates across different scripting languages without recompiling the binary.
* **Context-Aware Auditing**: Provides a multi-line code window (11 lines) around every finding, ensuring variable definitions and function headers are visible during the review.
* **Multi-Language Support**: Unified security analysis for **Shell (.sh, .zsh)** and **Python (.py)** scripts, targeting cross-language risks like subprocess execution and dynamic evaluation.
* **Interactive TUI Dashboard**: A professional security console featuring syntax-highlighted findings (Yellow/Bold) linked directly to the code context.
* **Remote Fetching Engine**: Audit scripts directly from GitHub, Gist, or any raw URL without saving them to your disk via memory-only analysis.
* **Educational Auditing**: Every security flag includes a detailed explanation and external references to help users learn to spot and understand malicious patterns.
* **Refined Pattern Matching**: Intelligent regex engine using word boundaries to minimise false positives while identifying obfuscated threats.
* **Universal Shell Integration**: Native hooks for **Zsh**, **Bash**, and **Fish** to intercept risky commands in real-time before they execute.

## Dependencies
Oversight is built in Rust for speed and safety. The following are required for compilation and runtime:
- **Rust Toolchain:** (cargo, rustc) for building the engine.
- **OpenSSL:** Required by `reqwest` for secure remote fetching.
- **FZF:** Required by the shell wrappers for interactive selection menus.
- **Crates:** `ratatui` (TUI), `tokio` (Async runtime), `reqwest` (HTTP), `clap` (CLI parser), and `regex`.
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
- **Live Protection**: Simply type a command like `curl ... | bash` and Oversight will automatically intercept it and offer an audit.

---

> *Note: Oversight is an advisory tool. While it uses robust regex pattern matching, no security tool is 100% bulletproof. Always use the "Final Verdict" as a guide and review the highlighted code manually if you are unsure about a source.*

> *Note2: Oversight is still in active development; therefore, no guarantee is provided regarding its functionality or system impact at this stage.*

## Support & Contributions
If you would like to support or contribute to the project you are more than welcome.

If you would like to discuss or ask questions about Oversight please join my Discord server [Mend | Oversight | XC Hub](https://discord.gg/GFk45RdS)

## License
MIT © 2026 Rakosn1cek. Attribution is required for any redistribution or derivative works.
 
