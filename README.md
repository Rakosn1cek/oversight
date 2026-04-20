# Oversight (v0.1.1)

A lightweight security auditor and sandbox for shell scripts. Oversight combines a **Static Analysis** engine (Rust) with **Dynamic Enforcement** (Linux Landlock) to keep your system safe from malicious scripts.

## Features
- **Regex Scanner:** Identifies dangerous patterns (e.g. rm -rf, obfuscation, network calls).
- **Kernel Sandbox:** Utilises Landlock to enforce strict filesystem restrictions.
- **Audit Reports:** Intercepts unauthorised actions and presents a clean security summary.

## Installation
1. Compile the Rust binary: `cargo build --release`
2. Source the Zsh wrapper: `source oversight.zsh`

**Note: Oversight is currently in active development; therefore, no guarantee is provided regarding its functionality or system impact at this stage.**
