# Oversight (v0.1.0)

A lightweight security auditor and sandbox for shell scripts. Oversight combines a **Static Analysis** engine (Rust) with **Dynamic Enforcement** (Linux Landlock) to keep your system safe from malicious scripts.

## Features
- **Regex Scanner:** Identifies dangerous patterns (rm -rf, obfuscation, network calls).
- **Kernel Sandbox:** Uses Landlock to restrict filesystem access.
- **Audit Reports:** Intercepts blocked actions and presents a clean security summary.

## Installation
1. Compile the Rust binary: `cargo build --release`
2. Source the Zsh wrapper: `source oversight.zsh`

**Note: Oversight is still in development and therefore I cannot guarantee it will work at all!!**
