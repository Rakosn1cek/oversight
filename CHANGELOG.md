# Changelog

All notable changes to the Oversight project will be documented in this file.

## [0.3.5] - 2026-04-28

### Added
- **Multi-Language Support:** Expanded the auditing engine to support Python (.py) alongside Shell scripts, targeting cross-language risks like subprocess spawning and socket creation.
- **Context-Aware Auditing:** Implemented an 11-line code window (5 before, 5 after) for every finding to reveal variable definitions and logic blocks.
- **Syntax Highlighting:** Added Yellow/Bold highlighting for the specific flagged line within the context block for better scannability.
- **Dynamic Rules Engine:** Decoupled security patterns from the source code. Patterns are now stored in an external `rules.json` file for easier updates without recompilation.
- **Enhanced Analysis Metadata:** Audit findings now include categories and reference URLs to provide users with deeper context on specific security risks.
- **Reference Support in TUI:** The analysis view now displays external documentation links for every flagged security pattern.
- **JSON Serialization:** Integrated `serde` and `serde_json` for robust management of the external security database.

### Changed
- **TUI Rendering Logic:** Refactored the Code Context view to handle multi-line Paragraph widgets and styled Line/Span elements.
- **Architectural Shift:** Moved security intelligence logic from hardcoded Rust enums to a flexible JSON-driven data structure.
- **Optimised Deployment:** Updated the installer to handle multi-path deployment, ensuring `rules.json` is correctly placed in `~/.local/share/oversight/`.
- **Release Profile Default:** Standardised the installer to build the binary using the `--release` profile for maximum scanning performance.
- **Improved Shell Wrappers:** Refined **Bash**, **Zsh**, and **Fish** hooks to point to consolidated share paths and match the project's updated naming convention.

### Fixed
- **TUI Indentation:** Disabled automatic trimming in the Paragraph widget to preserve code structure and indentation for Python/Shell scripts.
- **Rule Path Resolution:** Resolved an issue where the binary would fail to find security patterns if executed from outside the installation directory.
- **TUI Type Mismatch:** Fixed a bug where string-based severity levels from the rules engine weren't correctly mapping to UI colours.
- **Installer Logic Gap:** Patched the setup script to ensure the local rules database is deployed alongside the binary and shell hooks.

---

## [0.3.0] - 2026-04-25

### Added
- **Interactive TUI:** Introduced a terminal-based dashboard using `ratatui` for side-by-side code and security analysis.
- **Remote Auditing:** Support for fetching and scanning scripts directly from Raw URLs (GitHub/Gists) without writing to disk (memory-only analysis).
- **Universal Shell Support:** Added native hooks for **Bash** and **Fish**, ensuring parity with the existing Zsh integration.
- **Mend-Style Automated Installer:** A new `install.sh` that handles dependency checks, compilation, and automatic shell hook injection.
- **Final Verdict Logic:** Added a summary message providing a clear recommendation (Safe/Caution/Dangerous) based on audit results.
- **Word Boundary Detection:** Implemented `\b` regex boundaries to significantly reduce false positives in benign scripts (e.g., `encode` vs `nc`).

### Changed
- **Engine Pivot:** Transitioned from a Landlock-based "Enforcement" model to a Static Analysis "Intelligence" model for better portability.
- **Global Deployment:** The installer now deploys Oversight to `~/.local/bin`, moving it out of the development directory for system-wide use.
- **Wrapper Logic:** Unified the shell logic to focus on a thin "glue" layer, moving the intelligence into the core Rust binary.

### Fixed
- **Pattern Noise:** Fixed an issue where variable names containing command fragments (like 'nc') triggered high-severity network warnings.
- **Resource Cleanup:** All remote audits are now performed in volatile memory, ensuring no temporary files or sensitive data are left behind.

---

# [0.1.1] - 2026-04-20

### Added
- **Dynamic Filtering:** Implemented a real-time output filter to intercept "Permission denied" and "Operation not permitted" errors.
- **Heuristic Detection:** Added support for catching coreutils failsafes (e.g. `rm` preserve-root warnings) in the audit log.
- **Log Management:** Established a persistent log directory at `~/oversight/logs/` with timestamped sessions.
- **Janitor Service:** Added a start-up check to prompt the user to clear previous session logs, keeping the environment tidy.
- **Wait Synchronisation:** Integrated the `wait` command to ensure background processes (like sneaky `curl` calls) are captured before the audit closes.

### Changed
- **Security Policy:** Tightened Landlock restrictions. The sandbox now defaults to Read-Only (`-r`) for the current directory and Write-access (`-w`) only for the specific session log folder.
- **Documentation:** Updated all project materials to UK English.
- **UI:** Refined the `fzf` widget to include a footer displaying the current session path and cleanup instructions.

---

## [0.1.0] - 2026-04-19

### Added
- **Initial Release:** Core Rust engine with Landlock integration.
- **Zsh Wrapper:** Initial `sbox` function for scanning and execution.
- **Regex Scanner:** Basic pattern matching for common malicious shell commands.
- **Basic Sandbox:** Preliminary filesystem isolation using the Landlock LSM.
