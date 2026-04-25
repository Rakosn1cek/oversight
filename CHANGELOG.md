# Changelog

All notable changes to the Oversight project will be documented in this file.

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
