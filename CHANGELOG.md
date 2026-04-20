# Changelog

All notable changes to the Oversight project will be documented in this file.

## [0.1.1] - 2026-04-20

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

## [0.1.0] - 2026-04-19

### Added
- **Initial Release:** Core Rust engine with Landlock integration.
- **Zsh Wrapper:** Initial `sbox` function for scanning and execution.
- **Regex Scanner:** Basic pattern matching for common malicious shell commands.
- **Basic Sandbox:** Preliminary filesystem isolation using the Landlock LSM.
