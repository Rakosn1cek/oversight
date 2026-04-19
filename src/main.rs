/*
 * Oversight -  Static & Dynamic Security Sandbox
 * * Author:    Lukas Grumlik - Rakosn1cek
 * Created:     2026-04-19
 * Version:     0.1.0
 * License:     MIT
 * Repository:  ~/arch-projects/oversight
 * * Description: 
 * A Rust-based scanner that uses Landlock to enforce kernel-level 
 * filesystem restrictions on potentially malicious scripts.
 */
 
use clap::Parser;
use landlock::{
    Access, AccessFs, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use std::fs::File;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::path::PathBuf;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about = "Oversight: Minimalist Landlock Sandbox")]
struct Args {
    #[arg(short, long)]
    read: Vec<PathBuf>,

    #[arg(long)]
    no_scan: bool,

    #[arg(short, long)]
    write: Vec<PathBuf>,

    #[arg(raw = true)]
    command: Vec<String>,
}

#[derive(Debug)]
enum Severity {
    Critical,
    Warning,
}

struct RedFlag {
    pattern: &'static str,
    description: &'static str,
    severity: Severity,
}

fn scan_script(path: &PathBuf) {
    // Check if it's a file first
    if !path.is_file() { return; }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            // If it can't read it as a string, it's likely a binary
            // Just skip the scan and let Landlock handle the rest
            return;
        }
    };

    let flags = vec![
        // This catches rm -rf followed by /, a variable $, or even a wildcard *
        RedFlag { 
            pattern: r"rm\s+-[rf]{1,2}\s+.*[/$\*]", 
            description: "Dangerous Recursive Deletion", 
            severity: Severity::Critical 
        },
        RedFlag { 
            pattern: r"/.ssh/|/etc/shadow|/etc/passwd", 
            description: "Sensitive Auth File Access", 
            severity: Severity::Critical 
        },
        RedFlag { 
            pattern: r"curl|wget|nc -l|/dev/tcp", 
            description: "Network Activity / Exfiltration", 
            severity: Severity::Warning 
        },
        // This catches the base64 pipe you used in your test
        RedFlag { 
            pattern: r"base64\s+-[d]|eval\s+|echo\s+.*\|\s*(bash|sh|zsh)", 
            description: "Code Injection / Obfuscation", 
            severity: Severity::Warning 
        },
    ];

    let compiled_flags: Vec<(&RedFlag, Regex)> = flags
        .iter()
        .map(|f| (f, Regex::new(f.pattern).unwrap()))
        .collect();

    let mut findings = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        for (flag, re) in &compiled_flags {
            if re.is_match(line) {
                findings.push(format!(
                    "{}: [{:?}] {} -> {}", 
                    line_no + 1, 
                    flag.severity, 
                    flag.description, 
                    line.trim()
                ));
            }
        }
    }

    if !findings.is_empty() {
        println!("\n\x1b[1;31m[!] SECURITY ALERT: Malicious Patterns Found\x1b[0m");
        for finding in findings {
            println!("{}", finding);
        }
        std::process::exit(10);
    } 
    else {
        println!("\x1b[1;32m[SAFE]\x1b[0m No obvious red flags detected in script text.");
        let _ = io::stdout().flush();
    }
}

fn main() {
    let args = Args::parse();

    if args.command.is_empty() {
        eprintln!("Oversight: No command provided.");
        return;
    }

    let program_name = &args.command[0];
    let program_path = resolve_path(program_name).expect("Oversight: Executable not found");

    // Only scan if no_scan is false. 
    if !args.no_scan {
        scan_script(&program_path);
    }

    let abi = ABI::V1;
    let ro_access = AccessFs::ReadFile | AccessFs::Execute | AccessFs::ReadDir;
    let rw_access = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(rw_access) 
        .expect("Failed to configure ruleset")
        .create()
        .expect("Failed to create Landlock ruleset");

    let ro_paths = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/sys"];
    for path in ro_paths {
        if let Ok(file) = File::open(path) {
            ruleset = ruleset.add_rule(PathBeneath::new(file, ro_access))
                .expect("Failed to add system rule");
        }
    }

    for path in args.read {
        if let Ok(file) = File::open(&path) {
            ruleset = ruleset.add_rule(PathBeneath::new(file, ro_access))
                .expect("Failed to add custom read rule");
        }
    }

    for path in args.write {
        if let Ok(file) = File::open(&path) {
            ruleset = ruleset.add_rule(PathBeneath::new(file, rw_access))
                .expect("Failed to add custom write rule");
        }
    }

    if let Ok(tmp_file) = File::open("/tmp") {
        ruleset = ruleset.add_rule(PathBeneath::new(tmp_file, rw_access))
            .expect("Failed to add tmp rule");
    }

    ruleset.restrict_self().expect("Failed to enforce sandbox");

    let err = Command::new(program_path)
        .args(&args.command[1..])
        .exec(); 

    eprintln!("Oversight execution error: {}", err);
}

fn resolve_path(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        return Some(PathBuf::from(cmd));
    }
    
    if let Ok(path_var) = std::env::var("PATH") {
        for path in std::env::split_paths(&path_var) {
            let full_path = path.join(cmd);
            if full_path.is_file() {
                return Some(full_path);
            }
        }
    }
    None
}
