/*
 * Oversight v0.3.0 - Security Intelligence & Audit Engine
 * Author:  Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Version: 0.3.0
 * Description: 
 * A static analysis tool that audits local scripts and remote Raw URLs.
 * Designed to educate users on malicious patterns before execution.
 * Use UP/DOWN to navigate, 'q' or ESC to exit.
 */

use clap::Parser;
use regex::Regex;
use std::{fs, io};
use std::path::PathBuf;

// TUI Imports
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span}, // Added these two
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[derive(Parser, Debug)]
#[command(author, version, about = "Oversight: Educational Script Auditor")]
struct Args {
    target: String,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
enum Severity {
    Critical,
    High,
    Medium,
    #[allow(dead_code)]
    Low,
}

struct RedFlag {
    pattern: &'static str,
    name: &'static str,
    explanation: &'static str,
    severity: Severity,
}

#[derive(Debug, Clone)]
struct AuditFinding {
    line_no: usize,
    code_snippet: String,
    name: String,
    explanation: String,
    severity: Severity,
}

// --- APP STATE ---
struct App {
    findings: Vec<AuditFinding>,
    state: ListState,
    source_name: String,
}

impl App {
    fn new(findings: Vec<AuditFinding>, source_name: String) -> App {
        let mut state = ListState::default();
        if !findings.is_empty() {
            state.select(Some(0));
        }
        App { findings, state, source_name }
    }
    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => if i >= self.findings.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.state.select(Some(i));
    }
    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => if i == 0 { self.findings.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.state.select(Some(i));
    }
}

// --- ENGINE LOGIC ---

fn get_security_database() -> Vec<RedFlag> {
    vec![
        RedFlag {
            pattern: r"rm\s+-[rf]{1,2}\s+.*[/$\*]",
            name: "Recursive Deletion",
            explanation: "Attempts to delete folders permanently. If targeted at system or home directories, it results in total data loss.",
            severity: Severity::Critical,
        },
        RedFlag {
            pattern: r"/.ssh/|/etc/shadow|/etc/passwd|/etc/sudoers",
            name: "Sensitive File Access",
            explanation: "Accessing files that store private security keys or passwords. Common step in identity theft.",
            severity: Severity::Critical,
        },
        RedFlag {
            pattern: r"\b(curl|wget|nc|socat)\b|/dev/tcp|/dev/udp",
            name: "Network Activity",
            explanation: "Reaching out to the internet. Could be used to exfiltrate data or download further malware.",
            severity: Severity::High,
        },
        RedFlag {
            pattern: r"\|\s*(bash|sh|zsh|source|\.)",
            name: "Pipe to Shell",
            explanation: "Downloads or generates code and runs it immediately. You cannot verify the code before execution.",
            severity: Severity::High,
        },
        RedFlag {
            pattern: r"base64\s+-(d|-decode)|eval\s+|exec\s+",
            name: "Obfuscated Logic",
            explanation: "Hiding true intentions using encoding. Common tactic to bypass simple security scanners.",
            severity: Severity::Medium,
        },
    ]
}

fn perform_analysis(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let database = get_security_database();
    let compiled: Vec<(&RedFlag, Regex)> = database.iter().map(|f| (f, Regex::new(f.pattern).unwrap())).collect();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        for (flag, re) in &compiled {
            if re.is_match(trimmed) {
                findings.push(AuditFinding {
                    line_no: idx + 1,
                    code_snippet: trimmed.to_string(),
                    name: flag.name.to_string(),
                    explanation: flag.explanation.to_string(),
                    severity: flag.severity.clone(),
                });
            }
        }
    }
    findings
}

// --- TUI RENDERER ---

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
        ])
        .split(f.size());

    let header = Paragraph::new(format!(" Target: {}", app.source_name))
        .block(Block::default().borders(Borders::ALL).title(" Oversight Audit "))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(header, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(chunks[1]);

    // --- CASE 1: NO FINDINGS (SAFE MESSAGE) ---
    if app.findings.is_empty() {
        let safe_text = vec![
            Line::from(Span::styled("\n[✓] NO IMMEDIATE THREAT FOUND", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled("Safe to install/use.", Style::default().fg(Color::Green))),
            Line::from(Span::styled("\nNote: No tool is 100% bulletproof.", Style::default().fg(Color::Gray))),
            Line::from(Span::styled("Check code manually if unsure.", Style::default().fg(Color::Gray))),
        ];

        let safe_msg = Paragraph::new(safe_text)
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" Results "));
        f.render_widget(safe_msg, chunks[1]);
        
        let hint = Paragraph::new(" Press 'q' or ESC to exit.")
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(hint, chunks[2]);
        return;
    }

    // --- CASE 2: FINDINGS DETECTED ---
    let items: Vec<ListItem> = app.findings.iter().map(|f| {
        let color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        };
        ListItem::new(format!("[{:?}] {}", f.severity, f.name)).style(Style::default().fg(color))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Findings "))
        .highlight_style(Style::default().bg(Color::Rgb(50, 50, 50)).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.state);

    if let Some(sel) = app.state.selected() {
        let finding = &app.findings[sel];
        
        // Render Code Context
        let code_para = Paragraph::new(format!("\n Line {}:\n\n {}", finding.line_no, finding.code_snippet))
            .block(Block::default().borders(Borders::ALL).title(" Code Context "));
        f.render_widget(code_para, main_chunks[1]);

        // Determine Verdict Message
        let has_critical_or_high = app.findings.iter().any(|f| 
            matches!(f.severity, Severity::Critical) || matches!(f.severity, Severity::High)
        );

        let (verdict_msg, verdict_color) = if has_critical_or_high {
            ("Found critical or high-risk patterns. Review the code manually before running!", Color::Red)
        } else {
            ("Found minor issues. If you trust the source, you can install it.", Color::Yellow)
        };

        // Render Analysis & Verdict Footer
        let analysis_text = vec![
            Line::from(finding.explanation.as_str()),
            Line::from(""),
            Line::from(Span::styled(verdict_msg, Style::default().fg(verdict_color).add_modifier(Modifier::BOLD))),
        ];

        let expl_para = Paragraph::new(analysis_text)
            .block(Block::default().borders(Borders::ALL).title(" Analysis & Verdict "))
            .wrap(Wrap { trim: true });
        f.render_widget(expl_para, chunks[2]);
    }
}
#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();
    let content: String;
    let source_label: String;

    if args.target.starts_with("http") {
        let client = reqwest::Client::builder().user_agent("Oversight/0.3.0").build().unwrap();
        let resp = client.get(&args.target).send().await.expect("Failed to fetch");
        content = resp.text().await.unwrap_or_default();
        source_label = args.target.clone();
    } else {
        content = fs::read_to_string(&args.target).expect("Failed to read file");
        source_label = args.target.clone();
    }

    let findings = perform_analysis(&content);

    // Enter TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(findings, source_label);

    loop {
        terminal.draw(|f| ui(f, &mut app))?;
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down => app.next(),
                KeyCode::Up => app.previous(),
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
