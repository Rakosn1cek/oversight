/*
 * Oversight - Security Intelligence & Audit Engine
 * Author:  Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Description: 
 * A static analysis tool that audits local scripts and remote Raw URLs.
 * Uses a dynamic rules engine to educate users on malicious patterns.
 * Use UP/DOWN to navigate, 'q' or ESC to exit.
 */

use clap::Parser;
use std::{fs, io};
use std::path::PathBuf;
use std::collections::HashSet;
mod rules;
use rules::{load_rules, Rule};
use regex::Regex;
mod intel;
const VERSION: &str = env!("CARGO_PKG_VERSION");

// TUI Imports
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about = "Oversight: Educational Script Auditor")]
struct Args {
    target: String,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

pub struct AuditFinding {
    pub line_no: usize,
    pub code_snippet: String,
    pub name: String,
    pub category: String,
    pub explanation: String,
    pub severity: String,
    pub reference: String,
    pub fix: Option<String>,
}

// --- APP STATE ---
struct App {
    findings: Vec<AuditFinding>,
    state: ListState,
    source_name: String,
    risk_score: usize,
    suppressed_indices: HashSet<usize>,
}

impl App {
    fn new(findings: Vec<AuditFinding>, source_name: String) -> App {
        let mut state = ListState::default();
        if !findings.is_empty() {
            state.select(Some(0));
        }
        
        // Initialise empty set to pass into the scoring logic
        let suppressed_indices = HashSet::new();
        let risk_score = calculate_risk_score(&findings, &suppressed_indices);
        
        App { 
            findings, 
            state, 
            source_name, 
            risk_score,
            suppressed_indices, 
        }
    }

    fn next(&mut self) {
        // Select the next finding in the list or wrap to the start
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.findings.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        // Select the previous finding in the list or wrap to the end
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.findings.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

fn calculate_risk_score(findings: &[AuditFinding], suppressed: &HashSet<usize>) -> usize {
    let mut total = 0;
    for (i, f) in findings.iter().enumerate() {
        // Only count findings that are not suppressed
        if !suppressed.contains(&i) {
            total += match f.severity.as_str() {
                "Critical" => 35,
                "High" => 20,
                "Medium" => 10,
                "Low" => 5,
                _ => 0,
            };
        }
    }
    std::cmp::min(total, 100)
}

async fn perform_analysis(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let rules = load_rules();
    let lines: Vec<&str> = content.lines().collect();

    let compiled_rules: Vec<(&Rule, Regex)> = rules
        .iter()
        .filter_map(|r| {
            match Regex::new(&r.pattern) {
                Ok(re) => Some((r, re)),
                Err(_) => {
                    eprintln!("Warning: Skipping invalid regex pattern in rule: {}", r.name);
                    None
                }
            }
        })
        .collect();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        for (rule, re) in &compiled_rules {
            if let Some(caps) = re.captures(trimmed) {
                let start = if idx >= 5 { idx - 5 } else { 0 };
                let end = std::cmp::min(idx + 6, lines.len());
                
                let mut context_block = String::new();
                for i in start..end {
                    let indicator = if i == idx { "> " } else { "  " };
                    context_block.push_str(&format!("{}{}\n", indicator, lines[i]));
                }

                findings.push(AuditFinding {
                    line_no: idx + 1,
                    code_snippet: context_block.clone(),
                    name: rule.name.to_string(),
                    category: rule.category.to_string(),
                    explanation: rule.explanation.to_string(),
                    severity: rule.severity.to_string(),
                    reference: rule.reference.to_string(),
                    fix: rule.fix.clone(),
                });

                // Trigger OSV check for install patterns
                if rule.name.contains("install") {
                    let name = caps.get(1).map_or("", |m| m.as_str());
                    let version = caps.get(2).map_or("", |m| m.as_str());
                    let ecosystem = if rule.name.contains("pip") { "PyPI" } else { "crates.io" };

                    if !name.is_empty() {
                        if let Ok(response) = intel::check_package(name, version, ecosystem).await {
                            if let Some(vulns) = response.vulns {
                                for v in vulns {
                                    findings.push(AuditFinding {
                                        line_no: idx + 1,
                                        code_snippet: context_block.clone(),
                                        name: format!("Vulnerability: {}", v.id),
                                        category: "Security".to_string(),
                                        explanation: v.details,
                                        severity: "Critical".to_string(),
                                        reference: format!("https://osv.dev/vulnerability/{}", v.id),
                                        fix: None,
                                    });
                                }
                            }
                        }
                    }
                }
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

    let (score_color, label) = if app.risk_score <= 20 {
            (Color::Green, "CLEAN")
        } else if app.risk_score <= 60 {
            (Color::Yellow, "CAUTION")
        } else {
            (Color::Red, "DANGEROUS")
        };
    
    let header = Paragraph::new(format!(" Target: {} | Score: {} [{}]", app.source_name, app.risk_score, label))
        .block(Block::default().borders(Borders::ALL).title(" Oversight Audit "))
        .style(Style::default().fg(score_color));
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
        let color = match f.severity.as_str() {
            "Critical" => Color::Red,
            "High" => Color::LightRed,
            "Medium" => Color::Yellow,
            "Low" => Color::Blue,
            _ => Color::Gray,
        };
        ListItem::new(format!("[{}] {}", f.severity, f.name)).style(Style::default().fg(color))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Findings "))
        .highlight_style(Style::default().bg(Color::Rgb(50, 50, 50)).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.state);

    if let Some(sel) = app.state.selected() {
        let finding = &app.findings[sel];
        let is_suppressed = app.suppressed_indices.contains(&sel);
        
        // Process context lines and apply sanitisation if the finding is suppressed
        let lines: Vec<Line> = finding.code_snippet.lines().map(|l| {
            if l.starts_with('>') {
                if is_suppressed {
                    // Visual mitigation by commenting out the flagged line
                    let sanitised = format!("# [SUPPRESSED] {}", &l[1..].trim());
                    Line::from(Span::styled(sanitised, Style::default().fg(Color::Cyan).add_modifier(Modifier::ITALIC)))
                } else {
                    Line::from(Span::styled(l, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                }
            } else {
                Line::from(Span::styled(l, Style::default().fg(Color::Gray)))
            }
        }).collect();
    
        let code_para = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Code Context "))
            .wrap(Wrap { trim: false });
        
        f.render_widget(code_para, main_chunks[1]);

        // Verdict logic now ignores suppressed findings for the final safety assessment
        let has_critical_or_high = app.findings.iter().enumerate().any(|(i, f)| 
            !app.suppressed_indices.contains(&i) && (f.severity == "Critical" || f.severity == "High")
        );

        let (verdict_msg, verdict_color) = if has_critical_or_high {
            ("Found critical or high-risk patterns. Review the code manually before running!", Color::Red)
        } else {
            ("Found minor issues or findings have been suppressed.", Color::Yellow)
        };

        // Inject the fix suggestion into the Analysis footer
        let fix_text = finding.fix.as_deref().unwrap_or("Manual audit recommended.");
        let analysis_text = vec![
            Line::from(finding.explanation.as_str()),
            Line::from(Span::styled(format!("Tip: {}", fix_text), Style::default().fg(Color::Cyan))),
            Line::from(format!("Ref: {}", finding.reference)),
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
        let client = reqwest::Client::builder().user_agent("Oversight/0.4.5").build().unwrap();
        let resp = client.get(&args.target).send().await.expect("Failed to fetch");
        content = resp.text().await.unwrap_or_default();
        source_label = args.target.clone();
    } else {
        content = fs::read_to_string(&args.target).expect("Failed to read file");
        source_label = args.target.clone();
    }

    let findings = perform_analysis(&content).await;

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
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    if let Some(sel) = app.state.selected() {
                        // Toggle current index in the suppressed set
                        if !app.suppressed_indices.insert(sel) {
                            app.suppressed_indices.remove(&sel);
                        }
                        
                        // Refresh threat score using the helper function
                        app.risk_score = calculate_risk_score(&app.findings, &app.suppressed_indices);
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
