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
mod heuristics;
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

// Internal state for Behavioral Grouping
struct IntentTracker {
    fetch_lines: Vec<usize>,
    chmod_lines: Vec<usize>,
    execute_lines: Vec<usize>,
    stealth_lines: Vec<usize>,
    persistence_lines: Vec<usize>,
}

// --- APP STATE ---
struct App {
    findings: Vec<AuditFinding>,
    state: ListState,
    highlight_scroll: u16, // Use scroll offset instead of list state for wrapped paragraphs
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
        
        let suppressed_indices = HashSet::new();
        let risk_score = calculate_risk_score(&findings, &suppressed_indices);
        
        App { 
            findings, 
            state,
            highlight_scroll: 0,
            source_name, 
            risk_score,
            suppressed_indices, 
        }
    }

    fn next(&mut self) {
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
        self.highlight_scroll = 0; // Reset scroll position when jumping findings
    }

    fn previous(&mut self) {
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
        self.highlight_scroll = 0; // Reset scroll position when jumping findings
    }
}

fn calculate_risk_score(findings: &[AuditFinding], suppressed: &HashSet<usize>) -> usize {
    let mut total = 0;
    for (i, f) in findings.iter().enumerate() {
        if !suppressed.contains(&i) {
            total += match f.severity.as_str() {
                "Critical" => 60,
                "High" => 25,
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
    let mut tracker = IntentTracker { 
        fetch_lines: Vec::new(), 
        chmod_lines: Vec::new(), 
        execute_lines: Vec::new(),
        stealth_lines: Vec::new(),
        persistence_lines: Vec::new(),
    };
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

        let clean_line = if let Some(comment_idx) = trimmed.find('#') {
            trimmed[..comment_idx].trim()
        } else {
            trimmed
        };

        let start = if idx >= 5 { idx - 5 } else { 0 };
        let end = std::cmp::min(idx + 6, lines.len());
        let mut context_block = String::new();
        for i in start..end {
            let indicator = if i == idx { "> " } else { "  " };
            context_block.push_str(&format!("{}{}\n", indicator, lines[i]));
        }

        // --- Line-Level Heuristics ---
        if heuristics::is_high_entropy(clean_line) {
            findings.push(AuditFinding {
                line_no: idx + 1,
                code_snippet: context_block.clone(),
                name: "High Entropy Block Detected".to_string(),
                category: "Obfuscation".to_string(),
                explanation: "This line contains a high amount of randomness, often indicating an encoded or encrypted payload.".to_string(),
                severity: "High".to_string(),
                reference: "Heuristic Analysis".to_string(),
                fix: Some("Manually decode this string (e.g., base64 -d) to see the actual commands being hidden.".to_string()),
            });
        }

        if trimmed.contains("curl") || trimmed.contains("wget") { 
            tracker.fetch_lines.push(idx + 1); 
        }
        
        if trimmed.contains("chmod +x") || trimmed.contains("chmod 7") || trimmed.contains("chmod u+x") { 
            tracker.chmod_lines.push(idx + 1); 
        }

        if (trimmed.contains("eval ") && (trimmed.contains("printf") || trimmed.contains("\\x") || trimmed.contains("\\0")))
           || trimmed.contains("base64 -d") 
           || trimmed.contains("openssl enc")
           || (trimmed.starts_with("DATA=") && trimmed.len() > 40) 
        {
            tracker.stealth_lines.push(idx + 1);
        }
        
        if trimmed.starts_with("./") || trimmed.starts_with("/") || trimmed.contains("bash ") || trimmed.contains("| sh") || trimmed.contains("| bash") { 
            if !trimmed.starts_with("/etc") && !trimmed.starts_with("/usr") && !trimmed.starts_with('#') && !trimmed.contains('=') {
                tracker.execute_lines.push(idx + 1); 
            }
        }

        if trimmed.contains("rm $0") || trimmed.contains("> /dev/null") || trimmed.contains("/dev/shm") {
            tracker.stealth_lines.push(idx + 1);
        }
        if trimmed.contains("crontab") || trimmed.contains(".bashrc") || trimmed.contains("systemctl") {
            tracker.persistence_lines.push(idx + 1);
        }

        // --- Pattern Matching ---
        for (rule, re) in &compiled_rules {
            if let Some(caps) = re.captures(line) {
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

    // --- Final Behavioural Assessment ---
    if !tracker.fetch_lines.is_empty() && (!tracker.chmod_lines.is_empty() || !tracker.execute_lines.is_empty()) {
        let mut trace = String::from("Malicious Lifecycle Trace:\n");
        if !tracker.fetch_lines.is_empty() { trace.push_str(&format!(" -> Network Fetch: {:?}\n", tracker.fetch_lines)); }
        if !tracker.chmod_lines.is_empty() { trace.push_str(&format!(" -> Permissions Change: {:?}\n", tracker.chmod_lines)); }
        if !tracker.execute_lines.is_empty() { trace.push_str(&format!(" -> Execution Attempt: {:?}\n", tracker.execute_lines)); }
        if !tracker.stealth_lines.is_empty() { trace.push_str(&format!(" -> Stealth/Silence: {:?}\n", tracker.stealth_lines)); }
        if !tracker.persistence_lines.is_empty() { trace.push_str(&format!(" -> Persistence Hook: {:?}\n", tracker.persistence_lines)); }

        let (name, severity, explanation, fix) = if !tracker.stealth_lines.is_empty() {
            (
                "Heuristic: Malicious Lifecycle Detected".to_string(),
                "Critical".to_string(),
                "This script follows the 'Fetch-Modify-Execute' pattern typical of automated background trojans.".to_string(),
                Some("Isolated execution recommended. Verify hidden tracking elements and persistence structures.".to_string())
            )
        } else {
            (
                "Heuristic: Standard Installation Sequence".to_string(),
                "Medium".to_string(),
                "This script downloads remote components and updates local permissions. Common profile pattern for valid tools.".to_string(),
                Some("Verify destination target domain source points match trusted profiles before execution.".to_string())
            )
        };

        findings.push(AuditFinding {
            line_no: 0,
            code_snippet: trace,
            name,
            category: "Malware Behaviour".to_string(),
            explanation,
            severity,
            reference: "Behavioural Grouping v0.5.5".to_string(),
            fix,
        });
    }

    findings
}

// --- TUI RENDERER ---
fn ui(f: &mut ratatui::Frame, app: &mut App, content: &str) {
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

    // --- 3. MAIN BODY HORIZONTAL LAYOUT ---
    let is_glob_selected = app.state.selected()
        .map(|sel| app.findings[sel].line_no == 0)
        .unwrap_or(false);

    let main_constraints = if is_glob_selected {
        vec![
            Constraint::Percentage(20), 
            Constraint::Percentage(50), 
            Constraint::Percentage(25), 
            Constraint::Percentage(5),  
        ]
    } else {
        vec![
            Constraint::Percentage(25), 
            Constraint::Percentage(70), 
            Constraint::Percentage(5),  
        ]
    };

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(main_constraints)
        .split(chunks[1]);

    if app.findings.is_empty() {
        let safe_msg = Paragraph::new(vec![Line::from("No threats found.")])
            .block(Block::default().borders(Borders::ALL).title(" Results "));
        f.render_widget(safe_msg, chunks[1]);
    } else {
        let items: Vec<ListItem> = app.findings.iter().map(|f| {
            let color = match f.severity.as_str() {
                "Critical" => Color::Red,
                "High" => Color::LightRed,
                "Medium" => Color::Yellow,
                _ => Color::Gray,
            };
            let line_label = if f.line_no == 0 { "GLOB".into() } else { format!("L{}", f.line_no) };
            ListItem::new(format!("[{}] [{}] {}", line_label, f.severity, f.name))
                .style(Style::default().fg(color))
        }).collect();

        let list_highlight_style = if is_glob_selected {
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .bg(Color::Rgb(50, 50, 50))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Findings "))
            .highlight_style(list_highlight_style)
            .highlight_symbol(">> ");
        f.render_stateful_widget(list, main_chunks[0], &mut app.state);

        if let Some(sel) = app.state.selected() {
            let finding = &app.findings[sel];
            let is_suppressed = app.suppressed_indices.contains(&sel);
            
            let lines: Vec<Line> = finding.code_snippet.lines().map(|l| {
                if l.starts_with('>') {
                    if is_suppressed {
                        Line::from(Span::styled(format!("# [SUPPRESSED] {}", &l[1..].trim()), Style::default().fg(Color::Cyan).add_modifier(Modifier::ITALIC)))
                    } else if finding.line_no == 0 {
                        Line::from(Span::styled(l, Style::default().fg(Color::Gray)))
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

            // If a global rule is selected, render wrapped, perfectly matched context snapshots into the third column
            if is_glob_selected {
                let mut highlights = vec![
                    Line::from(Span::styled("Suspicious Line Quick-View:", Style::default().add_modifier(Modifier::BOLD))),
                    Line::from(""),
                ];

                for (idx, raw_line) in content.lines().enumerate() {
                    let line_num = idx + 1;
                    let trimmed = raw_line.trim();
                    
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    // Strict matching logic synced 1:1 with perform_analysis rules
                    let matched_label = if trimmed.contains("curl") || trimmed.contains("wget") {
                        Some("Fetch")
                    } else if trimmed.contains("chmod +x") || trimmed.contains("chmod 7") || trimmed.contains("chmod u+x") {
                        Some("Perms")
                    } else if (trimmed.contains("eval ") && (trimmed.contains("printf") || trimmed.contains("\\x") || trimmed.contains("\\0")))
                        || trimmed.contains("base64 -d") 
                        || trimmed.contains("openssl enc")
                        || (trimmed.starts_with("DATA=") && trimmed.len() > 40) 
                    {
                        Some("Obfuscation")
                    } else if (trimmed.starts_with("./") || trimmed.starts_with("/") || trimmed.contains("bash ") || trimmed.contains("| sh") || trimmed.contains("| bash"))
                        && (!trimmed.starts_with("/etc") && !trimmed.starts_with("/usr") && !trimmed.contains('='))
                    {
                        Some("Execution")
                    } else if trimmed.contains("rm $0") || trimmed.contains("> /dev/null") || trimmed.contains("/dev/shm") {
                        Some("Stealth")
                    } else if trimmed.contains("crontab") || trimmed.contains(".bashrc") || trimmed.contains("systemctl") {
                        Some("Persistence")
                    } else {
                        None
                    };

                    if let Some(label) = matched_label {
                        highlights.push(Line::from(vec![
                            Span::styled(format!("[L{}] {}: ", line_num, label), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::styled(trimmed, Style::default().fg(Color::White)),
                        ]));
                    }
                }

                let highlight_para = Paragraph::new(highlights)
                    .block(Block::default().borders(Borders::ALL).title(" Highlights "))
                    .wrap(Wrap { trim: false }) // Native line wrapping introduced here to ensure zero truncation
                    .scroll((app.highlight_scroll, 0));

                f.render_widget(highlight_para, main_chunks[2]);
            }

            // Assign map chunk slice based on layout configurations dynamic resizing index
            let map_chunk_idx = if is_glob_selected { 3 } else { 2 };
            let total_lines = content.lines().count();
            let sidebar_height = main_chunks[map_chunk_idx].height as usize;
            let mut map_lines = vec![Line::from(" "); sidebar_height];
            
            for find in &app.findings {
                let color = if find.severity == "Critical" || find.severity == "High" { Color::Red } else { Color::Yellow };
                
                if find.line_no == 0 {
                    map_lines[0] = Line::from(Span::styled("▼", Style::default().fg(color)));
                    if sidebar_height > 1 {
                        map_lines[sidebar_height - 1] = Line::from(Span::styled("▲", Style::default().fg(color)));
                    }
                } else if total_lines > 0 {
                    let pos = (find.line_no * sidebar_height / total_lines).saturating_sub(1);
                    if pos < sidebar_height {
                        map_lines[pos] = Line::from(Span::styled("█", Style::default().fg(color)));
                    }
                }
            }
            f.render_widget(Paragraph::new(map_lines).block(Block::default().borders(Borders::LEFT | Borders::RIGHT).title(" Map ")), main_chunks[map_chunk_idx]);

            let fix_text = finding.fix.as_deref().unwrap_or("Manual audit recommended.");
            let analysis_text = vec![
                Line::from(finding.explanation.as_str()),
                Line::from(Span::styled(format!("Tip: {}", fix_text), Style::default().fg(Color::Cyan))),
                Line::from(format!("Ref: {}", finding.reference)),
            ];

            let expl_para = Paragraph::new(analysis_text)
                .block(Block::default().borders(Borders::ALL).title(" Analysis & Verdict "))
                .wrap(Wrap { trim: true });
            f.render_widget(expl_para, chunks[2]);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();
    let content: String;
    let source_label: String;

    if args.target.starts_with("http") {
        let client = reqwest::Client::builder().user_agent("Oversight/0.5.5").build().unwrap();
        let resp = client.get(&args.target).send().await.expect("Failed to fetch");
        content = resp.text().await.unwrap_or_default();
        source_label = args.target.clone();
    } else {
        content = fs::read_to_string(&args.target).expect("Failed to read file");
        source_label = args.target.clone();
    }

    let findings = perform_analysis(&content).await;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(findings, source_label);

    loop {
        terminal.draw(|f| ui(f, &mut app, &content))?;
        if let Event::Key(key) = event::read()? {
            let is_glob_selected = app.state.selected()
                .map(|sel| app.findings[sel].line_no == 0)
                .unwrap_or(false);

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down => {
                    if is_glob_selected {
                        app.highlight_scroll = app.highlight_scroll.saturating_add(1);
                    } else {
                        app.next();
                    }
                }
                KeyCode::Up => {
                    if is_glob_selected {
                        app.highlight_scroll = app.highlight_scroll.saturating_sub(1);
                    } else {
                        app.previous();
                    }
                }
                KeyCode::Left => {
                    if is_glob_selected {
                        app.highlight_scroll = 0;
                    }
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    if let Some(sel) = app.state.selected() {
                        if !app.suppressed_indices.insert(sel) {
                            app.suppressed_indices.remove(&sel);
                        }
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
