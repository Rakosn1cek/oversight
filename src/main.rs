/*
 * Oversight - Security Intelligence & Audit Engine
 * Author:  Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Description: 
 * A static analysis tool that audits local scripts and remote Raw URLs.
 * Uses a dynamic rules engine to educate users on malicious patterns.
 * Use UP/DOWN to navigate, 'q' or ESC to exit, TAB to toggle view streams.
 */

use clap::Parser;
use std::{fs, io};
use std::path::{Path, PathBuf};
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
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about = "Oversight: Educational Script Auditor")]
struct Args {
    target: Option<String>,
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

struct IntentTracker {
    fetch_lines: Vec<usize>,
    chmod_lines: Vec<usize>,
    execute_lines: Vec<usize>,
    stealth_lines: Vec<usize>,
    persistence_lines: Vec<usize>,
    installer_lines: Vec<usize>,
}

struct TargetPackage {
    pub name: String,
    pub files: Vec<(String, String)>, // [("PKGBUILD", "text..."), (".install", "text...")]
}

// --- APP STATE ---
struct App {
    findings: Vec<AuditFinding>,
    state: ListState,
    highlight_scroll: u16,
    max_scroll: u16,
    viewport_height: u16,
    source_name: String,
    risk_score: usize,
    suppressed_indices: HashSet<usize>,
    active_tab: usize,
    packages: Vec<TargetPackage>,
}

impl App {
    fn new(findings: Vec<AuditFinding>, source_name: String, packages: Vec<TargetPackage>) -> App {
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
            max_scroll: 0,
            viewport_height: 10,
            source_name, 
            risk_score,
            suppressed_indices,
            active_tab: 0,
            packages,
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
        self.highlight_scroll = 0;
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
        self.highlight_scroll = 0;
    }

    fn scroll_down(&mut self, amount: u16) {
        self.highlight_scroll = self.highlight_scroll.saturating_add(amount).min(self.max_scroll);
    }

    fn scroll_up(&mut self, amount: u16) {
        self.highlight_scroll = self.highlight_scroll.saturating_sub(amount);
    }

    fn scroll_to_top(&mut self) {
        self.highlight_scroll = 0;
    }

    fn scroll_to_bottom(&mut self) {
        self.highlight_scroll = self.max_scroll;
    }

    fn page_step(&self) -> u16 {
        self.viewport_height.saturating_sub(2).max(1)
    }

    fn half_page_step(&self) -> u16 {
        (self.viewport_height / 2).max(1)
    }

    fn is_pager_mode(&self) -> bool {
        self.findings.len() <= 1 
            || self.active_tab > 0 
            || self.state.selected().map(|sel| self.findings[sel].name == "Static Analysis Passed").unwrap_or(false)
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
        installer_lines: Vec::new(),
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
        let mut trimmed = line.trim();
        
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            trimmed = trimmed[1..].trim();
        }
        
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

        if trimmed.contains("npm install") || trimmed.contains("bun install") || trimmed.contains("yarn add") || trimmed.contains("pnpm install") {
            tracker.installer_lines.push(idx + 1);
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
    if !tracker.installer_lines.is_empty() {
        findings.push(AuditFinding {
            line_no: 0,
            code_snippet: format!(" -> Build-Time Installer Execution: {:?}\n", tracker.installer_lines),
            name: "Heuristic: Malicious Dependency Injection Pattern".to_string(),
            category: "Malware Behaviour".to_string(),
            explanation: "The script runs a secondary package installer during the build profile. This directly allows unverified third-party asset code execution on the local system, mirroring recent AUR hijacking campaigns.".to_string(),
            severity: "Critical".to_string(),
            reference: "Behavioural Grouping v0.5.9".to_string(),
            fix: Some("Halt installation immediately. Check upstream dependency tree definitions before executing local build commands.".to_string()),
        });
    }

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
            reference: "Behavioural Grouping v0.5.9".to_string(),
            fix,
        });
    }

    if findings.is_empty() {
        findings.push(AuditFinding {
            line_no: 0,
            code_snippet: "No malicious patterns or anomalous lifecycle behaviors detected.\nUse Up/Down keys to read through the raw source text buffer safely.".to_string(),
            name: "Static Analysis Passed".to_string(),
            category: "Audit".to_string(),
            explanation: "The script or diff profile matches trusted deployment models.".to_string(),
            severity: "Low".to_string(),
            reference: "Oversight Engine".to_string(),
            fix: Some("Review the source code in the tabs panel to confirm structural layout integrity before executing installation prompts.".to_string()),
        });
    }

    findings
}

// --- TUI RENDERER ---
fn ui(f: &mut ratatui::Frame, app: &mut App, diff_content: &str) {
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

    // --- MAIN BODY HORIZONTAL LAYOUT ---
    let is_glob_selected = app.state.selected()
        .map(|sel| app.findings[sel].line_no == 0)
        .unwrap_or(false);

    let is_clean_pass = app.state.selected()
        .map(|sel| app.findings[sel].name == "Static Analysis Passed")
        .unwrap_or(false);

    let main_constraints = if is_glob_selected && !is_clean_pass {
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

    let items: Vec<ListItem> = app.findings.iter().map(|f| {
        let color = match f.severity.as_str() {
            "Critical" => Color::Red,
            "High" => Color::LightRed,
            "Medium" => Color::Yellow,
            "Low" if f.name == "Static Analysis Passed" => Color::Green,
            _ => Color::Gray,
        };
        let line_label = if f.line_no == 0 { "GLOB".into() } else { format!("L{}", f.line_no) };
        ListItem::new(format!("[{}] [{}] {}", line_label, f.severity, f.name))
            .style(Style::default().fg(color))
    }).collect();

    let list_highlight_style = if is_glob_selected {
        Style::default()
            .fg(if is_clean_pass { Color::Green } else { Color::Red })
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
        
        let viewport_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(main_chunks[1]);

        // Dynamically append extracted package identifiers onto the layout headers
        let mut tab_titles = vec![Line::from(" [0] Combined Git Diff ")];
        for (idx, pkg) in app.packages.iter().enumerate() {
            tab_titles.push(Line::from(format!(" [{}] PKGBUILD: {} ", idx + 1, pkg.name)));
        }

        let tabs_widget = Tabs::new(tab_titles)
            .block(Block::default().borders(Borders::ALL).title(" Code Stream Segments "))
            .select(app.active_tab)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
        f.render_widget(tabs_widget, viewport_layout[0]);

        let is_custom_pkg_tab = app.active_tab > 0 && app.active_tab <= app.packages.len();
        let current_source_text = if is_custom_pkg_tab {
            &app.packages[app.active_tab - 1].files[0].1
        } else {
            diff_content
        };

        static CLEAN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\x1B\[[0-9;]*[a-zA-Z]|.\x08").unwrap()
        });

        let lines: Vec<Line> = if is_clean_pass || is_custom_pkg_tab || is_glob_selected {
            current_source_text.lines().map(|l| {
                let clean = CLEAN_RE.replace_all(l, "").into_owned();
                
                // Text style based on unified diff formatting standards
                let style = if clean.starts_with('+') && !clean.starts_with("+++") {
                    Style::default().fg(Color::Green)
                } else if clean.starts_with('-') && !clean.starts_with("---") {
                    Style::default().fg(Color::Red)
                } else if clean.starts_with("@@") {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Gray)
                };

                Line::from(Span::styled(clean, style))
            }).collect()
        } else {
            finding.code_snippet.lines().map(|l| {
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
            }).collect()
        };

        // Viewport text metrics minus layout border frames
        let viewport_height = (viewport_layout[1].height as usize).saturating_sub(2);
        let inner_width = (viewport_layout[1].width as usize).saturating_sub(2);
        app.viewport_height = viewport_height as u16;

        let mut total_visual_rows = 0;
        for line in &lines {
            let width = line.width();
            let rows = if inner_width == 0 || width == 0 { 1 } else { (width + inner_width - 1) / inner_width };
            total_visual_rows += rows;
        }
        app.max_scroll = (total_visual_rows as u16).saturating_sub(app.viewport_height);
        app.highlight_scroll = app.highlight_scroll.min(app.max_scroll);

        let code_para = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Viewport "))
            .wrap(Wrap { trim: true })
            .scroll((app.highlight_scroll, 0));
            
        f.render_widget(ratatui::widgets::Clear, viewport_layout[1]);
        f.render_widget(code_para, viewport_layout[1]);

        if is_glob_selected && !is_clean_pass {
            let mut highlights = vec![
                Line::from(Span::styled("Suspicious Line Quick-View:", Style::default().add_modifier(Modifier::BOLD))),
                Line::from(""),
            ];

            for (idx, raw_line) in current_source_text.lines().enumerate() {
                let line_num = idx + 1;
                let trimmed = raw_line.trim();
                
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

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
                } else if trimmed.contains("npm install") || trimmed.contains("bun install") || trimmed.contains("yarn add") || trimmed.contains("pnpm install") {
                    Some("Installer")
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
                .wrap(Wrap { trim: false }) 
                .scroll((0, 0));

            f.render_widget(highlight_para, main_chunks[2]);
        }

        let map_chunk_idx = if is_glob_selected && !is_clean_pass { 3 } else { 2 };
        let total_lines = current_source_text.lines().count();
        let sidebar_height = main_chunks[map_chunk_idx].height as usize;
        let mut map_lines = vec![Line::from(" "); sidebar_height];
        
        let mut target_lines = Vec::new();
        let mut has_glob = false;
        let mut highest_severity_color = if is_clean_pass { Color::Green } else { Color::Yellow };

        for find in &app.findings {
            if find.name == "Static Analysis Passed" {
                continue;
            }
            if find.severity == "Critical" || find.severity == "High" {
                highest_severity_color = Color::Red;
            }
            if find.line_no == 0 {
                has_glob = true;
            } else {
                target_lines.push(find.line_no);
            }
        }

        if has_glob && !is_clean_pass {
            for (idx, raw_line) in current_source_text.lines().enumerate() {
                let mut trimmed = raw_line.trim();
                if trimmed.starts_with('+') || trimmed.starts_with('-') {
                    trimmed = trimmed[1..].trim();
                }
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let is_matched = trimmed.contains("curl") || trimmed.contains("wget")
                    || trimmed.contains("chmod +x") || trimmed.contains("chmod 7") || trimmed.contains("chmod u+x")
                    || (trimmed.contains("eval ") && (trimmed.contains("printf") || trimmed.contains("\\x") || trimmed.contains("\\0")))
                    || trimmed.contains("base64 -d") 
                    || trimmed.contains("openssl enc")
                    || (trimmed.starts_with("DATA=") && trimmed.len() > 40)
                    || ((trimmed.starts_with("./") || trimmed.starts_with("/") || trimmed.contains("bash ") || trimmed.contains("| sh") || trimmed.contains("| bash"))
                        && (!trimmed.starts_with("/etc") && !trimmed.starts_with("/usr") && !trimmed.contains('=')))
                    || trimmed.contains("rm $0") || trimmed.contains("> /dev/null") || trimmed.contains("/dev/shm")
                    || trimmed.contains("crontab") || trimmed.contains(".bashrc") || trimmed.contains("systemctl");

                if is_matched {
                    target_lines.push(idx + 1);
                }
            }
        }

        if total_lines > 0 && !is_clean_pass {
            for line_num in target_lines {
                let pos = (line_num * sidebar_height / total_lines).saturating_sub(1);
                if pos < sidebar_height {
                    map_lines[pos] = Line::from(Span::styled("█", Style::default().fg(highest_severity_color)));
                }
            }
        }

        // Render scroll position indicator on minimap
        if sidebar_height > 2 && app.max_scroll > 0 {
            let usable_range = sidebar_height - 2;
            let thumb = 1 + ((app.highlight_scroll as usize * (usable_range.saturating_sub(1))) / app.max_scroll as usize);
            if map_lines[thumb].spans.is_empty() || map_lines[thumb].spans[0].content == " " {
                map_lines[thumb] = Line::from(Span::styled("█", Style::default().fg(Color::Cyan)));
            }
        }

        map_lines[0] = Line::from(Span::styled("▼", Style::default().fg(highest_severity_color)));
        if sidebar_height > 1 {
            map_lines[sidebar_height - 1] = Line::from(Span::styled("▲", Style::default().fg(highest_severity_color)));
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

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();
    let mut diff_content = String::new();
    let mut packages: Vec<TargetPackage> = Vec::new();
    let source_label: String;

    match args.target {
        Some(ref t) if t.starts_with("http") => {
            let client = reqwest::Client::builder().user_agent(format!("Oversight/{}", VERSION)).build().unwrap();
            let resp = client.get(t).send().await.expect("Failed to fetch");
            diff_content = resp.text().await.unwrap_or_default();
            source_label = t.clone();
        }
        Some(ref t) if t == "-" => {
            io::Read::read_to_string(&mut io::stdin(), &mut diff_content)?;
            source_label = "stdin".to_string();
        }
        Some(ref t) => {
            diff_content = fs::read_to_string(t).expect("Failed to read file");
            source_label = t.clone();
        }
        None => {
            io::Read::read_to_string(&mut io::stdin(), &mut diff_content)?;
            source_label = "piped-input".to_string();
        }
    }

    if diff_content.trim().is_empty() {
        eprintln!("error: No input data provided via argument or stdin pipeline.");
        std::process::exit(1);
    }

    // Dynamic Multi-Package Scanner Loops
    // Scan headers inside combined git streams to isolate unique components
    let diff_header_regex = Regex::new(r"diff --git a/\.cache/[^/]+/([^/]+)/PKGBUILD|diff --git a/.*/([^/]+)/PKGBUILD").unwrap();
    let mut discovered_names = HashSet::new();
    
    // Check if a specific AUR helper environment or custom configuration variable is set
    let aur_helper = std::env::var("AUDIT_HELPER").unwrap_or_else(|_| "yay".to_string());
    
    let mut findings = perform_analysis(&diff_content).await;

    for line in diff_content.lines() {
        if let Some(caps) = diff_header_regex.captures(line) {
            // Check both capture groups from the fallback regex definitions
            if let Some(pkg_match) = caps.get(1).or_else(|| caps.get(2)) {
                let pkg_name = pkg_match.as_str().to_string();
                if discovered_names.insert(pkg_name.clone()) {
                    
                    // Check if the AUR package is orphaned
                    if let Ok(is_orphaned) = intel::check_aur_status(&pkg_name).await {
                        if is_orphaned {
                            findings.push(AuditFinding {
                                line_no: 0,
                                code_snippet: format!("Package Name: {}\nStatus: Orphaned on AUR (No active maintainer)", pkg_name),
                                name: "Orphaned AUR Package".to_string(),
                                category: "Maintenance Risk".to_string(),
                                explanation: "This package has no active maintainer on the Arch User Repository. Unmaintained packages can become vectors for abandonment or malicious takeovers.".to_string(),
                                severity: "Critical".to_string(),
                                reference: format!("https://aur.archlinux.org/packages/{}", pkg_name),
                                fix: Some("Consider adopting this package or switching to an alternative maintained package from the extra repository or AUR.".to_string()),
                            });
                        }
                    }

                    // Reconstruct path allocations matching target local fallback options
                    let home = std::env::var("HOME").unwrap_or_default();
                    let cache_path = format!("{}/.cache/{}/{}", home, aur_helper, pkg_name);
                    let pkgbuild_file = format!("{}/PKGBUILD", cache_path);
                    
                    if Path::new(&pkgbuild_file).exists() {
                        if let Ok(content) = fs::read_to_string(&pkgbuild_file) {
                            packages.push(TargetPackage {
                                name: pkg_name,
                                files: vec![("PKGBUILD".to_string(), content)],
                            });
                        }
                    }
                }
            }
        }
    }

    // Local fallback catch segment if running directory scopes manually
    if packages.is_empty() && Path::new("PKGBUILD").exists() {
        if let Ok(content) = fs::read_to_string("PKGBUILD") {
            let current_dir = std::env::current_dir().unwrap_or_default();
            let dir_name = current_dir.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "local".to_string());
            
            packages.push(TargetPackage {
                name: dir_name,
                files: vec![("PKGBUILD".to_string(), content)],
            });
        }
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(findings, source_label, packages);

    loop {
        terminal.draw(|f| ui(f, &mut app, &diff_content))?;
        match event::read()? {
            Event::Key(key) => {
                let max_tab_index = app.packages.len();
                let is_pager = app.is_pager_mode();

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => {
                        if max_tab_index > 0 {
                            app.active_tab = if app.active_tab >= max_tab_index { 0 } else { app.active_tab + 1 };
                            app.highlight_scroll = 0;
                        }
                    }
                    KeyCode::Char(c) if c.is_digit(10) => {
                        if let Some(digit) = c.to_digit(10) {
                            let target_idx = digit as usize;
                            if target_idx <= max_tab_index {
                                app.active_tab = target_idx;
                                app.highlight_scroll = 0;
                            }
                        }
                    }
                    KeyCode::Down => {
                        if is_pager {
                            app.scroll_down(1);
                        } else {
                            app.next();
                        }
                    }
                    KeyCode::Up => {
                        if is_pager {
                            app.scroll_up(1);
                        } else {
                            app.previous();
                        }
                    }
                    KeyCode::Char('j') | KeyCode::Char('J') => {
                        app.scroll_down(1);
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') => {
                        app.scroll_up(1);
                    }
                    KeyCode::PageDown | KeyCode::Char(' ') => {
                        app.scroll_down(app.page_step());
                    }
                    KeyCode::PageUp | KeyCode::Char('b') => {
                        app.scroll_up(app.page_step());
                    }
                    KeyCode::Char('d') => {
                        if key.modifiers.contains(KeyModifiers::CONTROL) || is_pager {
                            app.scroll_down(app.half_page_step());
                        }
                    }
                    KeyCode::Char('u') => {
                        if key.modifiers.contains(KeyModifiers::CONTROL) || is_pager {
                            app.scroll_up(app.half_page_step());
                        }
                    }
                    KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.scroll_down(app.page_step());
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        app.scroll_to_top();
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        app.scroll_to_bottom();
                    }
                    KeyCode::Left => {
                        app.scroll_to_top();
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
            Event::Mouse(mouse) => {
                match mouse.kind {
                    MouseEventKind::ScrollDown => {
                        app.scroll_down(3);
                    }
                    MouseEventKind::ScrollUp => {
                        app.scroll_up(3);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_man_pacman() {
        let output = std::process::Command::new("man").arg("pacman").output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        let findings = perform_analysis(&text).await;
        println!("Findings count: {}", findings.len());
        for f in &findings {
            println!("Finding: [{}] {}", f.line_no, f.name);
        }
    }

    #[test]
    fn test_app_scrolling_and_clamping() {
        let findings = vec![AuditFinding {
            line_no: 0,
            code_snippet: "test".to_string(),
            name: "Static Analysis Passed".to_string(),
            category: "Audit".to_string(),
            explanation: "Clean".to_string(),
            severity: "Low".to_string(),
            reference: "Engine".to_string(),
            fix: None,
        }];

        let mut app = App::new(findings, "test".to_string(), Vec::new());
        assert!(app.is_pager_mode());

        app.max_scroll = 50;
        app.viewport_height = 20;

        // Line down
        app.scroll_down(1);
        assert_eq!(app.highlight_scroll, 1);

        // Page down
        let step = app.page_step();
        assert_eq!(step, 18);
        app.scroll_down(step);
        assert_eq!(app.highlight_scroll, 19);

        // Scroll past max
        app.scroll_down(100);
        assert_eq!(app.highlight_scroll, 50);

        // Scroll up
        app.scroll_up(10);
        assert_eq!(app.highlight_scroll, 40);

        // Scroll to bottom and top
        app.scroll_to_bottom();
        assert_eq!(app.highlight_scroll, 50);
        app.scroll_to_top();
        assert_eq!(app.highlight_scroll, 0);
    }
}

