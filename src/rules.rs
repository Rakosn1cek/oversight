/*
 * Oversight - Security Intelligence & Audit Engine
 * Author:  Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Version: 0.4.0
 * Description: 
 * Dynamic rules loading logic
 */


use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Structure representing a single security rule
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: String,
    pub explanation: String,
    pub reference: String,
}

/// Container for the complete set of rules and metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: String,
    pub last_updated: String,
    pub rules: Vec<Rule>,
}

/// Loads security rules from the local filesystem with a compiled-in fallback
pub fn load_rules() -> Vec<Rule> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let local_path = PathBuf::from(home).join(".local/share/oversight/rules.json");

    // Attempt to load and parse local configuration
    if let Ok(content) = fs::read_to_string(&local_path) {
        if let Ok(rule_set) = serde_json::from_str::<RuleSet>(&content) {
            return rule_set.rules;
        }
        eprintln!("Warning: Local rules.json is malformed. Falling back to defaults.");
    }

    // Static fallback using embedded JSON data
    let embedded_json = include_str!("../rules.json");
    let rule_set: RuleSet = serde_json::from_str(embedded_json)
        .expect("Embedded rules.json is invalid. Build-time configuration error.");

    rule_set.rules
}
