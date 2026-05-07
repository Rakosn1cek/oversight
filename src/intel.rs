/*
 * Oversight - Security Intelligence & Audit Engine
 * Author:   Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Description: 
 * Vulnerability intelligence engine
 */

use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;

#[derive(Serialize)]
pub struct OsvQuery {
    pub package: Package,
    pub version: String,
}

#[derive(Serialize)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Deserialize, Debug)]
pub struct OsvResponse {
    pub vulns: Option<Vec<Vulnerability>>,
}

#[derive(Deserialize, Debug)]
pub struct Vulnerability {
    pub id: String,
    pub details: String,
}

/// Queries the OSV database for known vulnerabilities in a specific package
pub async fn check_package(name: &str, version: &str, ecosystem: &str) -> Result<OsvResponse, Box<dyn std::error::Error>> {
    // Initialise the client with a specific User Agent and timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Oversight/0.4.5")
        .build()?;

    let query = OsvQuery {
        package: Package {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
        },
        version: version.to_string(),
    };

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await?
        .json::<OsvResponse>()
        .await?;

    Ok(response)
}
