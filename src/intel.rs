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

// --- AUR Metadata Structures ---

#[derive(Deserialize, Debug)]
pub struct AurRpcResponse {
    pub results: Vec<AurPackageInfo>,
}

#[derive(Deserialize, Debug)]
pub struct AurPackageInfo {
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
}

/// Queries the OSV database for known vulnerabilities in a specific package
pub async fn check_package(name: &str, version: &str, ecosystem: &str) -> Result<OsvResponse, Box<dyn std::error::Error>> {
    // Initialise the client with a specific User Agent and timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Oversight/0.5.9")
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

/// Queries the Arch User Repository to check if a package is orphaned or unmaintained
pub async fn check_aur_status(pkgname: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Oversight/0.5.9")
        .build()?;

    let url = format!("https://aur.archlinux.org/rpc/v5/info?arg[]={}", pkgname);
    
    let response = client
        .get(&url)
        .send()
        .await?
        .json::<AurRpcResponse>()
        .await?;

    if let Some(pkg_info) = response.results.first() {
        // If the maintainer field is None or empty, the package is orphaned on the AUR
        match &pkg_info.maintainer {
            Some(m) if !m.trim().is_empty() => Ok(false),
            _ => Ok(true),
        }
    } else {
        // Package not found on AUR (might be local or official repo)
        Ok(false)
    }
}
