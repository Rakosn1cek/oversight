/*
 * Oversight - Security Intelligence & Audit Engine
 * Author:  Lukas Grumlik - Rakosn1cek
 * Created: 2026-04-19
 * Version: 0.4.0
 * Description: 
 * Vulnerability intelligence engine
 */


use serde::{Deserialize, Serialize};
use reqwest::blocking::Client;
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

pub fn check_package(name: &str, version: &str, ecosystem: &str) -> Result<OsvResponse, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
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
        .send()?
        .json::<OsvResponse>()?;

    Ok(response)
}
