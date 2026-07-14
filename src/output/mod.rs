pub mod html;
pub mod json;
pub mod table;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub variant: String,
    pub vulnerable: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub status_code: u16,
    pub details: Option<String>,

    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub waf_detected: Option<String>,
    #[serde(default)]
    pub cve_matches: Vec<String>,
    #[serde(default)]
    pub poc_generated: bool,
    #[serde(default)]
    pub poc_request: Option<String>,
    #[serde(default)]
    pub poc_response: Option<String>,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            variant: String::new(),
            vulnerable: false,
            server: None,
            bypass: None,
            status_code: 0,
            details: None,
            outcome: None,
            waf_detected: None,
            cve_matches: Vec::new(),
            poc_generated: false,
            poc_request: None,
            poc_response: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub author: String,
    pub timestamp: String,
    pub target: String,
    pub results: Vec<ScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_hosts: usize,
    pub total_variants: usize,
    pub vulnerable_count: usize,
    pub not_vulnerable_count: usize,
    pub errors: usize,
}

pub trait OutputFormatter {
    fn format(&self, report: &ScanReport) -> Result<String, String>;
    fn extension(&self) -> &'static str;
}

pub fn get_formatter(name: &str) -> Result<Box<dyn OutputFormatter>, String> {
    match name.to_lowercase().as_str() {
        "json" => Ok(Box::new(json::JsonFormatter)),
        "yaml" => Ok(Box::new(json::YamlFormatter)),
        "html" => Ok(Box::new(html::HtmlFormatter)),
        "table" => Ok(Box::new(table::TableFormatter)),
        _ => Err(format!("Unknown formatter: {}. Options: json, yaml, html, table", name)),
    }
}
