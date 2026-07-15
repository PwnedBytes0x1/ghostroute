pub mod html;
pub mod json;
pub mod table;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    #[allow(dead_code)]
    fn extension(&self) -> &'static str;
}


