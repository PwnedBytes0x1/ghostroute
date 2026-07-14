use super::{OutputFormatter, ScanResult, ScanReport};

pub struct JsonFormatter;
pub struct YamlFormatter;

impl OutputFormatter for JsonFormatter {
    fn format(&self, report: &ScanReport) -> Result<String, String> {
        serde_json::to_string_pretty(report).map_err(|e| e.to_string())
    }

    fn extension(&self) -> &'static str {
        "json"
    }
}

impl OutputFormatter for YamlFormatter {
    fn format(&self, report: &ScanReport) -> Result<String, String> {
        serde_yaml::to_string(report).map_err(|e| e.to_string())
    }

    fn extension(&self) -> &'static str {
        "yaml"
    }
}

pub fn jsonl_line(result: &ScanResult) -> String {
    serde_json::to_string(result).unwrap_or_default()
}
