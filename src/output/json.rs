use super::{ScanResult};

pub fn jsonl_line(result: &ScanResult) -> String {
    serde_json::to_string(result).unwrap_or_default()
}
