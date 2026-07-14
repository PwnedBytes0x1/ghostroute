use super::{OutputFormatter, ScanReport};

pub struct TableFormatter;

impl OutputFormatter for TableFormatter {
    fn format(&self, report: &ScanReport) -> Result<String, String> {
        let mut out = String::new();

        if report.results.is_empty() {
            out.push_str("\n  No results\n");
            return Ok(out);
        }

        let vulnerable: Vec<_> = report.results.iter().filter(|r| r.vulnerable).collect();
        let servers: Vec<_> = report.results.iter()
            .filter_map(|r| r.server.as_deref())
            .collect();

        let target_str = if report.summary.total_hosts == 1 {
            format!("\n  target : {}", report.target)
        } else {
            let hosts: Vec<&str> = report.target.split(", ").collect();
            format!("  targets : {}", hosts.join(", "))
        };
        out.push_str(&target_str);
        out.push('\n');

        if vulnerable.is_empty() {
            out.push_str("  vulnerable to : none\n");
        } else {
            let vuln_list: Vec<String> = vulnerable.iter().map(|r| {
                let mut s = r.variant.to_uppercase();
                if let Some(ref bypass) = r.bypass {
                    s.push_str(&format!(" ({})", bypass));
                }
                if r.poc_generated {
                    s.push_str(" [POC]");
                }
                s
            }).collect();
            out.push_str(&format!("  vulnerable to : {}\n", vuln_list.join(", ")));
        }

        if !servers.is_empty() {
            let mut unique: Vec<&str> = servers.clone();
            unique.sort();
            unique.dedup();
            out.push_str(&format!("  server : {}\n", unique.join(", ")));
        }

        for r in &vulnerable {
            if let Some(ref details) = r.details {
                out.push_str(&format!("    -> {}\n", details));
            }
            if r.poc_generated {
                out.push_str("    -> POC payload generated\n");
            }
            if let Some(ref outcome) = r.outcome {
                out.push_str(&format!("    -> outcome: {}\n", outcome));
            }
            if let Some(ref waf) = r.waf_detected {
                out.push_str(&format!("    -> waf: {}\n", waf));
            }
            if !r.cve_matches.is_empty() {
                out.push_str(&format!("    -> cves: {}\n", r.cve_matches.join(", ")));
            }
        }

        out.push('\n');
        Ok(out)
    }

    fn extension(&self) -> &'static str {
        "txt"
    }
}
