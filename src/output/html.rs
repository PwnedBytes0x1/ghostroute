use super::{OutputFormatter, ScanReport};

pub struct HtmlFormatter;

impl OutputFormatter for HtmlFormatter {
    fn format(&self, report: &ScanReport) -> Result<String, String> {
        let mut rows = String::new();
        for r in &report.results {
            let status_class = if r.vulnerable { "vuln" } else { "safe" };
            let status_text = if r.vulnerable { "VULNERABLE" } else { "NOT VULN" };
            let bypass = r.bypass.as_deref().unwrap_or("-");
            let server = r.server.as_deref().unwrap_or("-");

            rows.push_str(&format!(
                r#"<tr>
                    <td>{}:{}</td>
                    <td><span class="variant">{}</span></td>
                    <td><span class="status {}">{}</span></td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>"#,
                r.host, r.port, r.variant.to_uppercase(),
                status_class, status_text,
                server, bypass,
            ));

            if r.vulnerable {
                if let Some(ref details) = r.details {
                    rows.push_str(&format!(
                        r#"<tr class="detail-row">
                            <td colspan="5"><span class="detail">→ {}</span></td>
                        </tr>"#,
                        details,
                    ));
                }
                if let Some(ref outcome) = r.outcome {
                    rows.push_str(&format!(
                        r#"<tr class="detail-row">
                            <td colspan="5"><span class="detail">→ outcome: {}</span></td>
                        </tr>"#,
                        outcome,
                    ));
                }
                if let Some(ref waf) = r.waf_detected {
                    rows.push_str(&format!(
                        r#"<tr class="detail-row">
                            <td colspan="5"><span class="detail">→ waf: {}</span></td>
                        </tr>"#,
                        waf,
                    ));
                }
                if !r.cve_matches.is_empty() {
                    rows.push_str(&format!(
                        r#"<tr class="detail-row">
                            <td colspan="5"><span class="detail">→ cves: {}</span></td>
                        </tr>"#,
                        r.cve_matches.join(", "),
                    ));
                }
                if r.poc_generated {
                    rows.push_str(&format!(
                        r#"<tr class="detail-row">
                            <td colspan="5"><span class="detail">→ POC generated</span></td>
                        </tr>"#,
                    ));
                }
            }
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ghostroute - Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; background: #0a0e14; color: #e6e1cf; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ color: #ff7733; font-size: 2.5em; }}
        .header .sub {{ color: #b3b1ad; margin-top: 5px; }}
        .header .author {{ color: #39bae6; margin-top: 3px; font-size: 0.9em; }}
        .summary {{ background: #14191f; border: 1px solid #2e3b4e; border-radius: 6px; padding: 20px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }}
        .stat {{ text-align: center; }}
        .stat .num {{ font-size: 2em; font-weight: bold; }}
        .stat .label {{ color: #b3b1ad; font-size: 0.85em; }}
        .stat .num.vuln {{ color: #ff3333; }}
        .stat .num.safe {{ color: #99cc66; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 12px 10px; border-bottom: 2px solid #2e3b4e; color: #b3b1ad; text-transform: uppercase; font-size: 0.85em; }}
        td {{ padding: 10px; border-bottom: 1px solid #1c2530; }}
        tr:hover {{ background: #14191f; }}
        .variant {{ color: #39bae6; font-weight: bold; }}
        .status {{ padding: 3px 8px; border-radius: 3px; font-weight: bold; font-size: 0.85em; }}
        .status.vuln {{ color: #ff3333; background: #2d1515; }}
        .status.safe {{ color: #99cc66; background: #1a2d1a; }}
        .detail {{ color: #b3b1ad; font-size: 0.85em; }}
        .detail-row td {{ padding: 2px 10px; border: none; }}
        .footer {{ text-align: center; margin-top: 40px; color: #5c6370; font-size: 0.85em; }}
        .footer a {{ color: #39bae6; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ghostroute</h1>
            <div class="sub">HTTP Request Smuggling Scan Report</div>
            <div class="author">Author: PwnedBytes0x1</div>
        </div>

        <div class="summary">
            <h3>Target: {}</h3>
            <div class="summary-grid">
                <div class="stat">
                    <div class="num">{}</div>
                    <div class="label">Total Probes</div>
                </div>
                <div class="stat">
                    <div class="num vuln">{}</div>
                    <div class="label">Vulnerable</div>
                </div>
                <div class="stat">
                    <div class="num safe">{}</div>
                    <div class="label">Not Vulnerable</div>
                </div>
                <div class="stat">
                    <div class="num">{}</div>
                    <div class="label">Errors</div>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Variant</th>
                    <th>Status</th>
                    <th>Server</th>
                    <th>Bypass</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <div class="footer">
            Generated by ghostroute v{} | {} UTC<br>
            <a href="https://github.com/PwnedBytes0x1/ghostroute">github.com/PwnedBytes0x1/ghostroute</a>
        </div>
    </div>
</body>
</html>"#,
            report.target,
            report.summary.total_variants,
            report.summary.vulnerable_count,
            report.summary.not_vulnerable_count,
            report.summary.errors,
            rows,
            report.version,
            report.timestamp,
        );

        Ok(html)
    }

    fn extension(&self) -> &'static str {
        "html"
    }
}
