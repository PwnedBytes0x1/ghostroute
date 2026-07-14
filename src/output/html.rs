use super::{OutputFormatter, ScanReport};

fn variant_impact(variant: &str) -> &'static str {
    match variant.to_uppercase().as_str() {
        "CLTE" | "CL.TE" => "Front-end uses Content-Length, back-end uses Transfer-Encoding. Attacker can smuggle requests past front-end access controls, poison response queues, and hijack user sessions.",
        "TECL" | "TE.CL" => "Front-end uses Transfer-Encoding, back-end uses Content-Length. Allows request splitting, cache poisoning, and session hijacking by exploiting the header priority mismatch.",
        "TETE" | "TE.TE" => "Both front-end and back-end use Transfer-Encoding but parse it differently. An obfuscated TE header can cause one server to ignore it, enabling desync.",
        "CL0" | "CL.0" => "Front-end consumes the Content-Length body, back-end ignores it. The back-end treats the next pipelined request as part of the body, causing desync. (CVE-2019-20372)",
        "0CL" | "0.CL" => "Back-end reads Content-Length but front-end doesn't. The front-end forwards only the headers, and the back-end waits for a body that never arrives, desyncing the connection.",
        "H2CL" | "H2.CL" => "HTTP/2 request is downgraded to HTTP/1.1 by the front-end, which adds Content-Length. The back-end processes both H2 framing and the injected CL header, causing desync.",
        "H2TE" | "H2.TE" => "HTTP/2 downgrade adds Transfer-Encoding header. The back-end parses TE while the front-end uses H2 framing, creating a parser mismatch.",
        "TE0" | "TE.0" => "Null-byte injection in Transfer-Encoding header causes one parser to see TE while the other ignores it.",
        "WEBSOCKET" => "WebSocket upgrade request is smuggled inside another connection. The back-end interprets the smuggled data as a WebSocket connection, bypassing front-end controls.",
        "CHUNK-EXT" | "CHUNK EXT" => "Chunked encoding extension abuse (CVE-2025-55315). Different parsers interpret chunk extensions differently, leading to desync.",
        "EXPECT100" => "100-Continue expectation causes the front-end to hold the request while the back-end processes it, creating a timing-based desync window.",
        "TIMING" => "Response delay differential detects blind smuggling by measuring processing time differences between normal and smuggled requests.",
        "CLIENT-DESYNC" | "CLIENT DESYNC" => "Browser-server parser mismatch allows an attacker to poison the browser's connection to a vulnerable server (CL.0 variant targeting client-side proxies).",
        "CONNECTION-STATE" | "CONNECTION STATE" => "Connection state desync uses status/reflect/DNS canary comparison to detect parser state mismatches across connections.",
        "PAUSE-DESYNC" | "PAUSE DESYNC" => "Pause-based desync introduces a 61-second delay between prefix and victim requests, exploiting timeout-based parser divergence.",
        "HEADER-REMOVAL" | "HEADER REMOVAL" => "Header removal detection injects Keep-Alive headers with 5x repeat to detect connection eviction and header stripping.",
        "CONTAMINATION" => "HEAD request pollution with 3x stability check reveals connection contamination from previous smuggled requests.",
        "H2-DUAL-PATH" | "H2 DUAL PATH" => "Dual `:path` pseudo-header injection causes the front-end and back-end to disagree on the request target.",
        "H2-FAKE-PSEUDO" | "H2 FAKE PSEUDO" => "Fake pseudo-header reflection detects when the back-end echoes unrecognized pseudo-headers back in the response.",
        "PARSER-DISCREPANCY" | "PARSER DISCREPANCY" => "4-way canary permutation classifies parser discrepancies as Split or Nuke, identifying which headers cause desync.",
        _ => "HTTP request smuggling vulnerability detected. An attacker can potentially bypass security controls, poison caches, and hijack user sessions.",
    }
}

fn variant_references(variant: &str) -> Vec<(&'static str, &'static str)> {
    let v = variant.to_uppercase();
    let mut refs = Vec::new();
    refs.push(("PortSwigger Research", "https://portswigger.net/research/http-request-smuggling"));
    refs.push(("PortSwigger in 2025", "https://portswigger.net/research/http-request-smuggling-in-2025"));
    match v.as_str() {
        "CLTE" | "CL.TE" | "TECL" | "TE.CL" | "TETE" | "TE.TE" => {
            refs.push(("CVE-2019-20372", "https://nvd.nist.gov/vuln/detail/CVE-2019-20372"));
        }
        "CL0" | "CL.0" => {
            refs.push(("CVE-2019-20372", "https://nvd.nist.gov/vuln/detail/CVE-2019-20372"));
        }
        "H2CL" | "H2.CL" | "H2TE" | "H2.TE" => {
            refs.push(("CVE-2021-33104", "https://nvd.nist.gov/vuln/detail/CVE-2021-33104"));
        }
        "CHUNK-EXT" | "CHUNK EXT" => {
            refs.push(("CVE-2025-55315", "https://nvd.nist.gov/vuln/detail/CVE-2025-55315"));
        }
        _ => {}
    }
    refs
}

fn sample_poc_request(variant: &str, host: &str) -> String {
    let v = variant.to_uppercase();
    let h = host;
    match v.as_str() {
        "CLTE" | "CL.TE" => format!(
            "POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
        "TECL" | "TE.CL" => format!(
            "POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: localhost\r\n\r\n0\r\n\r\n"
        ),
        "TETE" | "TE.TE" => format!(
            "POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
        "CL0" | "CL.0" => format!(
            "POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 43\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
        "0CL" | "0.CL" => format!(
            "POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nContent-Length: 100\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
        _ => format!(
            "GET / HTTP/1.1\r\nHost: {h}\r\n\r\n"
        ),
    }
}

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
                    <td><span class="host">{h}:{p}</span></td>
                    <td><span class="variant">{v}</span></td>
                    <td><span class="status {sc}">{st}</span></td>
                    <td>{s}</td>
                    <td>{b}</td>
                </tr>"#,
                h = r.host, p = r.port,
                v = r.variant.to_uppercase(),
                sc = status_class, st = status_text,
                s = server, b = bypass,
            ));

            if r.vulnerable {
                let impact = variant_impact(&r.variant);
                let refs = variant_references(&r.variant);
                let generated_poc = sample_poc_request(&r.variant, &r.host);
                let poc_req = r.poc_request.as_deref().unwrap_or(&generated_poc);
                let poc_resp = r.poc_response.as_deref().unwrap_or("(see details)");

                let refs_html: String = refs.iter().map(|(name, url)| {
                    format!(r#"<a href="{url}" target="_blank">{name}</a>"#, url = url, name = name)
                }).collect::<Vec<_>>().join(" &middot; ");

                rows.push_str(&format!(
                    r#"<tr class="vuln-details" data-variant="{v}">
                        <td colspan="5">
                            <details class="vuln-card" open>
                                <summary><span class="vuln-summary">🔍 {v} — {st}</span></summary>
                                <div class="card-body">
                                    <div class="card-section">
                                        <h4>Impact</h4>
                                        <p>{impact}</p>
                                    </div>
                                    <div class="card-section">
                                        <h4>PoC Request</h4>
                                        <pre class="code-block"><code>{req_esc}</code></pre>
                                    </div>
                                    <div class="card-section">
                                        <h4>Response</h4>
                                        <pre class="code-block"><code>{resp_esc}</code></pre>
                                    </div>"#,
                    v = r.variant.to_uppercase(),
                    st = status_text,
                    impact = impact,
                    req_esc = escape_html(poc_req),
                    resp_esc = escape_html(poc_resp),
                ));

                if let Some(ref det) = r.details {
                    rows.push_str(&format!(
                        r#"<div class="card-section"><h4>Details</h4><p>{det}</p></div>"#,
                        det = escape_html(det),
                    ));
                }

                if let Some(ref outcome) = r.outcome {
                    rows.push_str(&format!(
                        r#"<div class="card-section"><h4>Outcome</h4><p>{o}</p></div>"#,
                        o = escape_html(outcome),
                    ));
                }

                if !r.cve_matches.is_empty() {
                    rows.push_str(&format!(
                        r#"<div class="card-section"><h4>CVE Matches</h4><p>{cves}</p></div>"#,
                        cves = r.cve_matches.join(", "),
                    ));
                }

                if !refs.is_empty() {
                    rows.push_str(&format!(
                        r#"<div class="card-section"><h4>References</h4><p>{refs_html}</p></div>"#,
                        refs_html = refs_html,
                    ));
                }

                rows.push_str(
                    r#"              </div>
                            </details>
                        </td>
                    </tr>"#
                );
            }
        }

        let html = format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ghostroute — Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background: #0a0e14; color: #e6e1cf; padding: 20px; }}
        .container {{ max-width: 1280px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .header h1 {{ color: #ff7733; font-size: clamp(1.5rem, 5vw, 2.5rem); }}
        .header .sub {{ color: #b3b1ad; margin-top: 5px; font-size: clamp(0.8rem, 2.5vw, 1rem); }}
        .header .author {{ color: #39bae6; margin-top: 3px; font-size: 0.85em; }}
        .summary {{ background: #14191f; border: 1px solid #2e3b4e; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .summary h3 {{ font-size: clamp(1rem, 3vw, 1.3rem); word-break: break-all; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-top: 15px; }}
        .stat {{ text-align: center; padding: 10px 5px; }}
        .stat .num {{ font-size: clamp(1.5rem, 4vw, 2em); font-weight: bold; }}
        .stat .label {{ color: #b3b1ad; font-size: clamp(0.7rem, 2vw, 0.85em); }}
        .stat .num.vuln {{ color: #ff3333; }}
        .stat .num.safe {{ color: #99cc66; }}
        .table-wrap {{ overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 20px; }}
        table {{ width: 100%; min-width: 600px; border-collapse: collapse; font-size: clamp(0.75rem, 2vw, 0.9rem); }}
        th {{ text-align: left; padding: 12px 8px; border-bottom: 2px solid #2e3b4e; color: #b3b1ad; text-transform: uppercase; font-size: clamp(0.7rem, 1.8vw, 0.8em); white-space: nowrap; }}
        td {{ padding: 10px 8px; border-bottom: 1px solid #1c2530; }}
        tr:hover {{ background: #14191f; }}
        .host {{ word-break: break-all; }}
        .variant {{ color: #39bae6; font-weight: bold; }}
        .status {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: clamp(0.65rem, 1.5vw, 0.8em); display: inline-block; white-space: nowrap; }}
        .status.vuln {{ color: #ff3333; background: #2d1515; }}
        .status.safe {{ color: #5c6370; background: #14191f; }}
        .vuln-card {{ background: #14191f; border: 1px solid #2e3b4e; border-radius: 8px; margin: 8px 0; padding: 0; }}
        .vuln-card[open] {{ border-color: #ff333366; }}
        .vuln-summary {{ font-weight: bold; color: #ff7733; cursor: pointer; padding: 12px; display: block; font-size: clamp(0.8rem, 2vw, 0.95rem); }}
        .vuln-summary:hover {{ background: #1c2530; border-radius: 8px; }}
        .card-body {{ padding: 0 12px 12px; }}
        .card-section {{ margin-bottom: 14px; }}
        .card-section h4 {{ color: #39bae6; font-size: clamp(0.75rem, 1.8vw, 0.85rem); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }}
        .card-section p {{ color: #b3b1ad; font-size: clamp(0.75rem, 1.8vw, 0.85rem); line-height: 1.5; }}
        .card-section a {{ color: #58a6ff; text-decoration: none; }}
        .card-section a:hover {{ text-decoration: underline; }}
        .code-block {{ background: #0a0e14; border: 1px solid #1c2530; border-radius: 6px; padding: 12px; overflow-x: auto; font-size: clamp(0.6rem, 1.5vw, 0.75rem); line-height: 1.4; }}
        .code-block code {{ white-space: pre; font-family: 'Courier New', Courier, monospace; color: #e6e1cf; }}
        .footer {{ text-align: center; margin-top: 40px; color: #5c6370; font-size: clamp(0.7rem, 1.8vw, 0.85em); }}
        .footer a {{ color: #39bae6; text-decoration: none; }}
        @media (max-width: 600px) {{
            body {{ padding: 10px; }}
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); gap: 8px; }}
            .summary {{ padding: 12px; }}
            th, td {{ padding: 8px 4px; }}
            .status {{ padding: 2px 5px; }}
            .code-block {{ padding: 8px; }}
        }}
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
            <h3>Target: {target}</h3>
            <div class="summary-grid">
                <div class="stat">
                    <div class="num">{total}</div>
                    <div class="label">Total Probes</div>
                </div>
                <div class="stat">
                    <div class="num vuln">{vuln}</div>
                    <div class="label">Vulnerable</div>
                </div>
                <div class="stat">
                    <div class="num safe">{safe}</div>
                    <div class="label">Not Vulnerable</div>
                </div>
                <div class="stat">
                    <div class="num">{errs}</div>
                    <div class="label">Errors</div>
                </div>
            </div>
        </div>

        <div class="table-wrap">
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
                    {rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by ghostroute v{ver} | {ts} UTC<br>
            <a href="https://github.com/PwnedBytes0x1/ghostroute">github.com/PwnedBytes0x1/ghostroute</a>
        </div>
    </div>
</body>
</html>"##,
            target = report.target,
            total = report.summary.total_variants,
            vuln = report.summary.vulnerable_count,
            safe = report.summary.not_vulnerable_count,
            errs = report.summary.errors,
            rows = rows,
            ver = report.version,
            ts = report.timestamp,
        );

        Ok(html)
    }

    fn extension(&self) -> &'static str {
        "html"
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
