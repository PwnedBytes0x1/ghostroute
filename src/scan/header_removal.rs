use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("Header removal detection probe");
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let _baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let mut conn = crate::net::connect(cfg).await?;

    let _test_headers = [
        ("Keep-Alive", "timeout=5, max=1000"),
        ("X-Custom-ID", "ghostroute-probe"),
    ];

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\nX-Custom-ID: ghostroute-probe\r\nUser-Agent: ghostroute/{}\r\nAccept: */*\r\n\r\n",
        host, env!("CARGO_PKG_VERSION")
    );
    let mut req_bytes = request.into_bytes();
    if let Some(a) = auth {
        a.apply_to_request(&mut req_bytes);
    }

    conn.write_all(&req_bytes).await.map_err(|e| format!("Header removal write: {}", e))?;

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

    let first_resp = match h1::parse_response(&buf) {
        Ok(r) => r,
        Err(_) => return Err("Failed to parse first response".into()),
    };

    let keep_alive_removed = !first_resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("keep-alive"));

    let custom_header_reflected = first_resp
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-custom-id") || v.contains("ghostroute-probe"));

    if !*silent {
        if keep_alive_removed {
            crate::print_dbg("Keep-Alive header stripped by front-end");
        }
        if custom_header_reflected {
            crate::print_dbg("Custom probe header reflected in response");
        }
    }

    for i in 0..5 {
        let repeat_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&repeat_req).await.ok();

        let mut buf_r = Vec::with_capacity(4096);
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf_r.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf_r.len() > 1_000_000 {
                break;
            }
        }
        if buf_r.is_empty() {
            if !*silent {
                crate::print_warn(&format!("Connection closed after {} repeat requests (connection eviction)", i + 1));
            }
            let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
            return Ok(ScanResult {
                host: host_name.to_string(),
                port: cfg.port,
                variant: "header-removal".to_string(),
                vulnerable: true,
                server: None,
                bypass: Some("connection-eviction".into()),
                status_code: 0,
                details: Some(format!("Header removal detected: connection evicted after {} repeat requests (Keep-Alive stripped)", i + 1)),
                ..Default::default()
            });
        }
    }

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "header-removal".to_string(),
        vulnerable: keep_alive_removed || custom_header_reflected,
        server: first_resp.server.clone(),
        bypass: if keep_alive_removed {
            Some("keep-alive-stripped".into())
        } else if custom_header_reflected {
            Some("header-reflection".into())
        } else {
            None
        },
        status_code: first_resp.status_code,
        details: if keep_alive_removed || custom_header_reflected {
            let mut parts = Vec::new();
            if keep_alive_removed {
                parts.push("Keep-Alive header stripped by front-end");
            }
            if custom_header_reflected {
                parts.push("Custom header reflected in response");
            }
            Some(parts.join("; "))
        } else {
            Some("No header removal detected".into())
        },
        ..Default::default()
    })
}
