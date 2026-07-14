use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

const CANARY_PATHS: &[(&str, &str)] = &[
    ("status", "/hopefully404"),
    ("reflect", "/?reflect=ghostroute_probe"),
    ("dns", "http://ghostroute-pingback.oastify.com/probe"),
];

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("Connection state attack probe");
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let mut success_canary: Option<String> = None;
    let mut response_status: u16 = 0;
    let mut vulnerable = false;

    for (canary, target_path) in CANARY_PATHS {
        if !*silent {
            crate::print_dbg(&format!("Connection state canary: {} ({})", canary, target_path));
        }

        let mut conn = crate::net::connect(cfg).await?;

        let get_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&get_req).await.ok();

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
        let _first = h1::parse_response(&buf).ok();

        let smuggled = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ghostroute/1.0.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
            target_path, host
        );
        conn.write_all(smuggled.as_bytes()).await.ok();

        let third_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&third_req).await.ok();

        let mut buf3 = Vec::with_capacity(4096);
        loop {
            match timeout(cfg.timeout, conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf3.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf3.len() > 1_000_000 {
                break;
            }
        }

        let responses_raw = String::from_utf8_lossy(&buf3);

        match canary {
            &"status" => {
                if let Ok(resp) = h1::parse_response(&buf3) {
                    response_status = resp.status_code;
                    if resp.status_code > 0 && resp.status_code != baseline.status_code {
                        vulnerable = true;
                        success_canary = Some("status".into());
                        if !*silent {
                            crate::print_det(&format!(
                                "Connection state: status canary triggered ({} vs baseline {})",
                                resp.status_code, baseline.status_code
                            ));
                        }
                    }
                }
            }
            &"reflect" => {
                if responses_raw.contains("reflect") || responses_raw.contains(&"ghostroute_probe") {
                    vulnerable = true;
                    success_canary = Some("reflect".into());
                    response_status = 200;
                    if !*silent {
                        crate::print_det("Connection state: reflect canary triggered (probe value in response)");
                    }
                }
            }
            &"dns" => {
                if responses_raw.len() > 100 {
                    vulnerable = true;
                    success_canary = Some("dns".into());
                    response_status = 200;
                    if !*silent {
                        crate::print_det("Connection state: DNS canary triggered (non-empty response to external URL)");
                    }
                }
            }
            _ => {}
        }

        if vulnerable {
            break;
        }
    }

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "connection-state".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: success_canary,
        status_code: response_status,
        details: if vulnerable {
            Some("Connection state desync: canary request leaked into subsequent connection".into())
        } else {
            None
        },
        ..Default::default()
    })
}
