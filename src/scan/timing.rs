use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;
use std::time::Instant;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    _silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    // Timing-based detection: send a request with a sleep/processing-time payload
    // in the smuggled prefix, measure response delay.
    // If significantly delayed, the smuggled content was processed.

    // Baseline timing
    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let start = Instant::now();
    let _baseline = h1::send_request(cfg, &baseline_req, auth).await?;
    let baseline_time = start.elapsed().as_millis();

    // Timing probe: send with a smuggled prefix that includes a sleep instruction
    // For blind smuggling, this uses a slow response or sleep in the backend.
    // We use a very large Content-Length that forces the backend to wait.

    let probe_body = b"x";
    let large_cl = 100_000u32;

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        host, large_cl
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
    let start_probe = Instant::now();
    conn.write_all(request.as_bytes()).await.ok();
    conn.write_all(probe_body).await.ok();

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

    let probe_time = start_probe.elapsed().as_millis();

    // If probe takes significantly longer than baseline (>2x), there may be blind smuggling
    let vulnerable = probe_time > baseline_time * 2 && probe_time > 500;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "timing".to_string(),
        vulnerable,
        server: None,
        bypass: None,
        status_code: 0,
        details: if vulnerable {
            Some(format!(
                "Timing-based: probe {}ms vs baseline {}ms (ratio: {:.1}x)",
                probe_time, baseline_time,
                probe_time as f64 / baseline_time.max(1) as f64
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
