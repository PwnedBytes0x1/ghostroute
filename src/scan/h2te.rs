use crate::net::{h2, NetConfig};
use crate::output::ScanResult;
use crate::auth::AuthStore;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    if !*silent {
        eprintln!("  [DBG] H2.TE probe: connecting with HTTP/2...");
    }

    let mut conn = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    let (baseline_status, _, _) = h2::send_h2_request(
        &mut conn.send_request,
        "GET",
        "/",
        &cfg.host,
        &auth_headers(auth),
        b"",
    ).await?;

    if !*silent {
        eprintln!("  [DBG] H2.TE baseline: {}", baseline_status);
    }

    let mut conn2 = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    // H2.TE: inject Transfer-Encoding in HEADERS frame
    let smuggled_headers = [(b"transfer-encoding" as &[u8], b"chunked" as &[u8])];

    let pseudo = vec![
        (":method", "GET"),
        (":path", "/"),
        (":scheme", if cfg.tls { "https" } else { "http" }),
        (":authority", &cfg.host),
    ];
    let mut extra: Vec<(Vec<u8>, Vec<u8>)> = smuggled_headers.iter()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    if let Some(a) = auth {
        for (k, v) in a.to_headers_vec() {
            extra.push((k.into_bytes(), v.into_bytes()));
        }
    }

    let extra_refs: Vec<(&[u8], &[u8])> = extra.iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let (probe_status, _, _probe_body) = h2::send_h2_request_raw_headers(
        &mut conn2.send_request,
        &pseudo,
        &extra_refs,
        b"0\r\n\r\n",
        &cfg.host,
    ).await?;

    let vulnerable = probe_status == 413 || probe_status == 400;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "h2te".to_string(),
        vulnerable,
        server: None,
        bypass: None,
        status_code: probe_status,
        details: if vulnerable {
            Some(format!("H2.TE: TE injection triggered status {} (may indicate smuggled parsing)", probe_status))
        } else {
            None
        },
        ..Default::default()
    })
}

fn auth_headers(auth: Option<&AuthStore>) -> Vec<(String, String)> {
    match auth {
        Some(a) => a.to_headers_vec(),
        None => Vec::new(),
    }
}
