use crate::net::{h2, NetConfig};
use crate::output::ScanResult;
use crate::auth::AuthStore;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    if !*silent {
        eprintln!("  [DBG] H2.CL probe: connecting with HTTP/2...");
    }

    let mut conn = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    // Baseline: normal H2 request
    let (baseline_status, _, baseline_body) = h2::send_h2_request(
        &mut conn.send_request,
        "GET",
        "/",
        &cfg.host,
        &auth_headers(auth),
        b"",
    ).await?;

    if !*silent {
        eprintln!("  [DBG] H2.CL baseline: {} ({} bytes)", baseline_status, baseline_body.len());
    }

    // Reconnect for smuggled probe
    let mut conn2 = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    // H2.CL: inject Content-Length in HEADERS frame (which H2 ignores, but downgrade may use it)
    let smuggled_headers = [(b"content-length" as &[u8], b"0" as &[u8]),
        (b"x-smuggled" as &[u8], b"1" as &[u8])];

    // Add auth headers
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
    let (probe_status, _, probe_body) = h2::send_h2_request_raw_headers(
        &mut conn2.send_request,
        &pseudo,
        &extra_refs,
        b"",
        &cfg.host,
    ).await?;

    let vulnerable = !probe_body.is_empty() || probe_status == 413;

    let host_name = &cfg.host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "h2cl".to_string(),
        vulnerable,
        server: None,
        bypass: None,
        status_code: probe_status,
        details: if vulnerable {
            Some(format!("H2.CL: CL injection caused status {} vs baseline {}", probe_status, baseline_status))
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
