use crate::net::{h2, NetConfig};
use crate::output::ScanResult;
use crate::auth::AuthStore;

const FAKE_PSEUDOS: &[(&str, &str)] = &[
    (":x-foo", "bar"),
    (":x-proxy", "inject"),
    (":internal", "true"),
    (":x-original-url", "/admin"),
    (":x-forwarded", "injected"),
];

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    if !*silent {
        crate::print_dbg("H2 fake pseudo-header reflection probe");
    }

    let mut conn = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    let (baseline_status, _baseline_headers, _baseline_body) = h2::send_h2_request(
        &mut conn.send_request,
        "GET",
        "/",
        &cfg.host,
        &auth_headers(auth),
        b"",
    ).await?;

    let mut conn2 = h2::h2_connect(&cfg.host, cfg.port, cfg.tls, cfg.timeout.as_secs()).await?;

    let mut vulnerable = false;
    let mut reflected_pseudo: Option<String> = None;
    let mut response_status: u16 = 0;

    for (pseudo_name, pseudo_val) in FAKE_PSEUDOS {
        let pseudo = vec![
            (":method", "GET"),
            (":path", "/"),
            (":scheme", if cfg.tls { "https" } else { "http" }),
            (":authority", &cfg.host),
            (pseudo_name, pseudo_val),
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
            Ok((status, headers, _body)) => {
                response_status = status;

                let any_reflected = headers.iter().any(|(k, v)| {
                    k.contains(pseudo_name.trim_start_matches(':'))
                        || v.contains(pseudo_val)
                        || v.contains("x-foo")
                        || v.contains("x-proxy")
                });

                if any_reflected {
                    vulnerable = true;
                    reflected_pseudo = Some(pseudo_name.to_string());
                    if !*silent {
                        crate::print_det(&format!(
                            "H2 fake pseudo-header reflected: {} (value: {})",
                            pseudo_name, pseudo_val
                        ));
                    }
                    break;
                }

                if status != baseline_status && status > 0 {
                    vulnerable = true;
                    reflected_pseudo = Some(format!("{} (status diff)", pseudo_name));
                    if !*silent {
                        crate::print_det(&format!(
                            "H2 fake pseudo-header caused status change: {} -> {} (baseline {})",
                            pseudo_name, status, baseline_status
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
        variant: "h2-fake-pseudo".to_string(),
        vulnerable,
        server: None,
        bypass: reflected_pseudo,
        status_code: response_status,
        details: if vulnerable {
            Some("H2 fake pseudo-header: server processed non-standard pseudo-header".into())
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
