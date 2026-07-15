use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

pub struct FuzzProbe {
    pub name: String,
    pub header: String,
    pub value: String,
    pub body: String,
}

pub fn generate_fuzz_probes() -> Vec<FuzzProbe> {
    let mut probes = Vec::new();

    // CL variants
    for cl in &[0u32, 1, 5, 10, 100, 1000, 99999] {
        probes.push(FuzzProbe {
            name: format!("cl-{}", cl),
            header: "Content-Length".into(),
            value: cl.to_string(),
            body: "x".repeat(std::cmp::min(*cl as usize, 100)),
        });
    }

    // TE variants
    for te in &["chunked", "Chunked", "CHUNKED", " chunked", "chunked "] {
        probes.push(FuzzProbe {
            name: format!("te-{}", te.replace(' ', "_")),
            header: "Transfer-Encoding".into(),
            value: te.to_string(),
            body: "1\r\nx\r\n0\r\n\r\n".into(),
        });
    }

    // Duplicate headers
    probes.push(FuzzProbe {
        name: "double-cl".into(),
        header: "Content-Length".into(),
        value: "5\r\nContent-Length: 10".into(),
        body: "hello".into(),
    });

    probes.push(FuzzProbe {
        name: "cl-te-both".into(),
        header: "Content-Length".into(),
        value: "5\r\nTransfer-Encoding: chunked".into(),
        body: "hello".into(),
    });

    // Whitespace variants
    for (name, conn_val) in &[("conn-close", "close"), ("conn-ka", "keep-alive"), ("conn-upgrade", "upgrade")] {
        probes.push(FuzzProbe {
            name: name.to_string(),
            header: "Connection".into(),
            value: conn_val.to_string(),
            body: String::new(),
        });
    }

    probes
}

pub async fn run_fuzz(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<Vec<ScanResult>, String> {
    let baseline_req = h1::build_request("GET", "/", &cfg.host, &[], b"");
    let _baseline = h1::send_request(cfg, &baseline_req, auth).await?;
    let mut results = Vec::new();
    let probes = generate_fuzz_probes();

    for (i, probe) in probes.iter().enumerate() {
        if !*silent {
            eprintln!("  [DBG] Fuzz probe {}/{}: {}", i + 1, probes.len(), probe.name);
        }

        if !probe.body.is_empty() {
            // Body-based probe
            if probe.header == "Content-Length" {
                let request = format!(
                    "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nUser-Agent: ghostroute/{}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
                    cfg.host, probe.value, env!("CARGO_PKG_VERSION"), probe.body
                );
                match h1::send_request(cfg, request.as_bytes(), auth).await {
                    Ok(resp) => {
                        let anomalous = resp.status_code >= 500 || resp.status_code == 0;
                        results.push(ScanResult {
                            host: cfg.host.clone(),
                            port: cfg.port,
                            variant: format!("fuzz-{}", probe.name),
                            vulnerable: anomalous,
                            server: resp.server.clone(),
                            bypass: None,
                            status_code: resp.status_code,
                            details: if anomalous {
                                Some(format!("Fuzz anomaly: {} returned {}", probe.name, resp.status_code))
                            } else {
                                None
                            },
                            ..Default::default()
                        });
                    }
                    Err(e) => {
                        results.push(ScanResult {
                            host: cfg.host.clone(),
                            port: cfg.port,
                            variant: format!("fuzz-{}", probe.name),
                            vulnerable: true,
                            server: None,
                            bypass: None,
                            status_code: 0,
                            details: Some(format!("Fuzz error: {}", e)),
                            ..Default::default()
                        });
                    }
                }
            }
        } else {
            let headers = vec![(&probe.header[..], &probe.value[..])];
            let request = h1::build_request("GET", "/", &cfg.host, &headers, b"");
            match h1::send_request(cfg, &request, auth).await {
                Ok(resp) => {
                    results.push(ScanResult {
                        host: cfg.host.clone(),
                        port: cfg.port,
                        variant: format!("fuzz-{}", probe.name),
                        vulnerable: resp.status_code >= 500 || resp.status_code == 0,
                        server: resp.server.clone(),
                        bypass: None,
                        status_code: resp.status_code,
                        details: None,
                        ..Default::default()
                    });
                }
                Err(e) => {
                    results.push(ScanResult {
                        host: cfg.host.clone(),
                        port: cfg.port,
                        variant: format!("fuzz-{}", probe.name),
                        vulnerable: true,
                        server: None,
                        bypass: None,
                        status_code: 0,
                        details: Some(format!("Fuzz error: {}", e)),
                        ..Default::default()
                    });
                }
            }
        }
    }

    Ok(results)
}
