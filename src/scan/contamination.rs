use std::time::Duration;

use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::output::ScanResult;

#[derive(Debug, Clone)]
pub struct ContaminationResult {
    pub clean: bool,
    pub head_pollution_detected: bool,
    pub stability_violations: u32,
    #[allow(dead_code)]
    pub details: Vec<String>,
}

pub async fn run_contamination_check(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    variant: &str,
    silent: &bool,
) -> Result<ContaminationResult, String> {
    let host = &cfg.host;
    let mut details: Vec<String> = Vec::new();
    let mut violations = 0u32;

    if !*silent {
        crate::print_dbg(&format!("Contamination check for {}: HEAD pollution test", variant));
    }

    let head_req = h1::build_request("HEAD", "/", host, &[], b"");
    let mut resp = h1::send_request(cfg, &head_req, auth).await?;
    let head_status = resp.status_code;

    let polluted = matches!(head_status, 0 | 403 | 406 | 429 | 503);

    if polluted {
        details.push(format!(
            "HEAD pollution detected: status {} (contaminated connection)",
            head_status
        ));
        if !*silent {
            crate::print_warn("HEAD pollution: connection state contaminated");
        }
    } else {
        details.push(format!("HEAD pollution clean: status {}", head_status));
    }

    if !*silent {
        crate::print_dbg(&format!(
            "Contamination check for {}: stability test (3x repeat)",
            variant
        ));
    }

    let baseline_status = resp.status_code;

    for i in 0..3 {
        let test_req = h1::build_request("GET", "/", host, &[], b"");
        resp = h1::send_request(cfg, &test_req, auth).await?;

        if resp.status_code != baseline_status && resp.status_code > 0 {
            violations += 1;
            details.push(format!(
                "Stability violation #{}: expected {} got {}",
                i + 1,
                baseline_status,
                resp.status_code
            ));
        }

        if i < 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let clean = !polluted && violations == 0;

    if !*silent {
        if clean {
            crate::print_det("Contamination check passed");
        } else {
            crate::print_warn(&format!(
                "Contamination check: {} violations, {}",
                violations,
                if polluted { "HEAD polluted" } else { "HEAD clean" }
            ));
        }
    }

    Ok(ContaminationResult {
        clean,
        head_pollution_detected: polluted,
        stability_violations: violations,
        details,
    })
}

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let result = run_contamination_check(cfg, auth, "contamination", silent).await?;

    let host_name = cfg.host.split(':').next().unwrap_or(&cfg.host);

    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "contamination".to_string(),
        vulnerable: !result.clean,
        server: None,
        bypass: None,
        status_code: 0,
        details: Some(if result.clean {
            "Contamination check passed: connection state stable".into()
        } else {
            format!(
                "Contamination detected: {} stability violations, HEAD polluted: {}",
                result.stability_violations,
                result.head_pollution_detected
            )
        }),
        ..Default::default()
    })
}

#[allow(dead_code)]
pub async fn validate_desync(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    variant: &str,
    silent: &bool,
) -> bool {
    match run_contamination_check(cfg, auth, variant, silent).await {
        Ok(result) => {
            if !result.clean && !*silent {
                crate::print_warn(&format!(
                    "Desync validation failed for {}: contamination detected",
                    variant
                ));
            }
            result.clean
        }
        Err(e) => {
            if !*silent {
                crate::print_warn(&format!(
                    "Contamination check error for {}: {}",
                    variant, e
                ));
            }
            false
        }
    }
}
