use crate::auth::AuthStore;
use crate::detect::parser_discrepancy::{run_discrepancy_check, variant_from_discrepancies, PermutationOutcome, DiscrepancyResult};
use crate::net::NetConfig;
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        crate::print_dbg("Parser discrepancy engine: testing 4 header permutations");
    }

    let header_pairs = [
        ("content-length", "5", "transfer-encoding", "chunked"),
        ("transfer-encoding", "chunked", "content-length", "5"),
        ("transfer-encoding", "chunked", "transfer-encoding", "identity"),
        ("content-length", "5", "content-length", "10"),
    ];

    let mut results: Vec<DiscrepancyResult> = Vec::new();

    for (hidden, hidden_val, canary, canary_val) in &header_pairs {
        let r = run_discrepancy_check(
            cfg, host,
            hidden, hidden_val,
            canary, canary_val,
            "/404",
            auth,
        ).await;

        if !*silent {
            let outcome_str = match r.outcome {
                PermutationOutcome::Match => "match",
                PermutationOutcome::Discrepancy => "DISCREPANCY",
                PermutationOutcome::HighDiscrepancy => "HIGH_DISCREPANCY",
                PermutationOutcome::WafBlock => "WAF_BLOCK",
                PermutationOutcome::Error => "error",
                PermutationOutcome::Timeout => "timeout",
            };
            crate::print_dbg(&format!(
                "  {} {} {}: {} → {}",
                hidden, canary, outcome_str,
                r.hidden_present_canary_present.map_or(0, |v| v),
                r.hidden_missing_canary_missing.map_or(0, |v| v),
            ));
        }

        results.push(r);
    }

    let sum_outcome = |o: PermutationOutcome| results.iter().filter(|r| r.outcome == o).count();

    let any_discrepancy = sum_outcome(PermutationOutcome::Discrepancy) > 0
        || sum_outcome(PermutationOutcome::HighDiscrepancy) > 0;
    let waf_blocked = sum_outcome(PermutationOutcome::WafBlock) > 0;

    let detected_variant = variant_from_discrepancies(&results);

    let details = if let Some((variant, s_or_n)) = &detected_variant {
        Some(format!(
            "Parser discrepancy: {}/{} pairs show discrepancy → {} ({})",
            sum_outcome(PermutationOutcome::Discrepancy) + sum_outcome(PermutationOutcome::HighDiscrepancy),
            results.len(),
            variant.to_uppercase(),
            s_or_n,
        ))
    } else if waf_blocked {
        Some("Parser discrepancy: WAF blocked all or some permutation probes".into())
    } else {
        Some(format!(
            "Parser discrepancy: no variance detected across {} header pairs",
            results.len(),
        ))
    };

    let bypass_str = detected_variant.as_ref().map(|(v, s)| format!("{}/{}", v, s));

    let mut result = ScanResult {
        host: host.to_string(),
        port: cfg.port,
        variant: "parser-discrepancy".to_string(),
        vulnerable: any_discrepancy,
        server: None,
        bypass: bypass_str.clone(),
        status_code: if any_discrepancy { 200 } else { 0 },
        details,
        ..Default::default()
    };

    if any_discrepancy {
        result.outcome = Some("DISCREPANCY".to_string());
        if let Some(bypass_val) = &bypass_str {
            result.cve_matches.push(format!("variant={}", bypass_val));
        }
    }
    if waf_blocked {
        result.waf_detected = Some("blocked".to_string());
    }

    Ok(result)
}
