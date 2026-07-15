use crate::auth::AuthStore;
use crate::net::{h1, NetConfig};
use crate::net::h1::RawResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PermutationOutcome {
    Match,
    Discrepancy,
    HighDiscrepancy,
    WafBlock,
    Error,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SplitOrNuke {
    Split,
    Nuke,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscrepancyResult {
    pub hidden_header: String,
    pub canary_header: String,
    pub outcome: PermutationOutcome,
    pub split_or_nuke: SplitOrNuke,
    pub hidden_present_canary_present: Option<u16>,
    pub hidden_missing_canary_present: Option<u16>,
    pub hidden_present_canary_missing: Option<u16>,
    pub hidden_missing_canary_missing: Option<u16>,
}

fn status_class(code: u16) -> &'static str {
    match code {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

async fn send_with_classification(
    cfg: &NetConfig,
    request: &[u8],
    auth: Option<&AuthStore>,
) -> (PermutationOutcome, Option<RawResponse>) {
    use std::time::Duration;
    use tokio::time::timeout;

    match timeout(Duration::from_secs(cfg.timeout.as_secs().max(5)), h1::send_request(cfg, request, auth)).await {
        Ok(Ok(resp)) => {
            if resp.status_code == 403 || resp.status_code == 406 || resp.status_code == 493 {
                (PermutationOutcome::Error, Some(resp))
            } else {
                (PermutationOutcome::Match, Some(resp))
            }
        }
        Ok(Err(_)) => (PermutationOutcome::Error, None),
        Err(_) => (PermutationOutcome::Timeout, None),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_discrepancy_check(
    cfg: &NetConfig,
    host: &str,
    hidden_header: &str,
    hidden_value: &str,
    canary_header: &str,
    canary_value: &str,
    target_path: &str,
    auth: Option<&AuthStore>,
) -> DiscrepancyResult {
    let build_req = |hidden_present: bool, canary_present: bool| -> Vec<u8> {
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if hidden_present {
            headers.push((hidden_header, hidden_value));
        }
        if canary_present {
            headers.push((canary_header, canary_value));
        }
        h1::build_request("GET", target_path, host, &headers, b"")
    };

    let req_pp = build_req(true, true);
    let req_mp = build_req(false, true);
    let req_pm = build_req(true, false);
    let req_mm = build_req(false, false);

    let (outcome_pp, resp_pp) = send_with_classification(cfg, &req_pp, auth).await;
    let (outcome_mp, resp_mp) = send_with_classification(cfg, &req_mp, auth).await;
    let (outcome_pm, resp_pm) = send_with_classification(cfg, &req_pm, auth).await;
    let (outcome_mm, resp_mm) = send_with_classification(cfg, &req_mm, auth).await;

    let status_pp = resp_pp.as_ref().map(|r| r.status_code);
    let status_mp = resp_mp.as_ref().map(|r| r.status_code);
    let status_pm = resp_pm.as_ref().map(|r| r.status_code);
    let status_mm = resp_mm.as_ref().map(|r| r.status_code);

    let has_waf = matches!(outcome_pp, PermutationOutcome::WafBlock)
        || matches!(outcome_mp, PermutationOutcome::WafBlock)
        || matches!(outcome_pm, PermutationOutcome::WafBlock)
        || matches!(outcome_mm, PermutationOutcome::WafBlock);

    let has_error = matches!(outcome_pp, PermutationOutcome::Error | PermutationOutcome::Timeout)
        || matches!(outcome_mp, PermutationOutcome::Error | PermutationOutcome::Timeout)
        || matches!(outcome_pm, PermutationOutcome::Error | PermutationOutcome::Timeout)
        || matches!(outcome_mm, PermutationOutcome::Error | PermutationOutcome::Timeout);

    if has_waf {
        return DiscrepancyResult {
            hidden_header: hidden_header.to_string(),
            canary_header: canary_header.to_string(),
            outcome: PermutationOutcome::WafBlock,
            split_or_nuke: SplitOrNuke::Unknown,
            hidden_present_canary_present: status_pp,
            hidden_missing_canary_present: status_mp,
            hidden_present_canary_missing: status_pm,
            hidden_missing_canary_missing: status_mm,
        };
    }

    if has_error {
        return DiscrepancyResult {
            hidden_header: hidden_header.to_string(),
            canary_header: canary_header.to_string(),
            outcome: PermutationOutcome::Error,
            split_or_nuke: SplitOrNuke::Unknown,
            hidden_present_canary_present: status_pp,
            hidden_missing_canary_present: status_mp,
            hidden_present_canary_missing: status_pm,
            hidden_missing_canary_missing: status_mm,
        };
    }

    let (outcome, split_or_nuke) = classify_outcome(
        status_pp, resp_pp.as_ref(),
        status_mp, resp_mp.as_ref(),
        status_pm, resp_pm.as_ref(),
        status_mm, resp_mm.as_ref(),
    );

    DiscrepancyResult {
        hidden_header: hidden_header.to_string(),
        canary_header: canary_header.to_string(),
        outcome,
        split_or_nuke,
        hidden_present_canary_present: status_pp,
        hidden_missing_canary_present: status_mp,
        hidden_present_canary_missing: status_pm,
        hidden_missing_canary_missing: status_mm,
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_outcome(
    status_pp: Option<u16>, _resp_pp: Option<&RawResponse>,
    status_mp: Option<u16>, _resp_mp: Option<&RawResponse>,
    status_pm: Option<u16>, _resp_pm: Option<&RawResponse>,
    status_mm: Option<u16>, _resp_mm: Option<&RawResponse>,
) -> (PermutationOutcome, SplitOrNuke) {
    let (pp, mp, pm, mm) = match (status_pp, status_mp, status_pm, status_mm) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return (PermutationOutcome::Error, SplitOrNuke::Unknown),
    };

    let pp_class = status_class(pp);
    let mp_class = status_class(mp);
    let pm_class = status_class(pm);
    let mm_class = status_class(mm);

    // Hidden affects the response: pp vs mp and pm vs mm differ
    // This means the hidden header is parsed and causes different behavior
    let hidden_affects = (pp != mp || pp_class != mp_class)
        && (pm != mm || pm_class != mm_class);

    // Canary affects the response: pp vs pm and mp vs mm differ
    // This means the canary header is parsed and causes different behavior
    let canary_affects = (pp != pm || pp_class != pm_class)
        && (mp != mm || mp_class != mm_class);

    // Both headers affect response independently → each parsed by different servers
    let both_affect_independently = (pp != mp || pp_class != mp_class)
        && (pp != pm || pp_class != pm_class)
        && (mp != mm || mp_class != mm_class)
        && (pm != mm || pm_class != mm_class);

    if both_affect_independently {
        return (PermutationOutcome::HighDiscrepancy, SplitOrNuke::Split);
    }

    // Only hidden affects → Split (hidden parsed, canary not)
    if hidden_affects && !canary_affects {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Split);
    }

    // Only canary affects → Nuke (canary parsed, hidden not)
    if canary_affects && !hidden_affects {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Nuke);
    }

    // All same → no discrepancy
    if pp == mp && mp == pm && pm == mm {
        return (PermutationOutcome::Match, SplitOrNuke::Unknown);
    }

    // Partial matches: some affect, some don't
    // If pp != mp and pm == mm → hidden affects when canary present, but not when absent
    if pp != mp && pm == mm {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Split);
    }

    // If pp == mp and pm != mm → hidden affects only when canary absent
    if pp == mp && pm != mm {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Nuke);
    }

    // pp != pm and mp == mm → canary affects when hidden present
    if pp != pm && mp == mm {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Split);
    }

    // pp == pm and mp != mm → canary affects when hidden absent
    if pp == pm && mp != mm {
        return (PermutationOutcome::Discrepancy, SplitOrNuke::Nuke);
    }

    (PermutationOutcome::Match, SplitOrNuke::Unknown)
}

pub fn variant_from_discrepancies(
    results: &[DiscrepancyResult],
) -> Option<(String, String)> {
    for r in results {
        if r.outcome == PermutationOutcome::Discrepancy || r.outcome == PermutationOutcome::HighDiscrepancy {
            let variant = match (r.hidden_header.as_str(), r.canary_header.as_str()) {
                ("content-length", "transfer-encoding") => "clte",
                ("transfer-encoding", "content-length") => "tecl",
                ("transfer-encoding", "transfer-encoding") => "tete",
                ("content-length", "content-length") => "cl0",
                _ => continue,
            };

            let s_or_n = match r.split_or_nuke {
                SplitOrNuke::Split => "split",
                SplitOrNuke::Nuke => "nuke",
                SplitOrNuke::Unknown => "unknown",
            };

            return Some((variant.to_string(), s_or_n.to_string()));
        }
    }

    None
}
