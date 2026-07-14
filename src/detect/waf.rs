use crate::net::h1::RawResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafKind {
    Generic,
    Cloudflare,
    Akamai,
    Aws,
    Netlify,
}

impl WafKind {
    pub fn name(&self) -> &'static str {
        match self {
            WafKind::Generic => "Generic WAF",
            WafKind::Cloudflare => "Cloudflare",
            WafKind::Akamai => "Akamai",
            WafKind::Aws => "AWS WAF",
            WafKind::Netlify => "Netlify",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_kind: Option<WafKind>,
    pub triggered_signatures: Vec<String>,
}

type WafCheck = fn(&RawResponse) -> bool;

struct WafRule {
    pub name: &'static str,
    pub kind: WafKind,
    pub check: WafCheck,
}

fn waf_rules() -> Vec<WafRule> {
    vec![
        WafRule {
            name: "status-403",
            kind: WafKind::Generic,
            check: |r| r.status_code == 403,
        },
        WafRule {
            name: "status-406",
            kind: WafKind::Generic,
            check: |r| r.status_code == 406,
        },
        WafRule {
            name: "status-493",
            kind: WafKind::Akamai,
            check: |r| r.status_code == 493,
        },
        WafRule {
            name: "body-blocked",
            kind: WafKind::Generic,
            check: |r| {
                let body = String::from_utf8_lossy(&r.body);
                body.to_lowercase().contains("blocked")
                    || body.contains("denied")
                    || body.contains("rejected")
            },
        },
        WafRule {
            name: "server-cloudflare",
            kind: WafKind::Cloudflare,
            check: |r| {
                r.server.as_deref().unwrap_or("").contains("cloudflare")
                    || r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cf-ray"))
            },
        },
        WafRule {
            name: "server-akamai",
            kind: WafKind::Akamai,
            check: |r| {
                r.server.as_deref().unwrap_or("").contains("akamai")
                    || r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-akamai-"))
            },
        },
        WafRule {
            name: "server-aws-waf",
            kind: WafKind::Aws,
            check: |r| {
                r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-amzn-requestid"))
                    || r.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-cache") && v.contains("Error"))
            },
        },
        WafRule {
            name: "header-x-served-by",
            kind: WafKind::Netlify,
            check: |r| {
                r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-served-by"))
            },
        },
        WafRule {
            name: "body-security-ref",
            kind: WafKind::Generic,
            check: |r| {
                let body = String::from_utf8_lossy(&r.body);
                body.contains("WAF")
                    || body.contains("firewall")
                    || body.contains("security")
                    || body.contains("incident")
            },
        },
        WafRule {
            name: "connection-close-4xx",
            kind: WafKind::Generic,
            check: |r| {
                r.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")
                }) && r.status_code >= 400
            },
        },
    ]
}

pub fn detect_waf(resp: &RawResponse) -> WafDetection {
    let mut triggered = Vec::new();
    let mut waf_kind: Option<WafKind> = None;

    for rule in waf_rules() {
        if (rule.check)(resp) {
            triggered.push(rule.name.to_string());
            if waf_kind.is_none() || !matches!(rule.kind, WafKind::Generic) {
                waf_kind = Some(rule.kind);
            }
        }
    }

    WafDetection {
        detected: !triggered.is_empty(),
        waf_kind,
        triggered_signatures: triggered,
    }
}

pub fn detect_waf_on_responses(responses: &[RawResponse]) -> WafDetection {
    let mut combined = WafDetection {
        detected: false,
        waf_kind: None,
        triggered_signatures: Vec::new(),
    };

    for resp in responses {
        let result = detect_waf(resp);
        if result.detected {
            combined.detected = true;
            combined.waf_kind = combined.waf_kind.or(result.waf_kind);
            for sig in result.triggered_signatures {
                if !combined.triggered_signatures.contains(&sig) {
                    combined.triggered_signatures.push(sig);
                }
            }
        }
    }

    combined
}
