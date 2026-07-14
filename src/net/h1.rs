use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{connect, NetConfig};
use crate::auth::AuthStore;

#[derive(Clone)]
pub struct RawResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
    pub server: Option<String>,
}

pub async fn send_request(
    cfg: &NetConfig,
    request_bytes: &[u8],
    auth: Option<&AuthStore>,
) -> Result<RawResponse, String> {
    let mut conn = connect(cfg).await?;
    let mut req = request_bytes.to_vec();

    if let Some(a) = auth {
        a.apply_to_request(&mut req);
    }

    timeout(cfg.timeout, conn.write_all(&req))
        .await
        .map_err(|_| "Write timeout")?
        .map_err(|e| format!("Write error: {}", e))?;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];

    loop {
        match timeout(cfg.timeout, conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error: {}", e)),
            Err(_) => break,
        }
        if buf.len() > 1_000_000 {
            break;
        }
    }

    parse_response(&buf)
}

pub async fn send_raw_on_conn(
    conn: &mut TcpStream,
    request_bytes: &[u8],
    timeout_dur: Duration,
) -> Result<RawResponse, String> {
    timeout(timeout_dur, conn.write_all(request_bytes))
        .await
        .map_err(|_| "Write timeout")?
        .map_err(|e| format!("Write error: {}", e))?;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];

    loop {
        match timeout(timeout_dur, conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(format!("Read error: {}", e)),
            Err(_) => break,
        }
        if buf.len() > 1_000_000 {
            break;
        }
    }

    parse_response(&buf)
}

pub fn parse_response(data: &[u8]) -> Result<RawResponse, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp
        .parse(data)
        .map_err(|e| {
            let preview = String::from_utf8_lossy(&data[..data.len().min(200)]);
            format!("Parse error: {} (raw: {:?})", e, preview)
        })?;

    let header_end = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => data.len(),
    };

    let status_code = resp.code.unwrap_or(0);
    let parsed_headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .filter_map(|h| {
            let name = h.name.to_string();
            let value = String::from_utf8(h.value.to_vec()).ok()?;
            Some((name, value))
        })
        .collect();

    let server = parsed_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.clone());

    let body = if header_end < data.len() {
        data[header_end..].to_vec()
    } else {
        Vec::new()
    };

    Ok(RawResponse {
        status_code,
        headers: parsed_headers,
        body,
        raw: data.to_vec(),
        server,
    })
}

pub fn build_request(
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);

    for (k, v) in extra_headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }

    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    req.push_str("Connection: keep-alive\r\n");
    req.push_str("User-Agent: ghostroute/1.0.0\r\n");
    req.push_str("Accept: */*\r\n\r\n");

    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub fn build_chunked_body(chunks: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in chunks {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    body
}

pub fn build_smuggled_request(
    host: &str,
    smuggled_body: &[u8],
    use_cl: bool,
    cl_value: Option<usize>,
) -> Vec<u8> {
    let mut headers = vec![
        ("Host", host),
        ("User-Agent", "ghostroute/1.0.0"),
        ("Accept", "*/*"),
    ];

    let cl_str;
    if use_cl {
        let cl = cl_value.unwrap_or(smuggled_body.len());
        cl_str = Some(cl.to_string());
        headers.push(("Content-Length", cl_str.as_ref().unwrap()));
    } else {
        cl_str = None;
    }

    let mut req = String::new();
    req.push_str("POST / HTTP/1.1\r\n");
    for (k, v) in &headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("Connection: keep-alive\r\n\r\n");

    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(smuggled_body);
    bytes
}
