use crate::auth::AuthStore;
use crate::net::NetConfig;
use crate::output::ScanResult;

pub async fn probe(
    cfg: &NetConfig,
    _auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;

    if !*silent {
        eprintln!("  [DBG] H2.0 probe (cleartext HTTP/2 prior knowledge) on {}:{}", host, cfg.port);
    }

    // H2.0: send HTTP/2 connection preface directly over cleartext
    // This tests if the server accepts H2C (HTTP/2 cleartext) prior knowledge

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use std::time::Duration;

    let addr = format!("{}:{}", host, cfg.port);
    let mut stream = timeout(
        Duration::from_secs(cfg.timeout.as_secs()),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("Timeout connecting to {}", addr))?
    .map_err(|e| format!("Connection failed: {}", e))?;

    // HTTP/2 connection preface (PRI * HTTP/2.0)
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    stream.write_all(preface).await.ok();

    // Read response — if we get a valid HTTP/2 response, server accepts h2c
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    if let Ok(Ok(n)) = timeout(Duration::from_secs(5), stream.read(&mut tmp)).await { buf.extend_from_slice(&tmp[..n]) }

    let preface_detected = buf.starts_with(b"PRI") || buf.windows(8).any(|w| w == b"HTTP/2.0");
    let settings_detected = buf.len() >= 4 && buf[3] == 0x04;

    let vulnerable = preface_detected || settings_detected || !buf.is_empty();

    let host_name = host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "h20".to_string(),
        vulnerable,
        server: None,
        bypass: None,
        status_code: if vulnerable { 101 } else { 0 },
        details: if vulnerable {
            Some(format!("H2.0: cleartext H2 accepted ({} bytes response)", buf.len()))
        } else {
            None
        },
        ..Default::default()
    })
}
