use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn ws_connect(
    host: &str,
    port: u16,
    use_tls: bool,
    path: &str,
    _extra_headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<WsStream, String> {
    let dur = Duration::from_secs(timeout_secs);
    let scheme = if use_tls { "wss" } else { "ws" };
    let url_str = format!("{}://{}:{}{}", scheme, host, port, path);

    let (ws_stream, _) = tokio::time::timeout(dur, connect_async(&url_str))
        .await
        .map_err(|_| "WS connection timeout".to_string())?
        .map_err(|e| format!("WS connection failed: {}", e))?;

    Ok(ws_stream)
}
