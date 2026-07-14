pub mod h1;
pub mod h2;
pub mod tls;
pub mod ws;

use std::time::Duration;

#[derive(Clone)]
pub struct NetConfig {
    pub timeout: Duration,
    pub tls: bool,
    pub proxy: Option<String>,
    pub port: u16,
    pub host: String,
    pub sni: String,
}

impl NetConfig {
    pub fn new(host: &str, port: u16, tls: bool, timeout_secs: u64) -> Self {
        NetConfig {
            timeout: Duration::from_secs(timeout_secs),
            tls,
            proxy: None,
            port,
            host: host.to_string(),
            sni: host.to_string(),
        }
    }
}

pub async fn connect(cfg: &NetConfig) -> Result<Box<dyn HttpConnection>, String> {
    use tokio::net::TcpStream;

    let addr = if let Some(proxy) = &cfg.proxy {
        proxy.clone()
    } else {
        format!("{}:{}", cfg.host, cfg.port)
    };

    let stream = tokio::time::timeout(cfg.timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Connection timeout to {}", addr))?
        .map_err(|e| format!("Connection failed to {}: {}", addr, e))?;

    if cfg.tls {
        let tls_stream = tls::tls_connect(stream, &cfg.sni, &cfg.timeout).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

pub trait HttpConnection: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> HttpConnection for T {}
