use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

pub async fn tls_connect(
    stream: TcpStream,
    hostname: &str,
    timeout_dur: &Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let connector = connector.with_alpn(vec![b"http/1.1".to_vec()]);

    let dns_name = tokio_rustls::rustls::pki_types::DnsName::try_from(hostname.to_string())
        .map_err(|e| format!("Invalid hostname: {}", e))?;
    let server_name = ServerName::DnsName(dns_name);

    let tls_stream = timeout(*timeout_dur, connector.connect(server_name, stream))
        .await
        .map_err(|_| format!("TLS handshake timeout to {}", hostname))?
        .map_err(|e| format!("TLS handshake failed to {}: {}", hostname, e))?;

    Ok(tls_stream)
}
