use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use h2::client::SendRequest;
use h2::RecvStream;
use http::{Method, Request, HeaderName, HeaderValue};

use super::{tls, HttpConnection};

pub struct H2Connection {
    pub send_request: SendRequest<bytes::Bytes>,
    #[allow(dead_code)]
    pub connection_task: tokio::task::JoinHandle<()>,
}

pub async fn h2_connect(
    host: &str,
    port: u16,
    use_tls: bool,
    timeout_secs: u64,
) -> Result<H2Connection, String> {
    let dur = Duration::from_secs(timeout_secs);
    let addr = format!("{}:{}", host, port);

    let stream = timeout(dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Timeout connecting to {}", addr))?
        .map_err(|e| format!("Connection failed to {}: {}", addr, e))?;

    let io: Box<dyn HttpConnection> = if use_tls {
        Box::new(tls::tls_connect(stream, host, &dur).await?)
    } else {
        Box::new(stream)
    };

    let (client, conn) = timeout(dur, h2::client::handshake(io))
        .await
        .map_err(|_| "H2 handshake timeout".to_string())?
        .map_err(|e| format!("H2 handshake failed: {}", e))?;

    let connection_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(H2Connection {
        send_request: client,
        connection_task,
    })
}

async fn read_h2_body(mut body: RecvStream) -> Result<Vec<u8>, String> {
    let mut body_bytes = Vec::new();
    while let Some(Ok(chunk)) = body.data().await {
        body_bytes.extend_from_slice(&chunk);
    }
    let _ = body.trailers().await;
    Ok(body_bytes)
}

pub async fn send_h2_request(
    client: &mut SendRequest<bytes::Bytes>,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let method: Method = method.parse().map_err(|e| format!("Invalid method: {}", e))?;
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(":authority", host)
        .header("user-agent", concat!("ghostroute/", env!("CARGO_PKG_VERSION")))
        .header("accept", "*/*");

    for (k, v) in extra_headers {
        if !k.is_empty() {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| format!("Invalid header: {}", e))?;
            let value = HeaderValue::from_str(v)
                .map_err(|e| format!("Invalid header value: {}", e))?;
            req = req.header(name, value);
        }
    }

    let body_empty = body.is_empty();
    let req = req.body(()).map_err(|e| format!("Request build error: {}", e))?;

    let (resp_future, mut send_stream) = client
        .send_request(req, body_empty)
        .map_err(|e| format!("Send error: {}", e))?;

    if !body_empty {
        send_stream.send_data(bytes::Bytes::copy_from_slice(body), true)
            .map_err(|e| format!("Send body error: {}", e))?;
    }

    let resp = resp_future.await.map_err(|e| format!("Response error: {}", e))?;

    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = read_h2_body(resp.into_body()).await?;

    Ok((status, headers, body_bytes))
}

pub async fn send_h2_request_raw_headers(
    client: &mut SendRequest<bytes::Bytes>,
    pseudo_headers: &[(&str, &str)],
    extra_headers: &[(&[u8], &[u8])],
    body: &[u8],
    _host: &str,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let mut method = Method::GET;
    let mut path = "/";

    for (k, v) in pseudo_headers {
        match *k {
            ":method" => method = v.parse().map_err(|_| "Invalid method")?,
            ":path" => path = v,
            _ => {}
        }
    }

    let mut req_builder = Request::builder()
        .method(method.clone())
        .uri(path);

    for (k, v) in pseudo_headers {
        if *k == ":authority" {
            req_builder = req_builder.header(":authority", *v);
        } else if *k == ":scheme" {
            req_builder = req_builder.header(":scheme", *v);
        }
    }

    req_builder = req_builder.header("user-agent", concat!("ghostroute/", env!("CARGO_PKG_VERSION")));
    req_builder = req_builder.header("accept", "*/*");

    for (k, v) in extra_headers {
        if !k.is_empty() {
            let name = HeaderName::from_bytes(k).map_err(|e| format!("Invalid header: {}", e))?;
            let val_str = std::str::from_utf8(v).unwrap_or("");
            if !val_str.is_empty() {
                let value = HeaderValue::from_str(val_str)
                    .map_err(|e| format!("Invalid header value: {}", e))?;
                req_builder = req_builder.header(name, value);
            }
        }
    }

    let body_empty = body.is_empty();
    let req = req_builder.body(()).map_err(|e| format!("Request build error: {}", e))?;

    let (resp_fut, mut send_stream) = client.send_request(req, body_empty)
        .map_err(|e| format!("Send error: {}", e))?;

    if !body_empty {
        send_stream.send_data(bytes::Bytes::copy_from_slice(body), true).ok();
    }

    let resp = resp_fut.await.map_err(|e| format!("Response error: {}", e))?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = read_h2_body(resp.into_body()).await?;

    Ok((status, headers, body_bytes))
}
