use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::utils::debug::log_for_debugging;

type FilterFn = Arc<
    dyn Fn(u16, String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

/// HTTP proxy server handle.
pub struct HttpProxyServer {
    pub port: u16,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl HttpProxyServer {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Start an HTTP proxy server that handles CONNECT tunneling and regular HTTP requests.
pub async fn start_http_proxy_server(
    filter: FilterFn,
    _mitm_fn: Option<()>,
) -> crate::error::Result<HttpProxyServer> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| crate::error::SandboxError::ProxyError(format!("HTTP proxy bind: {e}")))?;

    let port = listener
        .local_addr()
        .map_err(|e| crate::error::SandboxError::ProxyError(format!("HTTP proxy addr: {e}")))?
        .port();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let filter = filter.clone();
                            tokio::spawn(handle_client(stream, filter));
                        }
                        Err(e) => {
                            log_for_debugging(
                                &format!("HTTP proxy accept error: {e}"),
                                Some("error"),
                            );
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    log_for_debugging(&format!("HTTP proxy listening on localhost:{port}"), None);

    Ok(HttpProxyServer { port, shutdown_tx })
}

async fn handle_client(mut stream: TcpStream, filter: FilterFn) {
    // Read the first line of the HTTP request to determine method
    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await;
        return;
    }

    let method = parts[0];
    let target = parts[1];

    if method == "CONNECT" {
        handle_connect(stream, target, filter).await;
    } else {
        handle_http_request(stream, &buf[..n], method, target, filter).await;
    }
}

async fn handle_connect(mut client: TcpStream, target: &str, filter: FilterFn) {
    let parts: Vec<&str> = target.splitn(2, ':').collect();
    let hostname = parts.first().copied().unwrap_or("");
    let port: u16 = parts
        .get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);

    if hostname.is_empty() {
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await;
        return;
    }

    let allowed = filter(port, hostname.to_string()).await;
    if !allowed {
        log_for_debugging(
            &format!("CONNECT blocked to {hostname}:{port}"),
            Some("error"),
        );
        let _ = client
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\n\
                  Content-Type: text/plain\r\n\
                  X-Proxy-Error: blocked-by-allowlist\r\n\
                  \r\n\
                  Connection blocked by network allowlist",
            )
            .await;
        return;
    }

    // Connect to target
    match TcpStream::connect(format!("{hostname}:{port}")).await {
        Ok(mut server) => {
            // Send 200 to client
            let _ = client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;

            // Bidirectional copy
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
        Err(e) => {
            log_for_debugging(
                &format!("CONNECT tunnel failed to {hostname}:{port}: {e}"),
                Some("error"),
            );
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
        }
    }
}

async fn handle_http_request(
    mut client: TcpStream,
    request_data: &[u8],
    _method: &str,
    target: &str,
    filter: FilterFn,
) {
    // Parse target URL or Host header to extract host/port
    let (hostname, port): (String, u16) = {
        // Try parsing as absolute URL (e.g., http://example.com/path)
        if target.contains("://") {
            let without_scheme = target.split("://").nth(1).unwrap_or("");
            let host_port = without_scheme.split('/').next().unwrap_or("");
            let parts: Vec<&str> = host_port.splitn(2, ':').collect();
            let host = parts.first().unwrap_or(&"").to_string();
            let port = parts
                .get(1)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(if target.starts_with("https") { 443 } else { 80 });
            (host, port)
        } else {
            // Extract from Host header
            let request_str = String::from_utf8_lossy(request_data);
            let host = request_str
                .lines()
                .find(|l| l.to_lowercase().starts_with("host:"))
                .map(|l| l[5..].trim().to_string())
                .unwrap_or_default();
            let parts: Vec<&str> = host.splitn(2, ':').collect();
            let hostname = parts.first().unwrap_or(&"").to_string();
            let port = parts
                .get(1)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(80);
            (hostname, port)
        }
    };

    if hostname.is_empty() {
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await;
        return;
    }

    let allowed = filter(port, hostname.clone()).await;
    if !allowed {
        log_for_debugging(
            &format!("HTTP request blocked to {hostname}:{port}"),
            Some("error"),
        );
        let _ = client
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\n\
                  Content-Type: text/plain\r\n\
                  X-Proxy-Error: blocked-by-allowlist\r\n\
                  \r\n\
                  Connection blocked by network allowlist",
            )
            .await;
        return;
    }

    // Forward request to target
    match TcpStream::connect(format!("{hostname}:{port}")).await {
        Ok(mut server) => {
            let _ = server.write_all(request_data).await;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
        Err(e) => {
            log_for_debugging(
                &format!("HTTP proxy connect failed to {hostname}:{port}: {e}"),
                Some("error"),
            );
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
        }
    }
}
