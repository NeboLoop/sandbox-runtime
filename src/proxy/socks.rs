use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::utils::debug::log_for_debugging;

type FilterFn = Arc<
    dyn Fn(u16, String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

/// SOCKS5 proxy server handle.
pub struct SocksProxyServer {
    pub port: u16,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl SocksProxyServer {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Start a minimal SOCKS5 proxy server with domain filtering.
pub async fn start_socks_proxy_server(
    filter: FilterFn,
) -> crate::error::Result<SocksProxyServer> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| crate::error::SandboxError::ProxyError(format!("SOCKS bind: {e}")))?;

    let port = listener
        .local_addr()
        .map_err(|e| crate::error::SandboxError::ProxyError(format!("SOCKS addr: {e}")))?
        .port();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let filter = filter.clone();
                            tokio::spawn(handle_socks_client(stream, filter));
                        }
                        Err(e) => {
                            log_for_debugging(
                                &format!("SOCKS accept error: {e}"),
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

    log_for_debugging(&format!("SOCKS proxy listening on localhost:{port}"), None);

    Ok(SocksProxyServer { port, shutdown_tx })
}

async fn handle_socks_client(mut stream: TcpStream, filter: FilterFn) {
    // SOCKS5 handshake
    // Read greeting
    let mut buf = [0u8; 2];
    if stream.read_exact(&mut buf).await.is_err() {
        return;
    }

    if buf[0] != 0x05 {
        // Not SOCKS5
        return;
    }

    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    if stream.read_exact(&mut methods).await.is_err() {
        return;
    }

    // Reply: no authentication required
    if stream.write_all(&[0x05, 0x00]).await.is_err() {
        return;
    }

    // Read connection request
    let mut header = [0u8; 4];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }

    if header[0] != 0x05 || header[1] != 0x01 {
        // Only support CONNECT command
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }

    let (hostname, port) = match header[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            if stream.read_exact(&mut addr).await.is_err() {
                return;
            }
            let mut port_buf = [0u8; 2];
            if stream.read_exact(&mut port_buf).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(port_buf);
            (format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]), port)
        }
        0x03 => {
            // Domain name
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut domain = vec![0u8; len[0] as usize];
            if stream.read_exact(&mut domain).await.is_err() {
                return;
            }
            let mut port_buf = [0u8; 2];
            if stream.read_exact(&mut port_buf).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(port_buf);
            (String::from_utf8_lossy(&domain).to_string(), port)
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            if stream.read_exact(&mut addr).await.is_err() {
                return;
            }
            let mut port_buf = [0u8; 2];
            if stream.read_exact(&mut port_buf).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(port_buf);
            // Format IPv6 address
            let segments: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]])))
                .collect();
            (segments.join(":"), port)
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };

    // Apply filter
    let allowed = filter(port, hostname.clone()).await;
    if !allowed {
        log_for_debugging(
            &format!("SOCKS blocked connection to {hostname}:{port}"),
            Some("error"),
        );
        // Reply: connection not allowed
        let _ = stream
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }

    log_for_debugging(
        &format!("SOCKS connection to {hostname}:{port}"),
        None,
    );

    // Connect to target
    match TcpStream::connect(format!("{hostname}:{port}")).await {
        Ok(mut target) => {
            // Reply: success
            let _ = stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await;

            // Bidirectional copy
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
        }
        Err(e) => {
            log_for_debugging(
                &format!("SOCKS connect failed to {hostname}:{port}: {e}"),
                Some("error"),
            );
            // Reply: host unreachable
            let _ = stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        }
    }
}
