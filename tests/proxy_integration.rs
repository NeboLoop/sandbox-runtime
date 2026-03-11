use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type FilterFn = Arc<
    dyn Fn(u16, String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

fn allow_all_filter() -> FilterFn {
    Arc::new(|_port, _host| Box::pin(async { true }))
}

fn deny_all_filter() -> FilterFn {
    Arc::new(|_port, _host| Box::pin(async { false }))
}

#[tokio::test]
async fn test_http_proxy_start_shutdown() {
    let filter = allow_all_filter();
    let server = sandbox_runtime::proxy::http::start_http_proxy_server(filter, None)
        .await
        .unwrap();
    let port = server.port();
    assert!(port > 0);
    server.shutdown();
}

#[tokio::test]
async fn test_http_proxy_binds_to_port() {
    let filter = allow_all_filter();
    let server = sandbox_runtime::proxy::http::start_http_proxy_server(filter, None)
        .await
        .unwrap();
    let port = server.port();

    // Verify we can connect to the port
    let result = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
    assert!(result.is_ok());

    server.shutdown();
}

#[tokio::test]
async fn test_socks_proxy_start_shutdown() {
    let filter = allow_all_filter();
    let server = sandbox_runtime::proxy::socks::start_socks_proxy_server(filter)
        .await
        .unwrap();
    let port = server.port();
    assert!(port > 0);
    server.shutdown();
}

#[tokio::test]
async fn test_socks_proxy_binds_to_port() {
    let filter = allow_all_filter();
    let server = sandbox_runtime::proxy::socks::start_socks_proxy_server(filter)
        .await
        .unwrap();
    let port = server.port();

    // Verify we can connect to the port
    let result = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
    assert!(result.is_ok());

    server.shutdown();
}

#[tokio::test]
async fn test_http_proxy_deny_filter_returns_403() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let filter = deny_all_filter();
    let server = sandbox_runtime::proxy::http::start_http_proxy_server(filter, None)
        .await
        .unwrap();
    let port = server.port();

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // Send a CONNECT request
    stream
        .write_all(b"CONNECT blocked.com:443 HTTP/1.1\r\nHost: blocked.com\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("403"));

    server.shutdown();
}

#[tokio::test]
async fn test_socks_proxy_deny_filter_returns_connection_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let filter = deny_all_filter();
    let server = sandbox_runtime::proxy::socks::start_socks_proxy_server(filter)
        .await
        .unwrap();
    let port = server.port();

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // SOCKS5 handshake: version 5, 1 method, no auth
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut greeting_response = [0u8; 2];
    stream.read_exact(&mut greeting_response).await.unwrap();
    assert_eq!(greeting_response[0], 0x05); // SOCKS5
    assert_eq!(greeting_response[1], 0x00); // No auth

    // CONNECT to blocked.com:443 (domain type 0x03)
    let domain = b"blocked.com";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut response = [0u8; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 0x05); // SOCKS5
    assert_eq!(response[1], 0x02); // Connection not allowed

    server.shutdown();
}
