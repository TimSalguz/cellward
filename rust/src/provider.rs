//! Readiness checks for a proxy published by an application transport.
//!
//! The check never resolves a name or sends zone traffic. SOCKS5 completes
//! method negotiation; HTTP accepts a valid CONNECT response to an unserviceable
//! loopback port, including an ordinary gateway refusal.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::proxy::{Config, Kind};

const WAIT: Duration = Duration::from_secs(2);

pub fn check(config: &Config) -> Result<(), String> {
    let address = SocketAddr::new(config.server, config.port);
    let mut stream = TcpStream::connect_timeout(&address, WAIT)
        .map_err(|e| format!("published proxy is not reachable: {e}"))?;
    stream
        .set_read_timeout(Some(WAIT))
        .and_then(|()| stream.set_write_timeout(Some(WAIT)))
        .map_err(|e| format!("cannot set the published proxy's timeout: {e}"))?;
    handshake(
        &mut stream,
        config.kind,
        config.username.as_deref(),
        config.password.as_deref(),
    )
}

pub fn handshake(
    stream: &mut TcpStream,
    kind: Kind,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), String> {
    match kind {
        Kind::Socks5 => socks5(stream, username, password),
        Kind::Http => http(stream, username, password),
    }
}

fn socks5(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), String> {
    let authenticated = username.is_some() || password.is_some();
    if authenticated {
        stream
            .write_all(&[5, 2, 0, 2])
            .map_err(|e| format!("SOCKS5 greeting failed: {e}"))?;
    } else {
        stream
            .write_all(&[5, 1, 0])
            .map_err(|e| format!("SOCKS5 greeting failed: {e}"))?;
    }
    let mut answer = [0; 2];
    stream
        .read_exact(&mut answer)
        .map_err(|e| format!("SOCKS5 greeting was not answered: {e}"))?;
    if answer[0] != 5 {
        return Err("published proxy is not SOCKS5".to_owned());
    }
    match answer[1] {
        0 => return Ok(()),
        2 if authenticated => {}
        2 => return Err("published SOCKS5 proxy requires authentication".to_owned()),
        _ => return Err("published SOCKS5 proxy has no supported authentication".to_owned()),
    }
    let username = username.unwrap_or_default().as_bytes();
    let password = password.unwrap_or_default().as_bytes();
    if username.len() > 255 || password.len() > 255 {
        return Err("SOCKS5 credentials exceed the protocol's 255-byte limit".to_owned());
    }
    let mut request = vec![1, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .map_err(|e| format!("SOCKS5 authentication failed: {e}"))?;
    stream
        .read_exact(&mut answer)
        .map_err(|e| format!("SOCKS5 authentication was not answered: {e}"))?;
    if answer != [1, 0] {
        return Err("published SOCKS5 proxy rejected authentication".to_owned());
    }
    Ok(())
}

fn http(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), String> {
    let mut request = "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n".to_owned();
    if username.is_some() || password.is_some() {
        let credentials = format!(
            "{}:{}",
            username.unwrap_or_default(),
            password.unwrap_or_default()
        );
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(credentials.as_bytes())
        ));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("HTTP CONNECT readiness failed: {e}"))?;
    let mut response = String::new();
    let read = BufReader::new(stream.take(4096))
        .read_line(&mut response)
        .map_err(|e| format!("HTTP CONNECT was not answered: {e}"))?;
    if read == 0 || read == 4096 || !response.ends_with('\n') {
        return Err("published HTTP proxy returned an invalid response".to_owned());
    }
    let mut words = response.split_whitespace();
    let version = words.next().unwrap_or_default();
    let status = words
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status));
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status.is_none() {
        return Err("published HTTP proxy returned an invalid response".to_owned());
    }
    if status == Some(407) {
        return Err("published HTTP proxy rejected authentication".to_owned());
    }
    Ok(())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn config(port: u16, kind: &str, credentials: bool) -> Config {
        let auth = if credentials {
            "Username = private-user\nPassword = private-password\n"
        } else {
            ""
        };
        Config::from_ini(
            &crate::config::WgConfig::parse(
                format!(
                    "[Interface]\nAddress = 10.200.0.2/32\n[Proxy]\nType = {kind}\nServer = 127.0.0.1\nPort = {port}\n{auth}"
                )
                .as_bytes(),
            )
            .unwrap(),
            "awg0",
        )
        .unwrap()
    }

    fn server(answer: &'static [u8], second: bool) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut buffer = [0; 512];
            let read = stream.read(&mut buffer).unwrap();
            received.extend_from_slice(&buffer[..read]);
            stream.write_all(answer).unwrap();
            if second {
                let read = stream.read(&mut buffer).unwrap();
                received.extend_from_slice(&buffer[..read]);
                stream.write_all(&[1, 0]).unwrap();
            }
            received
        });
        (port, worker)
    }

    #[test]
    fn socks5_readiness_negotiates_authentication_without_leaking_credentials() {
        let (port, worker) = server(&[5, 2], true);
        check(&config(port, "socks5", true)).unwrap();
        let received = worker.join().unwrap();
        assert!(received.starts_with(&[5, 2, 0, 2]));
        let mut expected = vec![5, 2, 0, 2, 1, 12];
        expected.extend_from_slice(b"private-user");
        expected.push(16);
        expected.extend_from_slice(b"private-password");
        assert_eq!(received, expected);

        let (port, worker) = server(&[5, 0], false);
        check(&config(port, "socks5", false)).unwrap();
        assert_eq!(worker.join().unwrap(), [5, 1, 0]);

        let (port, worker) = server(&[5, 255], false);
        let error = check(&config(port, "socks5", true)).unwrap_err();
        worker.join().unwrap();
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-password"));
    }

    #[test]
    fn http_readiness_requires_a_connect_answer_not_only_an_open_port() {
        let (port, worker) = server(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", false);
        check(&config(port, "http", true)).unwrap();
        let received = worker.join().unwrap();
        let request = String::from_utf8(received).unwrap();
        assert!(request.starts_with("CONNECT 127.0.0.1:1 HTTP/1.1\r\n"));
        assert!(request
            .contains("Proxy-Authorization: Basic cHJpdmF0ZS11c2VyOnByaXZhdGUtcGFzc3dvcmQ=\r\n"));

        let (port, worker) = server(b"not HTTP\r\n", false);
        assert!(check(&config(port, "http", false)).is_err());
        worker.join().unwrap();

        let (port, worker) = server(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", false);
        let error = check(&config(port, "http", true)).unwrap_err();
        worker.join().unwrap();
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-password"));
    }

    #[test]
    fn basic_encoding_has_the_standard_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
