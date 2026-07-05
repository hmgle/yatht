use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::ProxyConfig;
use crate::supervisor::Destination;

pub fn dial(proxy: &ProxyConfig, dest: Destination, timeout: Duration) -> Result<TcpStream> {
    match proxy {
        ProxyConfig::Socks5 {
            addr,
            username,
            password,
        } => dial_socks5(
            addr,
            username.as_deref(),
            password.as_deref(),
            dest,
            timeout,
        ),
        ProxyConfig::Http { addr } => dial_http_connect(addr, dest, timeout),
    }
}

fn dial_socks5(
    proxy_addr: &str,
    username: Option<&str>,
    password: Option<&str>,
    dest: Destination,
    timeout: Duration,
) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let mut stream = connect_with_timeout(proxy_addr, timeout)
        .with_context(|| format!("connect SOCKS5 proxy {proxy_addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let methods: &[u8] = if username.is_some() || password.is_some() {
        &[0x02]
    } else {
        &[0x00]
    };
    stream.write_all(&[0x05, methods.len() as u8])?;
    stream.write_all(methods)?;

    let mut method_resp = [0_u8; 2];
    stream.read_exact(&mut method_resp)?;
    if method_resp[0] != 0x05 {
        bail!("bad SOCKS5 method response version {}", method_resp[0]);
    }
    match method_resp[1] {
        0x00 => {}
        0x02 => authenticate_socks5(&mut stream, username.unwrap_or(""), password.unwrap_or(""))?,
        0xff => bail!("SOCKS5 proxy rejected all authentication methods"),
        method => bail!("SOCKS5 proxy selected unsupported method {method:#x}"),
    }

    let mut req = vec![0x05, 0x01, 0x00];
    match dest.ip {
        IpAddr::V4(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&dest.port.to_be_bytes());
    stream.write_all(&req)?;

    let mut head = [0_u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        bail!("bad SOCKS5 connect response version {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 connect failed with reply code {:#x}", head[1]);
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize
        }
        0x04 => 16,
        atyp => bail!("bad SOCKS5 bind address type {atyp:#x}"),
    };
    let mut discard = vec![0_u8; addr_len + 2];
    stream.read_exact(&mut discard)?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    stream.set_read_timeout(Some(remaining.max(Duration::from_secs(1))))?;
    stream.set_write_timeout(Some(remaining.max(Duration::from_secs(1))))?;
    Ok(stream)
}

fn authenticate_socks5(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        bail!("SOCKS5 username/password must be <= 255 bytes");
    }
    stream.write_all(&[0x01, username.len() as u8])?;
    stream.write_all(username.as_bytes())?;
    stream.write_all(&[password.len() as u8])?;
    stream.write_all(password.as_bytes())?;

    let mut resp = [0_u8; 2];
    stream.read_exact(&mut resp)?;
    if resp != [0x01, 0x00] {
        bail!("SOCKS5 username/password authentication failed");
    }
    Ok(())
}

fn dial_http_connect(proxy_addr: &str, dest: Destination, timeout: Duration) -> Result<TcpStream> {
    let mut stream = connect_with_timeout(proxy_addr, timeout)
        .with_context(|| format!("connect HTTP proxy {proxy_addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let authority = dest.authority();
    let req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() >= 8192 {
            bail!("HTTP proxy response header too large");
        }
        let n = stream.read(&mut byte)?;
        if n == 0 {
            bail!("HTTP proxy closed before completing CONNECT response");
        }
        buf.push(byte[0]);
    }

    let header = String::from_utf8_lossy(&buf);
    let status = header
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty HTTP proxy response"))?;
    let mut parts = status.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP proxy response missing status code"))?;
    if code != "200" {
        let _ = stream.shutdown(Shutdown::Both);
        bail!("HTTP CONNECT failed: {status}");
    }

    Ok(stream)
}

fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<TcpStream> {
    if let Ok(sockaddr) = addr.parse::<SocketAddr>() {
        return TcpStream::connect_timeout(&sockaddr, timeout).map_err(Into::into);
    }

    let addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {addr}"))?;
    let mut last_err = None;
    for sockaddr in addrs {
        match TcpStream::connect_timeout(&sockaddr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .map(Into::into)
        .unwrap_or_else(|| anyhow!("no socket addresses resolved for {addr}")))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    use super::*;

    #[test]
    fn http_connect_sends_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            assert_eq!(first.trim_end(), "CONNECT 203.0.113.1:443 HTTP/1.1");
            conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
        });

        let stream = dial_http_connect(
            &addr.to_string(),
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        drop(stream);
        handle.join().unwrap();
    }
}
