use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::ProxyConfig;
use crate::supervisor::Destination;

pub fn dial(proxy: &ProxyConfig, dest: Destination, timeout: Duration) -> Result<TcpStream> {
    dial_with_timings(proxy, dest, timeout, &mut DialTimings::default())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DialTimings {
    pub connect: Option<Duration>,
    pub handshake: Option<Duration>,
}

pub fn dial_with_timings(
    proxy: &ProxyConfig,
    dest: Destination,
    timeout: Duration,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    match proxy {
        ProxyConfig::Socks5 {
            addr,
            username,
            password,
        } => dial_socks5_with_timings(
            addr,
            username.as_deref(),
            password.as_deref(),
            dest,
            timeout,
            timings,
        ),
        ProxyConfig::Http { addr } => dial_http_connect_with_timings(addr, dest, timeout, timings),
    }
}

pub struct DnsTcpConnection {
    stream: TcpStream,
}

impl DnsTcpConnection {
    pub fn connect(
        proxy: &ProxyConfig,
        dns_server: Destination,
        timeout: Duration,
    ) -> Result<Self> {
        let stream = dial(proxy, dns_server, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self { stream })
    }

    pub fn query(&mut self, query: &[u8]) -> Result<Vec<u8>> {
        dns_query_over_stream(&mut self.stream, query)
    }
}

fn dns_query_over_stream(stream: &mut TcpStream, query: &[u8]) -> Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        bail!("DNS query is too large");
    }

    stream.write_all(&(query.len() as u16).to_be_bytes())?;
    stream.write_all(query)?;

    let mut len_buf = [0_u8; 2];
    stream.read_exact(&mut len_buf)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

pub struct Socks5UdpAssociation {
    _control: TcpStream,
    udp: UdpSocket,
    recv_buf: Vec<u8>,
}

impl Socks5UdpAssociation {
    pub fn connect(proxy: &ProxyConfig, timeout: Duration) -> Result<Self> {
        let ProxyConfig::Socks5 {
            addr,
            username,
            password,
        } = proxy
        else {
            bail!("generic UDP redirection requires a SOCKS5 proxy");
        };

        let mut control = connect_with_timeout(addr, timeout)
            .with_context(|| format!("connect SOCKS5 proxy {addr}"))?;
        control.set_read_timeout(Some(timeout))?;
        control.set_write_timeout(Some(timeout))?;
        socks5_greet(&mut control, username.as_deref(), password.as_deref())?;

        control.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        let relay = read_socks5_reply_addr(&mut control)?;
        let relay = normalize_relay_addr(relay, control.peer_addr()?);
        let bind = if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let udp = UdpSocket::bind(bind)?;
        udp.connect(relay)?;
        udp.set_read_timeout(Some(timeout))?;
        udp.set_write_timeout(Some(timeout))?;

        Ok(Self {
            _control: control,
            udp,
            recv_buf: vec![0_u8; 65_535],
        })
    }

    pub fn send_datagram(&mut self, dest: Destination, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        let packet = encode_socks5_udp(dest, payload)?;
        self.udp.send(&packet)?;

        match self.udp.recv(&mut self.recv_buf) {
            Ok(n) => Ok(Some(
                decode_socks5_udp_payload(&self.recv_buf[..n])?.to_vec(),
            )),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }
}

fn dial_socks5_with_timings(
    proxy_addr: &str,
    username: Option<&str>,
    password: Option<&str>,
    dest: Destination,
    timeout: Duration,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    let connect_started = Instant::now();
    let connected = connect_with_timeout(proxy_addr, timeout);
    timings.connect = Some(connect_started.elapsed());
    let mut stream = connected.with_context(|| format!("connect SOCKS5 proxy {proxy_addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let handshake_started = Instant::now();
    let result: Result<()> = (|| {
        socks5_greet(&mut stream, username, password)?;

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

        let _ = read_socks5_reply_addr(&mut stream)?;

        clear_handshake_timeouts(&stream)?;
        Ok(())
    })();
    timings.handshake = Some(handshake_started.elapsed());
    result?;
    Ok(stream)
}

fn socks5_greet(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
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
        0x02 => authenticate_socks5(stream, username.unwrap_or(""), password.unwrap_or(""))?,
        0xff => bail!("SOCKS5 proxy rejected all authentication methods"),
        method => bail!("SOCKS5 proxy selected unsupported method {method:#x}"),
    }
    Ok(())
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

fn read_socks5_reply_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        bail!("bad SOCKS5 response version {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 request failed with reply code {:#x}", head[1]);
    }

    let ip = match head[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut name = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut name)?;
            let host = String::from_utf8(name).context("SOCKS5 relay domain is not UTF-8")?;
            let mut port_buf = [0_u8; 2];
            stream.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            return (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("SOCKS5 relay domain resolved to no addresses"));
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        atyp => bail!("bad SOCKS5 bind address type {atyp:#x}"),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

fn normalize_relay_addr(relay: SocketAddr, proxy_peer: SocketAddr) -> SocketAddr {
    if relay.ip().is_unspecified() {
        SocketAddr::new(proxy_peer.ip(), relay.port())
    } else {
        relay
    }
}

fn encode_socks5_udp(dest: Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + 18 + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    match dest.ip {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dest.port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_socks5_udp_payload(packet: &[u8]) -> Result<&[u8]> {
    if packet.len() < 4 {
        bail!("short SOCKS5 UDP packet");
    }
    if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        bail!("fragmented SOCKS5 UDP packets are not supported");
    }
    let addr_len = match packet[3] {
        0x01 => 4,
        0x03 => {
            if packet.len() < 5 {
                bail!("short SOCKS5 UDP domain packet");
            }
            1 + packet[4] as usize
        }
        0x04 => 16,
        atyp => bail!("bad SOCKS5 UDP address type {atyp:#x}"),
    };
    let payload_offset = 4 + addr_len + 2;
    if packet.len() < payload_offset {
        bail!("short SOCKS5 UDP packet");
    }
    Ok(&packet[payload_offset..])
}

fn dial_http_connect_with_timings(
    proxy_addr: &str,
    dest: Destination,
    timeout: Duration,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    let connect_started = Instant::now();
    let connected = connect_with_timeout(proxy_addr, timeout);
    timings.connect = Some(connect_started.elapsed());
    let mut stream = connected.with_context(|| format!("connect HTTP proxy {proxy_addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let handshake_started = Instant::now();
    let result: Result<()> = (|| {
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

        clear_handshake_timeouts(&stream)?;
        Ok(())
    })();
    timings.handshake = Some(handshake_started.elapsed());
    result?;
    Ok(stream)
}

fn clear_handshake_timeouts(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(())
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

        let mut timings = DialTimings::default();
        let stream = dial_http_connect_with_timings(
            &addr.to_string(),
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Duration::from_secs(2),
            &mut timings,
        )
        .unwrap();
        assert!(timings.connect.is_some());
        assert!(timings.handshake.is_some());
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        drop(stream);
        handle.join().unwrap();
    }

    #[test]
    fn socks5_connect_clears_handshake_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            conn.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            conn.write_all(&[5, 0]).unwrap();

            let mut request = [0_u8; 10];
            conn.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            conn.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        });

        let mut timings = DialTimings::default();
        let stream = dial_socks5_with_timings(
            &addr.to_string(),
            None,
            None,
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Duration::from_secs(2),
            &mut timings,
        )
        .unwrap();
        assert!(timings.connect.is_some());
        assert!(timings.handshake.is_some());
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        drop(stream);
        handle.join().unwrap();
    }

    #[test]
    fn socks5_udp_header_round_trips_payload() {
        let payload = b"hello";
        let packet = encode_socks5_udp(
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                port: 5300,
            },
            payload,
        )
        .unwrap();
        assert_eq!(decode_socks5_udp_payload(&packet).unwrap(), payload);
    }
}
