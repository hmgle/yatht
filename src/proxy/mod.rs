use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::{ProxyConfig, ProxyEndpoint};
use crate::supervisor::Destination;

pub mod warm;

#[derive(Clone, Copy, Debug, Default)]
pub struct DialTimings {
    pub connect: Option<Duration>,
    pub handshake: Option<Duration>,
}

#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    started: Instant,
    timeout: Duration,
}

impl Deadline {
    pub fn after(timeout: Duration) -> Self {
        Self::from_start(Instant::now(), timeout)
    }

    pub fn from_start(start: Instant, timeout: Duration) -> Self {
        Self {
            started: start,
            timeout,
        }
    }

    fn remaining(self) -> io::Result<Duration> {
        self.timeout
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proxy deadline exceeded"))
    }

    pub(crate) fn set_read_timeout(self, stream: &TcpStream) -> io::Result<()> {
        stream.set_read_timeout(Some(self.remaining()?))
    }

    pub(crate) fn set_write_timeout(self, stream: &TcpStream) -> io::Result<()> {
        stream.set_write_timeout(Some(self.remaining()?))
    }
}

pub fn dial_with_deadline(
    proxy: &ProxyConfig,
    dest: Destination,
    deadline: Deadline,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    match proxy {
        ProxyConfig::Socks5 {
            endpoint,
            username,
            password,
        } => dial_socks5_with_timings(
            endpoint,
            username.as_deref(),
            password.as_deref(),
            dest,
            deadline,
            timings,
        ),
        ProxyConfig::Http { endpoint } => {
            dial_http_connect_with_timings(endpoint, dest, deadline, timings)
        }
    }
}

pub struct DnsTcpConnection {
    stream: TcpStream,
}

impl DnsTcpConnection {
    pub fn connect(
        proxy: &ProxyConfig,
        dns_server: Destination,
        deadline: Deadline,
    ) -> Result<Self> {
        let stream = dial_with_deadline(proxy, dns_server, deadline, &mut DialTimings::default())?;
        Ok(Self { stream })
    }

    pub fn query(&mut self, query: &[u8], deadline: Deadline) -> Result<Vec<u8>> {
        dns_query_over_stream(&mut self.stream, query, deadline)
    }
}

fn dns_query_over_stream(
    stream: &mut TcpStream,
    query: &[u8],
    deadline: Deadline,
) -> Result<Vec<u8>> {
    if query.len() > u16::MAX as usize {
        bail!("DNS query is too large");
    }

    write_all_with_deadline(stream, &(query.len() as u16).to_be_bytes(), deadline)?;
    write_all_with_deadline(stream, query, deadline)?;

    let mut len_buf = [0_u8; 2];
    read_exact_with_deadline(stream, &mut len_buf, deadline)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0_u8; response_len];
    read_exact_with_deadline(stream, &mut response, deadline)?;
    Ok(response)
}

pub struct Socks5UdpAssociation {
    _control: TcpStream,
    udp: UdpSocket,
    recv_buf: Vec<u8>,
}

impl Socks5UdpAssociation {
    pub fn connect(proxy: &ProxyConfig, deadline: Deadline) -> Result<Self> {
        let ProxyConfig::Socks5 {
            endpoint,
            username,
            password,
        } = proxy
        else {
            bail!("generic UDP redirection requires a SOCKS5 proxy");
        };

        let mut control = connect_with_deadline(endpoint, deadline)
            .with_context(|| format!("connect SOCKS5 proxy {}", endpoint.authority()))?;
        socks5_greet(
            &mut control,
            username.as_deref(),
            password.as_deref(),
            deadline,
        )?;

        write_all_with_deadline(
            &mut control,
            &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            deadline,
        )?;
        let relay = read_socks5_reply_addr(&mut control, deadline)?;
        let relay = normalize_relay_addr(relay, control.peer_addr()?);
        let bind = if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let udp = UdpSocket::bind(bind)?;
        udp.connect(relay)?;

        Ok(Self {
            _control: control,
            udp,
            recv_buf: vec![0_u8; 65_535],
        })
    }

    pub fn send_datagram(
        &mut self,
        dest: Destination,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<Option<Vec<u8>>> {
        let packet = encode_socks5_udp(dest, payload)?;
        self.udp.set_write_timeout(Some(deadline.remaining()?))?;
        self.udp.send(&packet)?;

        self.udp.set_read_timeout(Some(deadline.remaining()?))?;
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
    endpoint: &ProxyEndpoint,
    username: Option<&str>,
    password: Option<&str>,
    dest: Destination,
    deadline: Deadline,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    let connect_started = Instant::now();
    let connected = connect_with_deadline(endpoint, deadline);
    timings.connect = Some(connect_started.elapsed());
    let mut stream =
        connected.with_context(|| format!("connect SOCKS5 proxy {}", endpoint.authority()))?;

    let handshake_started = Instant::now();
    let result: Result<()> = (|| {
        socks5_greet(&mut stream, username, password, deadline)?;
        socks5_request(&mut stream, dest, deadline)?;
        clear_handshake_timeouts(&stream)?;
        Ok(())
    })();
    timings.handshake = Some(handshake_started.elapsed());
    result?;
    Ok(stream)
}

// Frame builders and reply parsers below are pure so the blocking dial path
// and any nonblocking session establishment share one protocol definition.

const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_METHOD_USER_PASS: u8 = 0x02;

fn socks5_greeting_frame(with_auth: bool) -> [u8; 3] {
    let method = if with_auth {
        SOCKS5_METHOD_USER_PASS
    } else {
        SOCKS5_METHOD_NO_AUTH
    };
    [0x05, 0x01, method]
}

/// Returns the proxy-selected method byte after validating the reply.
fn parse_socks5_method_reply(reply: [u8; 2], offered: u8) -> Result<u8> {
    if reply[0] != 0x05 {
        bail!("bad SOCKS5 method response version {}", reply[0]);
    }
    match reply[1] {
        method @ (SOCKS5_METHOD_NO_AUTH | SOCKS5_METHOD_USER_PASS) if method == offered => {
            Ok(method)
        }
        method @ (SOCKS5_METHOD_NO_AUTH | SOCKS5_METHOD_USER_PASS) => {
            bail!("SOCKS5 proxy selected method {method:#x} that was not offered")
        }
        0xff => bail!("SOCKS5 proxy rejected all authentication methods"),
        method => bail!("SOCKS5 proxy selected unsupported method {method:#x}"),
    }
}

fn socks5_auth_frame(username: &str, password: &str) -> Result<Vec<u8>> {
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        bail!("SOCKS5 username/password must be <= 255 bytes");
    }
    let mut frame = Vec::with_capacity(3 + username.len() + password.len());
    frame.push(0x01);
    frame.push(username.len() as u8);
    frame.extend_from_slice(username.as_bytes());
    frame.push(password.len() as u8);
    frame.extend_from_slice(password.as_bytes());
    Ok(frame)
}

fn parse_socks5_auth_reply(reply: [u8; 2]) -> Result<()> {
    if reply != [0x01, 0x00] {
        bail!("SOCKS5 username/password authentication failed");
    }
    Ok(())
}

fn socks5_connect_request_frame(dest: Destination) -> Vec<u8> {
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
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
    req
}

fn socks5_greet(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
    deadline: Deadline,
) -> Result<()> {
    let with_auth = username.is_some() || password.is_some();
    write_all_with_deadline(stream, &socks5_greeting_frame(with_auth), deadline)?;

    let mut method_resp = [0_u8; 2];
    read_exact_with_deadline(stream, &mut method_resp, deadline)?;
    let offered = if with_auth {
        SOCKS5_METHOD_USER_PASS
    } else {
        SOCKS5_METHOD_NO_AUTH
    };
    if parse_socks5_method_reply(method_resp, offered)? == SOCKS5_METHOD_USER_PASS {
        authenticate_socks5(
            stream,
            username.unwrap_or(""),
            password.unwrap_or(""),
            deadline,
        )?;
    }
    Ok(())
}

fn authenticate_socks5(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    deadline: Deadline,
) -> Result<()> {
    write_all_with_deadline(stream, &socks5_auth_frame(username, password)?, deadline)?;

    let mut resp = [0_u8; 2];
    read_exact_with_deadline(stream, &mut resp, deadline)?;
    parse_socks5_auth_reply(resp)
}

/// Sends the CONNECT request on a stream whose greeting/auth already
/// completed and consumes the proxy reply. Shared by the cold dial path and
/// warm-session lease completion.
fn socks5_request(stream: &mut TcpStream, dest: Destination, deadline: Deadline) -> Result<()> {
    write_all_with_deadline(stream, &socks5_connect_request_frame(dest), deadline)?;
    let _ = read_socks5_reply_addr(stream, deadline)?;
    Ok(())
}

pub(crate) fn read_socks5_reply_addr(
    stream: &mut TcpStream,
    deadline: Deadline,
) -> Result<SocketAddr> {
    let mut head = [0_u8; 4];
    read_exact_with_deadline(stream, &mut head, deadline)?;
    if head[0] != 0x05 {
        bail!("bad SOCKS5 response version {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 request failed with reply code {:#x}", head[1]);
    }

    let ip = match head[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            read_exact_with_deadline(stream, &mut octets, deadline)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            read_exact_with_deadline(stream, &mut len, deadline)?;
            let mut name = vec![0_u8; len[0] as usize];
            read_exact_with_deadline(stream, &mut name, deadline)?;
            let host = String::from_utf8(name).context("SOCKS5 relay domain is not UTF-8")?;
            let mut port_buf = [0_u8; 2];
            read_exact_with_deadline(stream, &mut port_buf, deadline)?;
            let port = u16::from_be_bytes(port_buf);
            return resolve_one_with_deadline(format_host_port(&host, port), deadline);
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            read_exact_with_deadline(stream, &mut octets, deadline)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        atyp => bail!("bad SOCKS5 bind address type {atyp:#x}"),
    };
    let mut port = [0_u8; 2];
    read_exact_with_deadline(stream, &mut port, deadline)?;
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
    endpoint: &ProxyEndpoint,
    dest: Destination,
    deadline: Deadline,
    timings: &mut DialTimings,
) -> Result<TcpStream> {
    let connect_started = Instant::now();
    let connected = connect_with_deadline(endpoint, deadline);
    timings.connect = Some(connect_started.elapsed());
    let mut stream =
        connected.with_context(|| format!("connect HTTP proxy {}", endpoint.authority()))?;

    let handshake_started = Instant::now();
    let result: Result<()> = (|| {
        http_connect_request(&mut stream, dest, deadline)?;
        clear_handshake_timeouts(&stream)?;
        Ok(())
    })();
    timings.handshake = Some(handshake_started.elapsed());
    result?;
    Ok(stream)
}

/// Sends the CONNECT request on an established HTTP proxy connection and
/// consumes the response header. Shared by the cold dial path and
/// warm-session lease completion.
fn http_connect_request(
    stream: &mut TcpStream,
    dest: Destination,
    deadline: Deadline,
) -> Result<()> {
    write_all_with_deadline(stream, http_connect_frame(dest).as_bytes(), deadline)?;
    http_connect_read_reply(stream, deadline)
}

fn http_connect_frame(dest: Destination) -> String {
    let authority = dest.authority();
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )
}

pub(crate) fn http_connect_read_reply(stream: &mut TcpStream, deadline: Deadline) -> Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut peeked = [0_u8; 8192];
    loop {
        deadline.set_read_timeout(stream)?;
        let n = stream.peek(&mut peeked[..8192 - buf.len()])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed before completing CONNECT response",
            )
            .into());
        }

        let boundary_start = buf.len().saturating_sub(3);
        let mut boundary = Vec::with_capacity(buf.len() - boundary_start + n);
        boundary.extend_from_slice(&buf[boundary_start..]);
        boundary.extend_from_slice(&peeked[..n]);
        if let Some(offset) = find_bytes(&boundary, b"\r\n\r\n") {
            let header_end = boundary_start + offset + 4;
            let old_len = buf.len();
            buf.resize(header_end, 0);
            read_exact_with_deadline(stream, &mut buf[old_len..], deadline)?;
            break;
        }

        if buf.len() + n >= 8192 {
            bail!("HTTP proxy response header too large");
        }

        let old_len = buf.len();
        buf.resize(old_len + n, 0);
        read_exact_with_deadline(stream, &mut buf[old_len..], deadline)?;
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
    Ok(())
}

fn clear_handshake_timeouts(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(())
}

fn connect_with_deadline(endpoint: &ProxyEndpoint, deadline: Deadline) -> Result<TcpStream> {
    let mut last_err = None;
    for sockaddr in endpoint.addrs() {
        match TcpStream::connect_timeout(sockaddr, deadline.remaining()?) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .map(Into::into)
        .unwrap_or_else(|| anyhow!("no socket addresses resolved for {}", endpoint.authority())))
}

fn read_exact_with_deadline(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Deadline,
) -> io::Result<()> {
    while !buf.is_empty() {
        deadline.set_read_timeout(stream)?;
        match stream.read(buf) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

pub(crate) fn write_all_with_deadline(
    stream: &mut TcpStream,
    mut buf: &[u8],
    deadline: Deadline,
) -> io::Result<()> {
    while !buf.is_empty() {
        deadline.set_write_timeout(stream)?;
        match stream.write(buf) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => buf = &buf[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn resolve_one_with_deadline(authority: String, deadline: Deadline) -> Result<SocketAddr> {
    let resolver_authority = authority.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("yatht-socks-relay-resolver".to_string())
        .spawn(move || {
            let result = resolver_authority
                .to_socket_addrs()
                .map(|mut addrs| addrs.next());
            let _ = tx.send(result);
        })
        .context("spawn SOCKS5 relay resolver")?;
    match rx.recv_timeout(deadline.remaining()?) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => bail!("SOCKS5 relay domain resolved to no addresses"),
        Ok(Err(err)) => Err(err).context("resolve SOCKS5 relay domain"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "proxy deadline exceeded").into())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("SOCKS5 relay resolver stopped before producing a result")
        }
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
            conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\ntunnel")
                .unwrap();
        });

        let mut timings = DialTimings::default();
        let endpoint = ProxyEndpoint::new(addr.to_string());
        let mut stream = dial_http_connect_with_timings(
            &endpoint,
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Deadline::after(Duration::from_secs(2)),
            &mut timings,
        )
        .unwrap();
        assert!(timings.connect.is_some());
        assert!(timings.handshake.is_some());
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        let mut tunnel = [0_u8; 6];
        stream.read_exact(&mut tunnel).unwrap();
        assert_eq!(&tunnel, b"tunnel");
        drop(stream);
        handle.join().unwrap();
    }

    #[test]
    fn http_connect_slow_drip_cannot_extend_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() != 0 {
                if line == "\r\n" {
                    break;
                }
                line.clear();
            }
            for byte in b"HTTP/1.1 200" {
                if conn.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(40));
            }
        });

        let endpoint = ProxyEndpoint::new(addr.to_string());
        let started = Instant::now();
        let result = dial_http_connect_with_timings(
            &endpoint,
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Deadline::after(Duration::from_millis(120)),
            &mut DialTimings::default(),
        );
        let elapsed = started.elapsed();

        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(350), "elapsed={elapsed:?}");
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
        let endpoint = ProxyEndpoint::new(addr.to_string());
        let stream = dial_socks5_with_timings(
            &endpoint,
            None,
            None,
            Destination {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 443,
            },
            Deadline::after(Duration::from_secs(2)),
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

    #[test]
    fn greeting_frame_selects_method_by_auth_presence() {
        assert_eq!(socks5_greeting_frame(false), [0x05, 0x01, 0x00]);
        assert_eq!(socks5_greeting_frame(true), [0x05, 0x01, 0x02]);
    }

    #[test]
    fn method_reply_accepts_supported_methods_only() {
        assert_eq!(
            parse_socks5_method_reply([0x05, 0x00], SOCKS5_METHOD_NO_AUTH).unwrap(),
            0x00
        );
        assert_eq!(
            parse_socks5_method_reply([0x05, 0x02], SOCKS5_METHOD_USER_PASS).unwrap(),
            0x02
        );
        assert!(parse_socks5_method_reply([0x04, 0x00], SOCKS5_METHOD_NO_AUTH).is_err());
        assert!(parse_socks5_method_reply([0x05, 0xff], SOCKS5_METHOD_NO_AUTH).is_err());
        assert!(parse_socks5_method_reply([0x05, 0x01], SOCKS5_METHOD_NO_AUTH).is_err());
        assert!(parse_socks5_method_reply([0x05, 0x02], SOCKS5_METHOD_NO_AUTH).is_err());
    }

    #[test]
    fn auth_frame_encodes_username_password() {
        let frame = socks5_auth_frame("user", "pass").unwrap();
        assert_eq!(frame, b"\x01\x04user\x04pass");
        assert!(socks5_auth_frame(&"x".repeat(256), "").is_err());
    }

    #[test]
    fn auth_reply_requires_success_status() {
        assert!(parse_socks5_auth_reply([0x01, 0x00]).is_ok());
        assert!(parse_socks5_auth_reply([0x01, 0x01]).is_err());
        assert!(parse_socks5_auth_reply([0x00, 0x00]).is_err());
    }

    #[test]
    fn connect_request_frame_encodes_v4_and_v6() {
        let v4 = socks5_connect_request_frame(Destination {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            port: 443,
        });
        assert_eq!(v4, [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0x01, 0xbb]);

        let v6 = socks5_connect_request_frame(Destination {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 80,
        });
        assert_eq!(v6[..4], [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(v6[4..20], Ipv6Addr::LOCALHOST.octets());
        assert_eq!(v6[20..], [0x00, 0x50]);
    }
}
