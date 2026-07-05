use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

#[test]
fn redirects_dns_udp_over_tcp_proxy() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let dns_server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53531));
    let (dest_tx, dest_rx) = mpsc::channel();
    let socks_thread = thread::spawn(move || {
        let (mut client, _) = socks.accept().unwrap();
        socks5_greet(&mut client);
        let dest = read_socks5_request(&mut client);
        dest_tx.send(dest).unwrap();
        client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();

        let mut len = [0_u8; 2];
        client.read_exact(&mut len).unwrap();
        let query_len = u16::from_be_bytes(len) as usize;
        let mut query = vec![0_u8; query_len];
        client.read_exact(&mut query).unwrap();
        assert_eq!(query, b"dns-query");
        client.write_all(&6_u16.to_be_bytes()).unwrap();
        client.write_all(b"dns-ok").unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_seccomp-unotify-proxy"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--enable-dns")
        .arg("--dns-server")
        .arg(dns_server.to_string())
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg("8.8.8.8:53")
        .arg("dns-query")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dns-ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        dns_server
    );
    socks_thread.join().unwrap();
}

#[test]
fn redirects_generic_udp_over_socks5_associate() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let (dest_tx, dest_rx) = mpsc::channel();

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        let mut packet = vec![0_u8; 2048];
        let (n, peer) = udp.recv_from(&mut packet).unwrap();
        packet.truncate(n);
        let (dest, _) = parse_udp_packet(&packet);
        dest_tx.send(dest).unwrap();
        let response = encode_udp_packet(dest, b"udp-ok");
        udp.send_to(&response, peer).unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_seccomp-unotify-proxy"))
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg("198.51.100.10:4444")
        .arg("udp-query")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "udp-ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 4444))
    );
    socks_thread.join().unwrap();
}

fn build_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_probe.rs");
    let bin = dir.path().join("udp_probe");
    fs::write(
        &src,
        r#"
use std::env;
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.send_to(args[2].as_bytes(), &args[1]).unwrap();
    let mut buf = [0_u8; 2048];
    let (n, _) = socket.recv_from(&mut buf).unwrap();
    print!("{}", String::from_utf8_lossy(&buf[..n]));
}
"#,
    )
    .unwrap();
    let status = Command::new("rustc")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn socks5_greet(stream: &mut TcpStream) {
    let mut head = [0_u8; 2];
    stream.read_exact(&mut head).unwrap();
    let mut methods = vec![0_u8; head[1] as usize];
    stream.read_exact(&mut methods).unwrap();
    assert!(methods.contains(&0));
    stream.write_all(&[5, 0]).unwrap();
}

fn read_socks5_request(stream: &mut TcpStream) -> SocketAddr {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[0], 5);
    let addr = match head[3] {
        1 => {
            let mut ip = [0_u8; 4];
            stream.read_exact(&mut ip).unwrap();
            Ipv4Addr::from(ip)
        }
        atyp => panic!("unsupported ATYP {atyp}"),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).unwrap();
    SocketAddr::from((addr, u16::from_be_bytes(port)))
}

fn parse_udp_packet(packet: &[u8]) -> (SocketAddr, &[u8]) {
    assert_eq!(&packet[..4], &[0, 0, 0, 1]);
    let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    (SocketAddr::from((ip, port)), &packet[10..])
}

fn encode_udp_packet(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(dest) = dest else {
        panic!("expected IPv4 destination");
    };
    let mut out = vec![0, 0, 0, 1];
    out.extend_from_slice(&dest.ip().octets());
    out.extend_from_slice(&dest.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
