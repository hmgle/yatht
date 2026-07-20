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
fn does_not_replace_non_socket_fd_for_udp_send() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_non_socket_sendto_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--proxy-local")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
}

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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
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
fn redirects_connected_dns_udp_over_tcp_proxy() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_connected_udp_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let dns_server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53532));
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
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
fn redirects_threaded_connected_dns_udp_over_tcp_proxy() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_threaded_connected_udp_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let dns_server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53533));
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
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
fn rewrites_dns_recvmsg_source_to_original_destination() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_recvmsg_source_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let dns_server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53534));
    let socks_thread = thread::spawn(move || {
        let (mut client, _) = socks.accept().unwrap();
        socks5_greet(&mut client);
        let _dest = read_socks5_request(&mut client);
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--enable-dns")
        .arg("--dns-server")
        .arg(dns_server.to_string())
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg("127.0.0.1:53")
        .arg("dns-query")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dns-ok");
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
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

#[test]
fn updates_connected_udp_destination_on_reconnect() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_reconnecting_udp_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let first_dest = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 4444));
    let second_dest = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 20), 5555));
    let (dest_tx, dest_rx) = mpsc::channel();

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        for response in [b"one-ok".as_slice(), b"two-ok".as_slice()] {
            let mut packet = vec![0_u8; 2048];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            packet.truncate(n);
            let (dest, payload) = parse_udp_packet(&packet);
            dest_tx.send((dest, payload.to_vec())).unwrap();
            let response = encode_udp_packet(dest, response);
            udp.send_to(&response, peer).unwrap();
        }

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg(first_dest.to_string())
        .arg("one")
        .arg(second_dest.to_string())
        .arg("two")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "one-ok:two-ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (first_dest, b"one".to_vec())
    );
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (second_dest, b"two".to_vec())
    );
    socks_thread.join().unwrap();
}

// A single unconnected UDP socket first sends to a proxied destination (which
// turns the fd into an AF_UNIX relay socketpair), then reuses the same fd to
// send to a direct-routed destination. The direct send must still reach its
// peer -- the relay performs it -- rather than failing EINVAL on the AF_UNIX fd.
#[test]
fn direct_send_on_relayized_fd_reaches_peer() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_dual_dest_udp_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    // 127.0.0.0/8 is bypassed by default, so this destination routes direct.
    let direct = UdpSocket::bind("127.0.0.1:0").unwrap();
    let direct_addr = direct.local_addr().unwrap();
    let proxied_dest = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 4444));
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
        let response = encode_udp_packet(dest, b"proxy-ok");
        udp.send_to(&response, peer).unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    // Plain UDP echo server standing in for the direct-routed peer.
    let direct_thread = thread::spawn(move || {
        let mut buf = vec![0_u8; 2048];
        let (n, peer) = direct.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"direct-query");
        direct.send_to(b"direct-ok", peer).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg(proxied_dest.to_string())
        .arg("proxy-query")
        .arg(direct_addr.to_string())
        .arg("direct-query")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "proxy-ok:direct-ok"
    );
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        proxied_dest
    );
    socks_thread.join().unwrap();
    direct_thread.join().unwrap();
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

fn build_dual_dest_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("dual_dest_udp_probe.rs");
    let bin = dir.path().join("dual_dest_udp_probe");
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

    // First send goes to a proxied destination, turning the fd into a relay.
    socket.send_to(args[2].as_bytes(), &args[1]).unwrap();
    let mut buf = [0_u8; 2048];
    let (n, _) = socket.recv_from(&mut buf).unwrap();
    let first = String::from_utf8_lossy(&buf[..n]).into_owned();

    // Reuse the same fd for a direct-routed destination.
    socket.send_to(args[4].as_bytes(), &args[3]).unwrap();
    let (n, _) = socket.recv_from(&mut buf).unwrap();
    let second = String::from_utf8_lossy(&buf[..n]).into_owned();

    print!("{first}:{second}");
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

fn build_non_socket_sendto_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("non_socket_sendto_probe.c");
    let bin = dir.path().join("non_socket_sendto_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 2;

    struct stat before;
    if (fstat(fd, &before) != 0) return 3;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    if (inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr) != 1) return 4;

    errno = 0;
    ssize_t rc = sendto(fd, "x", 1, 0,
                        (struct sockaddr *)&dest, sizeof(dest));
    if (rc != -1 || errno != ENOTSOCK) return 5;

    struct stat after;
    if (fstat(fd, &after) != 0) return 6;
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mode != after.st_mode) return 7;

    int replaced = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (replaced < 0) return 8;
    if (dup2(fd, replaced) != replaced) return 9;
    struct stat duplicated;
    if (fstat(replaced, &duplicated) != 0) return 10;
    if (before.st_dev != duplicated.st_dev ||
        before.st_ino != duplicated.st_ino) return 11;

    int cloexec = open("/dev/zero", O_RDONLY);
    if (cloexec < 0) return 12;
    if (dup3(fd, cloexec, O_CLOEXEC) != cloexec) return 13;
    if ((fcntl(cloexec, F_GETFD) & FD_CLOEXEC) == 0) return 14;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_connected_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("connected_udp_probe.rs");
    let bin = dir.path().join("connected_udp_probe");
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
    socket.connect(&args[1]).unwrap();
    socket.send(args[2].as_bytes()).unwrap();
    let mut buf = [0_u8; 2048];
    let n = socket.recv(&mut buf).unwrap();
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

fn build_threaded_connected_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("threaded_connected_udp_probe.rs");
    let bin = dir.path().join("threaded_connected_udp_probe");
    fs::write(
        &src,
        r#"
use std::env;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let dest = args[1].clone();
    let payload = args[2].clone();
    let output = thread::spawn(move || {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.connect(dest).unwrap();
        socket.send(payload.as_bytes()).unwrap();
        let mut buf = [0_u8; 2048];
        let n = socket.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    })
    .join()
    .unwrap();
    print!("{output}");
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

fn build_recvmsg_source_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("recvmsg_source_probe.c");
    let bin = dir.path().join("recvmsg_source_probe");
    fs::write(
        &src,
        r#"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;

    char dest_arg[64];
    snprintf(dest_arg, sizeof(dest_arg), "%s", argv[1]);
    char *colon = strrchr(dest_arg, ':');
    if (!colon) return 3;
    *colon = '\0';

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((unsigned short)atoi(colon + 1));
    if (inet_pton(AF_INET, dest_arg, &dest.sin_addr) != 1) return 4;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return 5;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) return 6;

    size_t payload_len = strlen(argv[2]);
    ssize_t sent = sendto(fd, argv[2], payload_len, MSG_NOSIGNAL,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent != (ssize_t)payload_len) return 7;

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, 5000) <= 0) return 8;

    char buf[2048];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct sockaddr_in peer;
    struct msghdr msg;
    memset(&peer, 0, sizeof(peer));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0) return 9;
    if (peer.sin_family != AF_INET ||
        peer.sin_port != dest.sin_port ||
        peer.sin_addr.s_addr != dest.sin_addr.s_addr) {
        return 10;
    }
    if (write(STDOUT_FILENO, buf, (size_t)n) != n) return 11;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_reconnecting_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("reconnecting_udp_probe.rs");
    let bin = dir.path().join("reconnecting_udp_probe");
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

    socket.connect(&args[1]).unwrap();
    socket.send(args[2].as_bytes()).unwrap();
    let mut buf = [0_u8; 2048];
    let n = socket.recv(&mut buf).unwrap();
    print!("{}", String::from_utf8_lossy(&buf[..n]));

    socket.connect(&args[3]).unwrap();
    socket.send(args[4].as_bytes()).unwrap();
    let n = socket.recv(&mut buf).unwrap();
    print!(":{}", String::from_utf8_lossy(&buf[..n]));
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
