use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const UDP_METADATA_QUERY: &[u8] = b"receive-metadata-query";
const UDP_METADATA_RESPONSE: &[u8] = b"receive-metadata-response";
const UDP_RECVMMSG_QUERIES: [&[u8]; 4] = [
    b"recvmmsg-query-one",
    b"recvmmsg-query-two",
    b"recvmmsg-query-three",
    b"recvmmsg-query-four",
];
const UDP_RECVMMSG_RESPONSES: [&[u8]; 4] = [
    b"recvmmsg-first-response",
    b"recvmmsg-second-response",
    b"recvmmsg-third-response",
    b"recvmmsg-fourth-response",
];
const UDP_RECVMMSG_FLAG_QUERIES: [&[u8]; 3] = [
    b"recvmmsg-peek-query",
    b"recvmmsg-wait-one-query",
    b"recvmmsg-wait-two-query",
];
const UDP_RECVMMSG_FLAG_RESPONSES: [&[u8]; 3] = [
    b"recvmmsg-peek-response",
    b"recvmmsg-wait-one-response",
    b"recvmmsg-wait-two-response",
];
const UDP_RCVTIMEO_BATCH_QUERIES: [&[u8]; 2] =
    [b"rcvtimeo-batch-query-one", b"rcvtimeo-batch-query-two"];
const UDP_RCVTIMEO_BATCH_RESPONSES: [&[u8]; 2] = [
    b"rcvtimeo-batch-response-one",
    b"rcvtimeo-batch-response-two",
];
const UDP_RCVTIMEO_LATE_QUERY: &[u8] = b"rcvtimeo-late-query";
const UDP_RCVTIMEO_LATE_RESPONSE: &[u8] = b"rcvtimeo-late-response";
const UDP_RCVTIMEO_PROMPT_QUERY: &[u8] = b"rcvtimeo-prompt-query";
const UDP_RCVTIMEO_PROMPT_RESPONSE: &[u8] = b"rcvtimeo-prompt-response";
// The probe arms a 500 ms SO_RCVTIMEO; the batch gap must stay well under it
// so the per-entry reset keeps both responses, and the late delay must exceed
// it so a cleared timeout provably blocks past the old deadline.
const UDP_RCVTIMEO_BATCH_GAP: Duration = Duration::from_millis(250);
const UDP_RCVTIMEO_LATE_DELAY: Duration = Duration::from_millis(700);

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
fn quiet_dns_sockets_do_not_starve_active_receive() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    const QUIET_RECEIVES: usize = 70;

    let (_probe_dir, probe) = build_quiet_receive_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let dns_server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53535));
    let socks_thread = thread::spawn(move || {
        let quiet_ready = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let mut handlers = Vec::new();
        for _ in 0..=QUIET_RECEIVES {
            let (mut client, _) = socks.accept().unwrap();
            let handler_quiet_ready = Arc::clone(&quiet_ready);
            handlers.push(thread::spawn(move || {
                socks5_greet(&mut client);
                let _dest = read_socks5_request(&mut client);
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();

                let mut len = [0_u8; 2];
                client.read_exact(&mut len).unwrap();
                let query_len = u16::from_be_bytes(len) as usize;
                let mut query = vec![0_u8; query_len];
                client.read_exact(&mut query).unwrap();
                if query == b"active" {
                    let (lock, ready) = &*handler_quiet_ready;
                    let mut quiet_count = lock.lock().unwrap();
                    while *quiet_count < QUIET_RECEIVES {
                        quiet_count = ready.wait(quiet_count).unwrap();
                    }
                    client.write_all(&9_u16.to_be_bytes()).unwrap();
                    client.write_all(b"active-ok").unwrap();
                } else {
                    let (lock, ready) = &*handler_quiet_ready;
                    *lock.lock().unwrap() += 1;
                    ready.notify_all();
                }

                let mut keepalive = [0_u8; 1];
                let _ = client.read(&mut keepalive);
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--enable-dns")
        .arg("--dns-server")
        .arg(dns_server.to_string())
        .arg("--")
        .arg(&probe)
        .arg("8.8.8.8:53")
        .arg(QUIET_RECEIVES.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "active-ok");
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
fn direct_kernel_udp_receive_metadata_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_receive_metadata_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_exchange();

    let output = Command::new(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "receive-metadata-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn direct_kernel_udp_socket_error_semantics_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_socket_error_probe();
    let output = Command::new(&probe).output().unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "socket-errors-ok");
}

#[test]
fn stable_udp_matches_socket_error_semantics() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_socket_error_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "socket-errors-ok");
}

#[test]
fn direct_kernel_udp_address_semantics_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_address_semantics_probe();
    let output = Command::new(&probe).output().unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "address-semantics-ok"
    );
}

#[test]
fn stable_udp_matches_address_semantics() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_address_semantics_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "address-semantics-ok"
    );
}

fn assert_udp_name_length_semantics(socket_mode: Option<&str>) {
    let (_probe_dir, probe) = build_udp_name_length_probe();
    let output = match socket_mode {
        Some(mode) => Command::new(env!("CARGO_BIN_EXE_yatht"))
            .arg("--udp-socket-mode")
            .arg(mode)
            .arg("--proxy")
            .arg("socks5://127.0.0.1:9")
            .arg("--enable-udp")
            .arg("--")
            .arg(&probe)
            .output()
            .unwrap(),
        None => Command::new(&probe).output().unwrap(),
    };

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "name-lengths-ok");
}

#[test]
fn direct_kernel_udp_name_length_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_udp_name_length_semantics(None);
}

#[test]
fn stable_udp_preserves_name_length_semantics() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_udp_name_length_semantics(Some("stable"));
}

#[test]
fn direct_kernel_udp_send_destination_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_send_destination_probe();
    let peer = UdpSocket::bind("[::1]:0").unwrap();
    let output = Command::new(&probe)
        .arg(peer.local_addr().unwrap().port().to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "send-destination-ok"
    );
}

#[test]
fn stable_udp_matches_send_destination_semantics() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_send_destination_probe();
    let peer = UdpSocket::bind("[::1]:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(peer.local_addr().unwrap().port().to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "send-destination-ok"
    );
}

#[test]
fn lazy_udp_matches_send_destination_semantics() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_send_destination_probe();
    let peer = UdpSocket::bind("[::1]:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("lazy")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(peer.local_addr().unwrap().port().to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "send-destination-ok"
    );
}

/// The UDP filters trap send syscalls for every fd, so a TCP, AF_UNIX or stale
/// fd must keep the kernel's own limits rather than the UDP datagram cap.
fn assert_cross_protocol_sends_reach_the_kernel(socket_mode: Option<&str>) {
    let (_probe_dir, probe) = build_cross_protocol_send_probe();
    let output = match socket_mode {
        Some(mode) => Command::new(env!("CARGO_BIN_EXE_yatht"))
            .arg("--udp-socket-mode")
            .arg(mode)
            .arg("--proxy")
            .arg("socks5://127.0.0.1:9")
            .arg("--enable-udp")
            .arg("--")
            .arg(&probe)
            .output()
            .unwrap(),
        None => Command::new(&probe).output().unwrap(),
    };

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cross-protocol-send-ok"
    );
}

#[test]
fn direct_kernel_cross_protocol_send_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_cross_protocol_sends_reach_the_kernel(None);
}

#[test]
fn stable_udp_leaves_non_udp_sends_to_the_kernel() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_cross_protocol_sends_reach_the_kernel(Some("stable"));
}

#[test]
fn lazy_udp_leaves_non_udp_sends_to_the_kernel() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_cross_protocol_sends_reach_the_kernel(Some("lazy"));
}

fn assert_connected_udplite_preserves_protocol(socket_mode: Option<&str>) {
    let (_probe_dir, probe) = build_connected_udplite_probe();
    let output = match socket_mode {
        Some(mode) => Command::new(env!("CARGO_BIN_EXE_yatht"))
            .arg("--udp-socket-mode")
            .arg(mode)
            .arg("--proxy")
            .arg("socks5://127.0.0.1:9")
            .arg("--enable-udp")
            .arg("--")
            .arg(&probe)
            .output()
            .unwrap(),
        None => Command::new(&probe).output().unwrap(),
    };

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "connected-udplite-ok"
    );
}

#[test]
fn direct_kernel_connected_udplite_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_connected_udplite_preserves_protocol(None);
}

#[test]
fn stable_udp_preserves_connected_udplite_protocol() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_connected_udplite_preserves_protocol(Some("stable"));
}

#[test]
fn direct_kernel_udp_getsockopt_truncation_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_getsockopt_probe();
    let output = Command::new(&probe).output().unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "getsockopt-ok");
}

#[test]
fn stable_udp_preserves_getsockopt_truncation() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_getsockopt_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "getsockopt-ok");
}

#[test]
fn direct_kernel_recvmmsg_source_and_mixed_receive_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_source_probe();
    let (destination, response_sources, server_thread) = spawn_changed_source_udp_batch_exchange();

    let output = Command::new(&probe)
        .arg(destination.to_string())
        .args(response_sources.map(|source| source.to_string()))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "recvmmsg-ok");
    server_thread.join().unwrap();
}

#[test]
fn direct_kernel_recvmmsg_error_and_nonblocking_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_error_probe();
    let output = Command::new(&probe).output().unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-errors-ok"
    );
}

#[test]
fn stable_udp_recvmmsg_matches_error_and_nonblocking_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_error_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-errors-ok"
    );
}

#[test]
fn direct_kernel_recvmmsg_timeout_write_fault_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_timeout_fault_probe();
    let (destination, server_thread) = spawn_udp_recvmmsg_timeout_fault_exchange();
    let output = Command::new(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-timeout-fault-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_recvmmsg_timeout_write_fault_overrides_batch_count() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_timeout_fault_probe();
    let (destination, server_thread) = spawn_udp_recvmmsg_timeout_fault_exchange();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-timeout-fault-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_recvmmsg_honors_an_empty_queue_deadline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_deadline_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-deadline-ok"
    );
}

#[test]
fn direct_kernel_udp_receive_rcvtimeo_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_rcvtimeo_probe();
    let (destination, server_thread) = spawn_udp_rcvtimeo_exchange();

    let output = Command::new(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rcvtimeo-ok");
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_direct_receive_honors_rcvtimeo() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_rcvtimeo_probe();
    let (destination, server_thread) = spawn_udp_rcvtimeo_exchange();

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rcvtimeo-ok");
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_proxy_receive_honors_rcvtimeo() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_rcvtimeo_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 23), 4499));

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        for (expected_query, response, delay) in udp_rcvtimeo_script() {
            let mut packet = vec![0_u8; 2048];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            packet.truncate(n);
            let (actual_destination, payload) = parse_udp_packet(&packet);
            assert_eq!(actual_destination, destination);
            assert_eq!(payload, expected_query);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            udp.send_to(&encode_udp_packet(destination, response), peer)
                .unwrap();
        }

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rcvtimeo-ok");
    socks_thread.join().unwrap();
}

#[test]
fn lazy_udp_relay_receive_honors_rcvtimeo() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_lazy_udp_rcvtimeo_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 24), 4499));

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
        let (actual_destination, payload) = parse_udp_packet(&packet);
        assert_eq!(actual_destination, destination);
        assert_eq!(payload, UDP_RCVTIMEO_PROMPT_QUERY);
        udp.send_to(
            &encode_udp_packet(destination, UDP_RCVTIMEO_PROMPT_RESPONSE),
            peer,
        )
        .unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "lazy-rcvtimeo-ok");
    socks_thread.join().unwrap();
}

#[test]
fn direct_kernel_recvmmsg_returns_partial_count_before_bad_entry() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_partial_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_exchange();
    let output = Command::new(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-partial-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_recvmmsg_returns_partial_count_before_bad_entry() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_partial_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_exchange();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "recvmmsg-partial-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn direct_kernel_recvmmsg_peek_and_waitforone_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_flag_probe();
    let (destination, response_sources, server_thread) = spawn_udp_recvmmsg_flag_exchange();
    let output = Command::new(&probe)
        .arg(destination.to_string())
        .args(response_sources.map(|source| source.to_string()))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "recvmmsg-flags-ok");
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_recvmmsg_preserves_peek_and_waitforone() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_flag_probe();
    let (destination, response_sources, server_thread) = spawn_udp_recvmmsg_flag_exchange();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .args(response_sources.map(|source| source.to_string()))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "recvmmsg-flags-ok");
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_direct_recvmmsg_preserves_sources_and_queue_order() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_source_probe();
    let (destination, response_sources, server_thread) = spawn_changed_source_udp_batch_exchange();

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .args(response_sources.map(|source| source.to_string()))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "recvmmsg-ok");
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_proxy_recvmmsg_preserves_sources_and_queue_order() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_source_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 15), 4499));
    let response_sources = [
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 31), 5601)),
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 32), 5602)),
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 33), 5603)),
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 34), 5604)),
    ];

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        for index in 0..4 {
            let mut packet = vec![0_u8; 2048];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            packet.truncate(n);
            let (actual_destination, payload) = parse_udp_packet(&packet);
            assert_eq!(actual_destination, destination);
            assert_eq!(payload, UDP_RECVMMSG_QUERIES[index]);
            udp.send_to(
                &encode_udp_packet(response_sources[index], UDP_RECVMMSG_RESPONSES[index]),
                peer,
            )
            .unwrap();
        }

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .args(response_sources.map(|source| source.to_string()))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "recvmmsg-ok");
    socks_thread.join().unwrap();
}

#[test]
fn direct_kernel_udp_dual_stack_address_baseline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_dual_stack_address_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_rounds(2);

    let output = Command::new(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "dual-stack-address-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn stable_udp_reports_dual_stack_addresses_as_v4_mapped() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_dual_stack_address_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_rounds(2);

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "dual-stack-address-ok"
    );
    server_thread.join().unwrap();
}

fn assert_dual_stack_bind_preserves_source_port(socket_mode: Option<&str>) {
    let (_probe_dir, probe) = build_udp_dual_stack_bind_probe();
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let destination = server.local_addr().unwrap();
    let bind_reservation = UdpSocket::bind("[::]:0").unwrap();
    let bind_port = bind_reservation.local_addr().unwrap().port();
    drop(bind_reservation);
    let (source_tx, source_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let mut payload = [0_u8; 32];
        let (received, source) = server.recv_from(&mut payload).unwrap();
        assert_eq!(&payload[..received], b"dual-stack-bind-query");
        source_tx.send(source).unwrap();
        server.send_to(b"dual-stack-bind-ok", source).unwrap();
    });

    let output = match socket_mode {
        Some(mode) => Command::new(env!("CARGO_BIN_EXE_yatht"))
            .arg("--udp-socket-mode")
            .arg(mode)
            .arg("--proxy")
            .arg("socks5://127.0.0.1:9")
            .arg("--enable-udp")
            .arg("--")
            .arg(&probe)
            .arg(destination.to_string())
            .arg(bind_port.to_string())
            .output()
            .unwrap(),
        None => Command::new(&probe)
            .arg(destination.to_string())
            .arg(bind_port.to_string())
            .output()
            .unwrap(),
    };

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "dual-stack-bind-ok"
    );
    assert_eq!(
        source_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .port(),
        bind_port
    );
    server_thread.join().unwrap();
}

#[test]
fn direct_kernel_dual_stack_bind_preserves_source_port() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_dual_stack_bind_preserves_source_port(None);
}

#[test]
fn stable_udp_dual_stack_bind_preserves_source_port() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    assert_dual_stack_bind_preserves_source_port(Some("stable"));
}

#[test]
fn stable_udp_direct_receive_reports_actual_response_source() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_receive_metadata_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_exchange();

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "receive-metadata-ok"
    );
    server_thread.join().unwrap();
}

#[test]
fn udp_relays_preserve_direct_dual_stack_family_switches() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_direct_family");
    assert!(Command::new("cc")
        .args([
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/probes/udp_direct_family.c",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for mode in ["native", "lazy", "dns", "stable"] {
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let v6 = UdpSocket::bind("[::1]:0").unwrap();
        let ports = [
            v4.local_addr().unwrap().port(),
            v6.local_addr().unwrap().port(),
        ];
        let echoes: Vec<_> = [v4, v6]
            .into_iter()
            .enumerate()
            .map(|(index, socket)| {
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                thread::spawn(move || {
                    for _ in 0..if index == 0 { 2 } else { 1 } {
                        let mut query = [0];
                        let Ok((n, peer)) = socket.recv_from(&mut query) else {
                            return;
                        };
                        socket.send_to(&query[..n], peer).unwrap();
                    }
                })
            })
            .collect();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_addr = socks.local_addr().unwrap();
        let dns = (mode != "native").then(|| {
            thread::spawn(move || {
                let (mut stream, _) = socks.accept().unwrap();
                socks5_greet(&mut stream);
                read_socks5_request(&mut stream);
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut query = [0; 3];
                stream.read_exact(&mut query).unwrap();
                assert_eq!(query, [0, 1, b'p']);
                stream.write_all(&query).unwrap();
                let _ = stream.read(&mut [0]);
            })
        });
        let mut command = if mode == "native" {
            Command::new(&probe)
        } else {
            let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
            command.args(["--enable-dns", "--proxy", &format!("socks5://{socks_addr}")]);
            if mode != "dns" {
                command.args(["--enable-udp", "--udp-socket-mode", mode]);
            }
            command.arg("--").arg(&probe);
            command
        };
        let output = command
            .arg(ports[0].to_string())
            .arg(ports[1].to_string())
            .arg(if mode == "native" { "0" } else { "1" })
            .output()
            .unwrap();
        for echo in echoes {
            echo.join().unwrap();
        }
        if let Some(dns) = dns {
            dns.join().unwrap();
        }
        assert_success(&output);
    }
}

#[test]
fn stable_udp_proxy_receive_reports_socks5_response_source() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_receive_metadata_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 14), 4488));
    let response_source = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 21), 5599));

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
        let (actual_destination, payload) = parse_udp_packet(&packet);
        assert_eq!(actual_destination, destination);
        assert_eq!(payload, UDP_METADATA_QUERY);
        udp.send_to(
            &encode_udp_packet(response_source, UDP_METADATA_RESPONSE),
            peer,
        )
        .unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .arg(response_source.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "receive-metadata-ok"
    );
    socks_thread.join().unwrap();
}

#[test]
fn stable_udp_socket_survives_bind_dup_close_and_fork() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_stable_udp_alias_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 11), 4455));
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
        let (dest, payload) = parse_udp_packet(&packet);
        dest_tx.send((dest, payload.to_vec())).unwrap();
        let response = encode_udp_packet(dest, b"stable-ok");
        udp.send_to(&response, peer).unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--debug")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "stable-ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (destination, b"stable-query".to_vec())
    );
    socks_thread.join().unwrap();
}

#[test]
fn lazy_udp_socket_survives_bind_dup_close_and_fork() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_lazy_alias");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_lazy_alias.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port().to_be_bytes();
    udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let server = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _ = read_socks5_request(&mut client);
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();
        for _ in 0..5 {
            let mut packet = [0; 128];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            let (_, payload) = parse_udp_packet(&packet[..n]);
            assert_eq!(payload, b"alias");
            udp.send_to(&packet[..n], peer).unwrap();
        }
        let _ = client.read(&mut [0]);
    });
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .args([
            "--udp-socket-mode",
            "lazy",
            "--enable-udp",
            "--proxy",
            &format!("socks5://{tcp_addr}"),
            "--",
        ])
        .arg(probe)
        .arg("198.51.100.11:4455")
        .output()
        .unwrap();
    assert_success(&output);
    server.join().unwrap();
}

#[test]
fn lazy_and_dns_udp_queries_report_internet_identity() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_lazy_identity");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_lazy_identity.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for enable in ["--enable-udp", "--enable-dns"] {
        let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
            .args([
                enable,
                "--udp-socket-mode",
                "lazy",
                "--proxy",
                "socks5://127.0.0.1:9",
                "--",
            ])
            .arg(&probe)
            .output()
            .unwrap();
        assert_success(&output);
    }
}

#[test]
fn udp_relay_limit_reports_enobufs() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_relay_limit");
    assert!(Command::new("cc")
        .args(["-O2", "-Wall", "-Wextra", "-Werror"])
        .arg("tests/probes/udp_relay_limit.c")
        .arg("-o")
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for mode in ["stable", "lazy"] {
        let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
            .args([
                "--udp-socket-mode",
                mode,
                "--proxy",
                "socks5://127.0.0.1:9",
                "--proxy-local",
                "--enable-udp",
                "--",
            ])
            .arg(&probe)
            .arg(mode)
            .output()
            .unwrap();
        assert_success(&output);
    }
}

#[test]
fn stable_udp_reclaims_closed_socket_capacity() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_stable_udp_lifetime_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "stable-lifetime-ok"
    );
}

#[test]
fn stable_udp_getsockname_reports_bound_port() {
    udp_getsockname_reports_bound_port(true);
}

#[test]
fn stable_udp_rejects_bind_after_send_or_connect() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_autobind");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_autobind.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    assert_success(&Command::new(&probe).output().unwrap());
    for proxy_local in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
        command.args([
            "--enable-udp",
            "--udp-socket-mode",
            "stable",
            "--proxy",
            "socks5://127.0.0.1:9",
        ]);
        if proxy_local {
            command.arg("--proxy-local");
        }
        let output = command.arg("--").arg(&probe).output().unwrap();
        assert_success(&output);
    }
}

#[test]
fn direct_kernel_udp_getsockname_reports_bound_port() {
    udp_getsockname_reports_bound_port(false);
}

#[test]
fn udp_disconnect_releases_ports_during_stalled_dns_setup() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_disconnect_port");
    assert!(Command::new("cc")
        .args([
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/probes/udp_disconnect_port.c",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for relayed in [false, true] {
        for family in ["4", "6"] {
            for binding in ["0", "1", "2"] {
                let udp = UdpSocket::bind(if family == "4" {
                    "127.0.0.1:0"
                } else {
                    "[::1]:0"
                })
                .unwrap();
                udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let port = udp.local_addr().unwrap().port();
                let echo = thread::spawn(move || {
                    for _ in 0..2 {
                        let mut query = [0];
                        let Ok((n, peer)) = udp.recv_from(&mut query) else {
                            return;
                        };
                        udp.send_to(&query[..n], peer).unwrap();
                    }
                });
                let socks = TcpListener::bind("127.0.0.1:0").unwrap();
                let bind_ip: std::net::IpAddr = if family == "4" { "0.0.0.0" } else { "::" }
                    .parse()
                    .unwrap();
                let reservation = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).unwrap();
                let explicit_port = reservation.local_addr().unwrap().port();
                drop(reservation);
                let mut command = if relayed {
                    let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
                    command
                        .args([
                            "--enable-udp",
                            "--enable-dns",
                            "--udp-socket-mode",
                            "stable",
                            "--proxy",
                            &format!("socks5://{}", socks.local_addr().unwrap()),
                            "--connect-timeout",
                            "5s",
                            "--",
                        ])
                        .arg(&probe);
                    command
                } else {
                    Command::new(&probe)
                };
                let mut child = command
                    .args([
                        family,
                        &port.to_string(),
                        binding,
                        if relayed { "1" } else { "0" },
                        &explicit_port.to_string(),
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdout = BufReader::new(child.stdout.take().unwrap());
                let mut line = String::new();
                stdout.read_line(&mut line).unwrap();
                let old_port: u16 = line
                    .strip_prefix("ready ")
                    .expect("probe did not bind")
                    .trim()
                    .parse()
                    .unwrap();
                let control = relayed.then(|| {
                    let (mut stream, _) = socks.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    // No reply yet: the I/O worker cannot process its wake fd.
                    stream
                });
                child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
                line.clear();
                stdout.read_line(&mut line).unwrap();
                let released = line == "released\n";
                assert!(
                    released,
                    "disconnect did not finish while DNS setup was stalled"
                );
                // Check from outside the supervised process: a stable-mode
                // close intentionally retains its reservation until reaping.
                let collision = UdpSocket::bind(SocketAddr::new(bind_ip, old_port));
                if binding == "2" {
                    assert_eq!(
                        collision.unwrap_err().raw_os_error(),
                        Some(libc::EADDRINUSE)
                    );
                } else {
                    drop(collision.expect("disconnect left the old port occupied"));
                }
                let dns = control.map(|mut stream| {
                    thread::spawn(move || {
                        stream.write_all(&[5, 0]).unwrap();
                        read_socks5_request(&mut stream);
                        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                        let mut query = [0; 3];
                        let _ = stream.read_exact(&mut query);
                        let _ = stream.read(&mut [0]);
                    })
                });
                child.stdin.take().unwrap().write_all(b"x").unwrap();
                let output = child.wait_with_output().unwrap();
                echo.join().unwrap();
                if let Some(dns) = dns {
                    dns.join().unwrap();
                }
                assert_success(&output);
            }
        }
    }
}

fn udp_getsockname_reports_bound_port(stable: bool) {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_bound_port");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_bound_port.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for (family, bind) in [("4", "127.0.0.1:0"), ("6", "[::1]:0")] {
        let server = UdpSocket::bind(bind).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            for _ in 0..2 {
                let mut payload = [0; 2];
                let (n, peer) = server.recv_from(&mut payload).unwrap();
                assert_eq!(n, 2);
                assert_eq!(u16::from_be_bytes(payload), peer.port());
                server.send_to(&payload, peer).unwrap();
            }
        });
        let mut command = if stable {
            let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
            command.args(["--enable-udp", "--udp-socket-mode", "stable", "--"]);
            command.arg(&probe);
            command
        } else {
            Command::new(&probe)
        };
        let output = command.arg(family).arg(port.to_string()).output().unwrap();
        assert_success(&output);
        echo.join().unwrap();
    }
}

#[test]
fn stable_udp_reaps_idle_closed_relay_workers() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    const SOCKET_COUNT: usize = 24;
    let (_probe_dir, probe) = build_stable_udp_idle_reap_probe();
    let mut child = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "open\n");
    let open_threads = process_thread_count(child.id());

    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "closed\n");
    assert!(open_threads >= SOCKET_COUNT * 2);
    let expected_max = open_threads - SOCKET_COUNT * 2;
    let deadline = Instant::now() + Duration::from_secs(3);
    let closed_threads = loop {
        let threads = process_thread_count(child.id());
        if threads <= expected_max || Instant::now() >= deadline {
            break threads;
        }
        thread::sleep(Duration::from_millis(20));
    };

    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "status={status:?}");
    assert!(
        closed_threads <= expected_max,
        "relay workers were not reaped: open={open_threads}, closed={closed_threads}"
    );
}

#[test]
fn rejects_stable_udp_socket_mode_without_generic_udp() {
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--")
        .arg("true")
        .output()
        .unwrap();

    assert!(!output.status.success(), "status={:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--udp-socket-mode=stable requires --enable-udp"),
        "{stderr}"
    );
}

#[test]
fn deprecated_udp_socket_mode_env_alias_selects_stable_mode() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    const SOCKET_COUNT: usize = 24;
    let (_probe_dir, probe) = build_stable_udp_idle_reap_probe();
    let lazy = run_idle_reap_probe(&probe, SocketModeSelector::Flag("lazy"));
    let aliased = run_idle_reap_probe(&probe, SocketModeSelector::DeprecatedEnv("stable"));

    assert!(
        aliased.threads >= lazy.threads + SOCKET_COUNT * 2,
        "deprecated alias did not select stable mode: lazy={}, aliased={}",
        lazy.threads,
        aliased.threads
    );
    assert!(
        aliased.stderr.contains("SUP_UDP_SOCKET_MODE is deprecated"),
        "{}",
        aliased.stderr
    );
    assert!(!lazy.stderr.contains("deprecated"), "{}", lazy.stderr);
}

#[test]
fn stable_udp_connected_socket_reports_logical_peer() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_connected_udp_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 13), 4477));
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
        let (dest, payload) = parse_udp_packet(&packet);
        dest_tx.send((dest, payload.to_vec())).unwrap();
        let response = encode_udp_packet(dest, b"connected-ok");
        udp.send_to(&response, peer).unwrap();

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--udp-socket-mode")
        .arg("stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .arg("connected-query")
        .arg("--check-peer")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "connected-ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (destination, b"connected-query".to_vec())
    );
    socks_thread.join().unwrap();
}

#[test]
fn stable_udp_sendmmsg_routes_batch_and_recvmmsg_reads_responses() {
    udp_sendmmsg_routes_first_batch("stable", false, false);
}

#[test]
fn lazy_udp_sendmmsg_creates_relay_on_first_batch() {
    udp_sendmmsg_routes_first_batch("lazy", false, false);
}

#[test]
fn lazy_udp_first_sendmmsg_preserves_mixed_routes_and_connected_peer() {
    for connected in [false, true] {
        udp_sendmmsg_routes_first_batch("lazy", true, connected);
    }
}

fn udp_sendmmsg_routes_first_batch(mode: &str, mixed: bool, connected: bool) {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_mmsg_probe();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 12), 4466));
    let (payload_tx, payload_rx) = mpsc::channel();
    let direct = mixed.then(|| UdpSocket::bind("127.0.0.1:0").unwrap());
    let direct_port = direct
        .as_ref()
        .map(|socket| socket.local_addr().unwrap().port());
    let direct_thread = direct.map(|socket| {
        thread::spawn(move || {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0; 64];
            let (n, peer) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"batch-one");
            socket.send_to(b"batch-one-ok", peer).unwrap();
        })
    });

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        for response in [b"batch-one-ok".as_slice(), b"batch-two-ok".as_slice()]
            .into_iter()
            .skip(usize::from(mixed))
        {
            let mut packet = vec![0_u8; 2048];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            packet.truncate(n);
            let (dest, payload) = parse_udp_packet(&packet);
            payload_tx.send((dest, payload.to_vec())).unwrap();
            udp.send_to(&encode_udp_packet(dest, response), peer)
                .unwrap();
        }

        let mut keepalive = [0_u8; 1];
        let _ = client.read(&mut keepalive);
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
    if let Some(port) = direct_port {
        command.env("YATHT_TEST_DIRECT_PORT", port.to_string());
    }
    if connected {
        command.env("YATHT_TEST_CONNECTED", "1");
    }
    let output = command
        .arg("--udp-socket-mode")
        .arg(mode)
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut responses = stdout.split(':').collect::<Vec<_>>();
    if mixed {
        // Independent direct/proxy peers have no cross-transport reply order.
        // Both requests and their route assertions below must still succeed.
        responses.sort_unstable();
    }
    assert_eq!(responses, ["batch-one-ok", "batch-two-ok"]);
    if !mixed {
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            (destination, b"batch-one".to_vec())
        );
    }
    assert_eq!(
        payload_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (destination, b"batch-two".to_vec())
    );
    socks_thread.join().unwrap();
    if let Some(thread) = direct_thread {
        thread.join().unwrap();
    }
}

#[test]
fn dns_sendmmsg_creates_relay_on_first_batch() {
    let (_probe_dir, probe) = build_udp_mmsg_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut client, _) = socks.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socks5_greet(&mut client);
        let _ = read_socks5_request(&mut client);
        client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        for query in [b"batch-one", b"batch-two"] {
            let mut len = [0; 2];
            client.read_exact(&mut len).unwrap();
            let mut payload = vec![0; u16::from_be_bytes(len) as usize];
            client.read_exact(&mut payload).unwrap();
            assert_eq!(payload, query);
            client.write_all(&12_u16.to_be_bytes()).unwrap();
            client.write_all(query).unwrap();
            client.write_all(b"-ok").unwrap();
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .args([
            "--proxy",
            &format!("socks5://{socks_addr}"),
            "--enable-dns",
            "--",
        ])
        .arg(probe)
        .arg("198.51.100.12:53")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "batch-one-ok:batch-two-ok"
    );
    server.join().unwrap();
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

fn build_stable_udp_alias_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("stable_udp_alias_probe.c");
    let bin = dir.path().join("stable_udp_alias_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int same_socket(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 3;

    struct stat created;
    if (fstat(fd, &created) != 0) return 4;
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 5;

    struct sockaddr_in reported;
    socklen_t reported_len = sizeof(reported);
    if (getsockname(fd, (struct sockaddr *)&reported, &reported_len) != 0
        || reported.sin_family != AF_INET) return 6;
    int domain = 0;
    socklen_t option_len = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &option_len) != 0
        || domain != AF_INET) return 7;
    int type = 0;
    option_len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_len) != 0
        || type != SOCK_DGRAM) return 8;
    int protocol = 0;
    option_len = sizeof(protocol);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &option_len) != 0
        || protocol != IPPROTO_UDP) return 9;

    struct stat after_bind;
    if (fstat(fd, &after_bind) != 0 || !same_socket(&created, &after_bind)) return 10;
    int alias = dup(fd);
    if (alias < 0) return 11;
    struct stat duplicated;
    if (fstat(alias, &duplicated) != 0 || !same_socket(&created, &duplicated)) return 12;
    if (close(fd) != 0) return 13;

    pid_t child = fork();
    if (child < 0) return 14;
    if (child == 0) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        char *colon = strrchr(argv[1], ':');
        if (colon == NULL) _exit(15);
        *colon = '\0';
        dest.sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
        if (inet_pton(AF_INET, argv[1], &dest.sin_addr) != 1) _exit(16);

        struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
        if (setsockopt(alias, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) _exit(17);
        if (sendto(alias, "stable-query", 12, 0,
                   (struct sockaddr *)&dest, sizeof(dest)) != 12) _exit(18);
        char response[64];
        ssize_t received = recvfrom(alias, response, sizeof(response), 0, NULL, NULL);
        if (received < 0) _exit(19);
        if (write(STDOUT_FILENO, response, (size_t)received) != received) _exit(20);
        _exit(0);
    }

    if (close(alias) != 0) return 21;
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 22;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 23;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_stable_udp_lifetime_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("stable_udp_lifetime_probe.c");
    let bin = dir.path().join("stable_udp_lifetime_probe");
    fs::write(
        &src,
        r#"
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    for (int index = 0; index < 160; ++index) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return 2;
        if (close(fd) != 0) return 3;
    }
    if (write(STDOUT_FILENO, "stable-lifetime-ok", 18) != 18) return 4;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_stable_udp_idle_reap_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("stable_udp_idle_reap_probe.c");
    let bin = dir.path().join("stable_udp_idle_reap_probe");
    fs::write(
        &src,
        r#"
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int sockets[24];
    for (int index = 0; index < 24; ++index) {
        sockets[index] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sockets[index] < 0) return 2;
    }
    if (write(STDOUT_FILENO, "open\n", 5) != 5) return 3;
    for (int index = 0; index < 24; ++index) {
        if (close(sockets[index]) != 0) return 4;
    }
    if (write(STDOUT_FILENO, "closed\n", 7) != 7) return 5;
    char done;
    if (read(STDIN_FILENO, &done, 1) != 1) return 6;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_mmsg_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_mmsg_probe.c");
    let bin = dir.path().join("udp_mmsg_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 3;
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 4;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    char *colon = strrchr(argv[1], ':');
    if (colon == NULL) return 5;
    *colon = '\0';
    dest.sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    if (inet_pton(AF_INET, argv[1], &dest.sin_addr) != 1) return 6;

    char first[] = "batch-one";
    char second[] = "batch-two";
    struct iovec send_iov[2] = {
        { .iov_base = first, .iov_len = sizeof(first) - 1 },
        { .iov_base = second, .iov_len = sizeof(second) - 1 },
    };
    struct mmsghdr send_msgs[3];
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int i = 0; i < 2; ++i) {
        send_msgs[i].msg_hdr.msg_name = &dest;
        send_msgs[i].msg_hdr.msg_namelen = sizeof(dest);
        send_msgs[i].msg_hdr.msg_iov = &send_iov[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    struct sockaddr_in direct = { .sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    const char *direct_port = getenv("YATHT_TEST_DIRECT_PORT");
    if (direct_port) {
        direct.sin_port = htons(atoi(direct_port));
        send_msgs[0].msg_hdr.msg_name = &direct;
        if (getenv("YATHT_TEST_CONNECTED")) {
            if (connect(fd, (struct sockaddr *)&direct, sizeof(direct))) return 17;
            send_msgs[0].msg_hdr.msg_name = NULL;
            send_msgs[0].msg_hdr.msg_namelen = 0;
        }
    }
    /* A later unsupported family must neither bypass the proxy for the
       entire fresh batch nor discard the successfully sent prefix. */
    struct sockaddr bad_name = { .sa_family = AF_UNIX };
    send_msgs[2].msg_hdr = send_msgs[0].msg_hdr;
    send_msgs[2].msg_hdr.msg_name = &bad_name;
    send_msgs[2].msg_hdr.msg_namelen = sizeof(bad_name);
    send_msgs[2].msg_len = 12345;
    if (sendmmsg(fd, send_msgs, 3, 0) != 2 || send_msgs[2].msg_len != 12345) return 7;

    /* An oversized named entry reports the first message's error. */
    static char big[65508];
    memset(big, 'x', sizeof big);
    struct iovec split[2] = {
        { .iov_base = big, .iov_len = 60000 },
        { .iov_base = big, .iov_len = 5508 },
    };
    struct mmsghdr oversized;
    memset(&oversized, 0, sizeof(oversized));
    oversized.msg_hdr.msg_name = &dest;
    oversized.msg_hdr.msg_namelen = sizeof(dest);
    oversized.msg_hdr.msg_iov = split;
    oversized.msg_hdr.msg_iovlen = 2;
    errno = 0;
    if (sendmmsg(fd, &oversized, 1, 0) != -1 || errno != EMSGSIZE) return 16;

    if (send_msgs[0].msg_len != sizeof(first) - 1 ||
        send_msgs[1].msg_len != sizeof(second) - 1) return 8;

    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 9;
    char responses[2][64];
    unsigned int lengths[2];
    for (int i = 0; i < 2; ++i) {
        struct iovec recv_iov = { .iov_base = responses[i], .iov_len = sizeof(responses[i]) };
        struct mmsghdr recv_msg;
        memset(&recv_msg, 0, sizeof(recv_msg));
        recv_msg.msg_hdr.msg_iov = &recv_iov;
        recv_msg.msg_hdr.msg_iovlen = 1;
        if (recvmmsg(fd, &recv_msg, 1, 0, NULL) != 1) return 10;
        lengths[i] = recv_msg.msg_len;
    }
    if (write(STDOUT_FILENO, responses[0], lengths[0]) != (ssize_t)lengths[0]) return 11;
    if (write(STDOUT_FILENO, ":", 1) != 1) return 12;
    if (write(STDOUT_FILENO, responses[1], lengths[1]) != (ssize_t)lengths[1]) return 13;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
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
    if args.get(3).is_some() {
        assert_eq!(socket.peer_addr().unwrap(), args[1].parse().unwrap());
    }
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

fn build_quiet_receive_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("quiet_receive_probe.rs");
    let bin = dir.path().join("quiet_receive_probe");
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
    let quiet_count = args[2].parse::<usize>().unwrap();
    let mut quiet_sockets = Vec::new();

    for _ in 0..quiet_count {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.send_to(b"quiet", &dest).unwrap();
        quiet_sockets.push(socket);
    }
    for socket in quiet_sockets {
        thread::spawn(move || {
            let mut buf = [0_u8; 16];
            let _ = socket.recv_from(&mut buf);
        });
    }

    thread::sleep(Duration::from_millis(250));
    let active = UdpSocket::bind("0.0.0.0:0").unwrap();
    active
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    active.send_to(b"active", &dest).unwrap();
    let mut buf = [0_u8; 16];
    let (n, _) = active.recv_from(&mut buf).unwrap();
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

    unsigned char control[64];
    memset(control, 0xa5, sizeof(control));
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t n = recvmsg(fd, &msg, 0);
    if (msg.msg_controllen != 0 || CMSG_FIRSTHDR(&msg) != NULL) return 12;
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

fn build_udp_dual_stack_address_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_dual_stack_address_probe.c");
    let bin = dir.path().join("udp_dual_stack_address_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char query[] = "receive-metadata-query";
static const char response[] = "receive-metadata-response";

static int split_address(const char *value, struct in_addr *ip, unsigned short *port) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    *port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, ip) == 1 ? 0 : -1;
}

static int parse_ipv4(const char *value, struct sockaddr_in *address) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    return split_address(value, &address->sin_addr, &address->sin_port);
}

/* Linux renders an IPv4 peer of a dual-stack socket as ::ffff:a.b.c.d. */
static int parse_v4_mapped(const char *value, struct sockaddr_in6 *address) {
    struct in_addr ipv4;
    unsigned short port;
    if (split_address(value, &ipv4, &port) != 0) return -1;
    memset(address, 0, sizeof(*address));
    address->sin6_family = AF_INET6;
    address->sin6_port = port;
    address->sin6_addr.s6_addr[10] = 0xff;
    address->sin6_addr.s6_addr[11] = 0xff;
    memcpy(&address->sin6_addr.s6_addr[12], &ipv4, sizeof(ipv4));
    return 0;
}

static int same_address(const struct sockaddr_in6 *left,
                        const struct sockaddr_in6 *right) {
    return left->sin6_family == right->sin6_family &&
           left->sin6_port == right->sin6_port &&
           memcmp(&left->sin6_addr, &right->sin6_addr, sizeof(left->sin6_addr)) == 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in6 expected_peer;
    struct sockaddr_in6 expected_source;
    if (parse_ipv4(argv[1], &destination) != 0 ||
        parse_v4_mapped(argv[1], &expected_peer) != 0 ||
        parse_v4_mapped(argv[2], &expected_source) != 0) return 3;

    int peer_fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (peer_fd < 0) return 4;
    if (connect(peer_fd, (struct sockaddr *)&destination, sizeof(destination)) != 0) return 5;
    struct sockaddr_in6 peer;
    socklen_t peer_len = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (getpeername(peer_fd, (struct sockaddr *)&peer, &peer_len) != 0) return 6;
    if (peer_len != sizeof(peer) || !same_address(&peer, &expected_peer)) return 7;
    if (close(peer_fd) != 0) return 8;

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 9;
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 10;
    if (sendto(fd, query, sizeof(query) - 1, MSG_NOSIGNAL,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(query) - 1)) return 11;

    char peek[7];
    struct sockaddr_in6 peek_source;
    socklen_t peek_source_len = sizeof(peek_source);
    memset(&peek_source, 0, sizeof(peek_source));
    ssize_t peeked = recvfrom(fd, peek, sizeof(peek), MSG_PEEK | MSG_TRUNC,
                              (struct sockaddr *)&peek_source, &peek_source_len);
    if (peeked != (ssize_t)(sizeof(response) - 1)) return 12;
    if (peek_source_len != sizeof(peek_source) ||
        !same_address(&peek_source, &expected_source)) return 13;

    char received[sizeof(response)];
    struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
    struct sockaddr_in6 msg_source;
    struct msghdr msg;
    memset(&msg_source, 0, sizeof(msg_source));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &msg_source;
    msg.msg_namelen = sizeof(msg_source);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ssize_t received_len = recvmsg(fd, &msg, 0);
    if (received_len != (ssize_t)(sizeof(response) - 1)) return 14;
    if (msg.msg_namelen != sizeof(msg_source) ||
        !same_address(&msg_source, &expected_source)) return 15;
    if (memcmp(received, response, sizeof(response) - 1) != 0) return 16;

    /* recvmmsg fills msg_name per entry and must map the source the same way. */
    if (sendto(fd, query, sizeof(query) - 1, MSG_NOSIGNAL,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(query) - 1)) return 17;

    char batch_payload[sizeof(response)];
    struct iovec batch_iov = {
        .iov_base = batch_payload, .iov_len = sizeof(batch_payload)
    };
    struct sockaddr_in6 batch_source;
    struct mmsghdr batch;
    memset(&batch_source, 0, sizeof(batch_source));
    memset(&batch, 0, sizeof(batch));
    batch.msg_hdr.msg_name = &batch_source;
    batch.msg_hdr.msg_namelen = sizeof(batch_source);
    batch.msg_hdr.msg_iov = &batch_iov;
    batch.msg_hdr.msg_iovlen = 1;
    if (recvmmsg(fd, &batch, 1, 0, NULL) != 1) return 18;
    if (batch.msg_len != (unsigned int)(sizeof(response) - 1)) return 19;
    if (batch.msg_hdr.msg_namelen != sizeof(batch_source) ||
        !same_address(&batch_source, &expected_source)) return 20;
    if (memcmp(batch_payload, response, sizeof(response) - 1) != 0) return 21;
    if (close(fd) != 0) return 22;

    if (write(STDOUT_FILENO, "dual-stack-address-ok", 21) != 21) return 23;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_dual_stack_bind_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_dual_stack_bind_probe.c");
    let bin = dir.path().join("udp_dual_stack_bind_probe");
    fs::write(
        &src,
        r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    char *colon = strrchr(argv[1], ':');
    if (colon == NULL) return 3;
    *colon = '\0';
    destination.sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    if (inet_pton(AF_INET, argv[1], &destination.sin_addr) != 1) return 4;

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 5;
    struct sockaddr_in6 local;
    memset(&local, 0, sizeof(local));
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    local.sin6_port = htons((unsigned short)strtoul(argv[2], NULL, 10));
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 6;

    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 7;
    static const char query[] = "dual-stack-bind-query";
    if (sendto(fd, query, sizeof(query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(query) - 1)) return 8;

    char response[32];
    ssize_t received = recv(fd, response, sizeof(response), 0);
    if (received != 18 || memcmp(response, "dual-stack-bind-ok", 18) != 0) return 9;
    if (write(STDOUT_FILENO, response, (size_t)received) != received) return 10;
    return close(fd);
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_receive_metadata_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_receive_metadata_probe.c");
    let bin = dir.path().join("udp_receive_metadata_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char query[] = "receive-metadata-query";
static const char response[] = "receive-metadata-response";

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static int same_address(const struct sockaddr_in *left,
                        const struct sockaddr_in *right) {
    return left->sin_family == right->sin_family &&
           left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in expected_source;
    if (parse_address(argv[1], &destination) != 0 ||
        parse_address(argv[2], &expected_source) != 0) return 3;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 5;
    if (sendto(fd, query, sizeof(query) - 1, MSG_NOSIGNAL,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(query) - 1)) return 6;

    char peek[7];
    struct sockaddr_in peek_source;
    socklen_t peek_source_len = sizeof(peek_source);
    memset(&peek_source, 0, sizeof(peek_source));
    ssize_t peeked = recvfrom(fd, peek, sizeof(peek), MSG_PEEK | MSG_TRUNC,
                              (struct sockaddr *)&peek_source, &peek_source_len);
    if (peeked != (ssize_t)(sizeof(response) - 1)) return 7;
    if (peek_source_len != sizeof(peek_source) ||
        !same_address(&peek_source, &expected_source)) return 8;
    if (memcmp(peek, response, sizeof(peek)) != 0) return 9;

    char received[9];
    unsigned char control[64];
    memset(control, 0xa5, sizeof(control));
    struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
    struct sockaddr_in msg_source;
    struct msghdr msg;
    memset(&msg_source, 0, sizeof(msg_source));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &msg_source;
    msg.msg_namelen = sizeof(msg_source);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t received_len = recvmsg(fd, &msg, 0);
    if (received_len != (ssize_t)sizeof(received)) return 10;
    if (msg.msg_controllen != 0 || CMSG_FIRSTHDR(&msg) != NULL) return 15;
    if ((msg.msg_flags & MSG_TRUNC) == 0) return 11;
    if (msg.msg_namelen != sizeof(msg_source) ||
        !same_address(&msg_source, &expected_source)) return 12;
    if (memcmp(received, response, sizeof(received)) != 0) return 13;
    if (write(STDOUT_FILENO, "receive-metadata-ok", 19) != 19) return 14;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_socket_error_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_socket_error_probe.c");
    let bin = dir.path().join("udp_socket_error_probe");
    fs::write(
        &src,
        r#"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;

    errno = 0;
    if (send(fd, "x", 1, 0) != -1 || errno != EDESTADDRREQ) return 3;

    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    errno = 0;
    if (sendmsg(fd, &msg, 0) != -1 || errno != EDESTADDRREQ) return 4;

    struct sockaddr_in6 ipv6;
    memset(&ipv6, 0, sizeof(ipv6));
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(9);
    ipv6.sin6_addr = in6addr_loopback;
    errno = 0;
    if (bind(fd, (struct sockaddr *)&ipv6, sizeof(ipv6)) != -1 ||
        errno != EAFNOSUPPORT) return 5;
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&ipv6, sizeof(ipv6)) != -1 ||
        errno != EAFNOSUPPORT) return 6;
    errno = 0;
    if (connect(fd, (struct sockaddr *)&ipv6, sizeof(ipv6)) != -1 ||
        errno != EAFNOSUPPORT) return 7;

    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&ipv4, sizeof(ipv4)) != 0) return 8;

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0 ||
        peer.sin_family != AF_INET || peer.sin_port != ipv4.sin_port ||
        peer.sin_addr.s_addr != ipv4.sin_addr.s_addr) return 9;

    struct sockaddr disconnected;
    memset(&disconnected, 0, sizeof(disconnected));
    disconnected.sa_family = AF_UNSPEC;
    if (connect(fd, &disconnected, sizeof(disconnected)) != 0) return 10;
    peer_len = sizeof(peer);
    errno = 0;
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != -1 ||
        errno != ENOTCONN) return 11;
    errno = 0;
    if (send(fd, "x", 1, 0) != -1 || errno != EDESTADDRREQ) return 12;

    if (write(STDOUT_FILENO, "socket-errors-ok", 16) != 16) return 13;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_cross_protocol_send_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("cross_protocol_send_probe.c");
    let bin = dir.path().join("cross_protocol_send_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Comfortably past the 65535-byte UDP datagram limit. */
static char bulk[70000];

enum tcp_send_operation {
    TCP_SENDMSG_UNNAMED,
    TCP_SENDMSG_NAMED,
    TCP_SENDTO_NAMED,
};

static int widen(int fd) {
    int size = 400000;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0) return -1;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

static ssize_t send_bulk(int fd, void *name, socklen_t name_len) {
    struct iovec iov = { .iov_base = bulk, .iov_len = sizeof(bulk) };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = name;
    msg.msg_namelen = name_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    errno = 0;
    return sendmsg(fd, &msg, MSG_DONTWAIT);
}

/* An AF_UNIX datagram carries the whole message or none of it, so it pins the
 * limit exactly; a stream may legitimately accept only part of it. */
static int check_unix_pair(int type, int atomic) {
    int fds[2];
    if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, fds) != 0) return -1;
    if (widen(fds[0]) != 0 || widen(fds[1]) != 0) { close(fds[0]); close(fds[1]); return -1; }
    ssize_t sent = send_bulk(fds[0], NULL, 0);
    close(fds[0]);
    close(fds[1]);
    if (atomic) return sent == (ssize_t)sizeof(bulk) ? 0 : -1;
    return sent > 0 ? 0 : -1;
}

static int check_tcp_send(int listener, struct sockaddr_in *address,
                          enum tcp_send_operation operation) {
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0) return -1;
    if (connect(client, (struct sockaddr *)address, sizeof(*address)) != 0) {
        close(client);
        return -1;
    }
    int served = accept(listener, NULL, NULL);
    if (served < 0) { close(client); return -1; }
    if (widen(client) != 0 || widen(served) != 0) { close(client); close(served); return -1; }

    struct sockaddr_in explicit_name;
    memset(&explicit_name, 0, sizeof(explicit_name));
    explicit_name.sin_family = AF_INET;
    explicit_name.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &explicit_name.sin_addr) != 1) {
        close(client);
        close(served);
        return -1;
    }
    ssize_t sent;
    if (operation == TCP_SENDTO_NAMED) {
        sent = sendto(client, bulk, sizeof(bulk), MSG_DONTWAIT,
                      (struct sockaddr *)&explicit_name, sizeof(explicit_name));
    } else {
        sent = send_bulk(client, operation == TCP_SENDMSG_NAMED ? &explicit_name : NULL,
                         operation == TCP_SENDMSG_NAMED ? sizeof(explicit_name) : 0);
    }
    close(client);
    close(served);
    return sent > 0 ? 0 : -1;
}

static int check_tcp(void) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return -1;
    socklen_t length = sizeof(address);
    if (bind(listener, (struct sockaddr *)&address, length) != 0 ||
        listen(listener, 2) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0) {
        close(listener);
        return -1;
    }

    int result = check_tcp_send(listener, &address, TCP_SENDMSG_UNNAMED);
    if (result == 0) result = check_tcp_send(listener, &address, TCP_SENDMSG_NAMED);
    if (result == 0) result = check_tcp_send(listener, &address, TCP_SENDTO_NAMED);
    close(listener);
    return result;
}

/* A closed fd outranks anything the message itself might be wrong about. */
static int check_stale_fd(void) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = (struct iovec *)1;
    msg.msg_iovlen = 1;
    errno = 0;
    if (sendmsg(-1, &msg, 0) != -1 || errno != EBADF) return -1;
    return 0;
}

static int check_udplite_send(int use_sendmsg) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDPLITE);
    if (fd < 0) return -1;
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &destination.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (use_sendmsg) {
        char payload = 'x';
        struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &destination;
        msg.msg_namelen = sizeof(destination);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        (void)sendmsg(fd, &msg, MSG_DONTWAIT);
    } else {
        (void)sendto(fd, "x", 1, MSG_DONTWAIT,
                     (struct sockaddr *)&destination, sizeof(destination));
    }

    int protocol = 0;
    socklen_t length = sizeof(protocol);
    int result = getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &length);
    close(fd);
    return result == 0 && length == sizeof(protocol) &&
           protocol == IPPROTO_UDPLITE ? 0 : -1;
}

int main(void) {
    if (check_unix_pair(SOCK_STREAM, 0) != 0) return 2;
    if (check_unix_pair(SOCK_DGRAM, 1) != 0) return 3;
    if (check_tcp() != 0) return 4;
    if (check_stale_fd() != 0) return 5;
    if (check_udplite_send(0) != 0) return 6;
    if (check_udplite_send(1) != 0) return 7;
    if (write(STDOUT_FILENO, "cross-protocol-send-ok", 22) != 22) return 8;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_connected_udplite_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("connected_udplite_probe.c");
    let bin = dir.path().join("connected_udplite_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDPLITE);
    if (fd < 0) return 2;
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &destination.sin_addr) != 1) return 3;
    if (connect(fd, (struct sockaddr *)&destination, sizeof(destination)) != 0) return 4;

    int protocol = 0;
    socklen_t length = sizeof(protocol);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &length) != 0 ||
        length != sizeof(protocol) || protocol != IPPROTO_UDPLITE) return 5;
    if (write(STDOUT_FILENO, "connected-udplite-ok", 20) != 20) return 6;
    return close(fd);
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_send_destination_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_send_destination_probe.c");
    let bin = dir.path().join("udp_send_destination_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* `sendto(2)` keeps msg_name set, so a zero length fails the destination
 * length check; `sendmsg(2)` drops the name and reports the unconnected
 * socket instead. */
static int check_empty_name(int domain) {
    struct sockaddr_storage address;
    socklen_t short_len;
    memset(&address, 0, sizeof(address));
    if (domain == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(9);
        if (inet_pton(AF_INET, "203.0.113.1", &ipv4->sin_addr) != 1) return -1;
        short_len = sizeof(*ipv4) - 1;
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(9);
        if (inet_pton(AF_INET6, "2001:db8::1", &ipv6->sin6_addr) != 1) return -1;
        /* IPv6 destinations only need SIN6_LEN_RFC2133 bytes. */
        short_len = 23;
    }

    int fd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&address, 0) != -1 ||
        errno != EINVAL) { close(fd); return -1; }

    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &address;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    errno = 0;
    if (sendmsg(fd, &msg, 0) != -1 || errno != EDESTADDRREQ) { close(fd); return -1; }

    /* A named send over the same socket still reaches the length check. */
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&address, short_len) != -1 ||
        errno != EINVAL) { close(fd); return -1; }

    return close(fd);
}

/* AF_UNSPEC and unsupported families only mean something relative to the
 * socket: an AF_INET socket reads AF_UNSPEC as AF_INET and rejects the rest
 * with EAFNOSUPPORT, while an AF_INET6 socket drops an AF_UNSPEC name and
 * rejects the rest with EINVAL. */
static int check_socket_relative_names(void) {
    struct sockaddr_in unspecified;
    memset(&unspecified, 0, sizeof(unspecified));
    unspecified.sin_family = AF_UNSPEC;
    unspecified.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &unspecified.sin_addr) != 1) return -1;
    struct sockaddr_in unknown = unspecified;
    unknown.sin_family = 1234;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&unspecified,
               sizeof(unspecified)) != 1) { close(fd); return -1; }
    struct sockaddr_in zero_port = unspecified;
    zero_port.sin_port = 0;
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&zero_port,
               sizeof(zero_port)) != -1 || errno != EINVAL) { close(fd); return -1; }
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&unknown, sizeof(unknown)) != -1 ||
        errno != EAFNOSUPPORT) { close(fd); return -1; }
    if (close(fd) != 0) return -1;

    struct sockaddr_in6 unspecified6;
    memset(&unspecified6, 0, sizeof(unspecified6));
    unspecified6.sin6_family = AF_UNSPEC;
    struct sockaddr_in6 unknown6 = unspecified6;
    unknown6.sin6_family = 1234;

    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&unspecified6,
               sizeof(unspecified6)) != -1 ||
        errno != EDESTADDRREQ) { close(fd); return -1; }
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&unknown6, sizeof(unknown6)) != -1 ||
        errno != EINVAL) { close(fd); return -1; }
    return close(fd);
}

/* Linux imports the iovec array while copying the message header, and
 * `udp_sendmsg` rejects an oversized datagram, both before it reports a
 * missing peer. Reading the buffers themselves happens after that verdict, so
 * a faulting `iov_base` must still surface as EDESTADDRREQ. */
static int check_iovec_import_order(void) {
    static char small[1];
    static struct iovec many[2000];
    struct iovec huge = { .iov_base = small, .iov_len = 200000 };
    struct iovec signed_max = { .iov_base = small, .iov_len = (size_t)SSIZE_MAX };
    struct iovec unsigned_max = { .iov_base = small, .iov_len = (size_t)-1 };
    struct iovec bad_base = { .iov_base = (void *)1, .iov_len = 1 };
    for (int index = 0; index < 2000; index++) {
        many[index].iov_base = small;
        many[index].iov_len = 0;
    }

    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &ipv4.sin_addr) != 1) return -1;

    struct sockaddr_in6 ipv6;
    memset(&ipv6, 0, sizeof(ipv6));
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(9);
    if (inet_pton(AF_INET6, "2001:db8::1", &ipv6.sin6_addr) != 1) return -1;

    /* An AF_INET6 socket drops an AF_UNSPEC name, reaching the same
     * unconnected-peer verdict by a different route. */
    struct sockaddr_in6 unspecified;
    memset(&unspecified, 0, sizeof(unspecified));
    unspecified.sin6_family = AF_UNSPEC;
    unspecified.sin6_port = htons(9);

    struct msghdr msg;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

#define SEND_MSG(name_ptr, name_len, iov_ptr, iov_count) \
    (memset(&msg, 0, sizeof(msg)), msg.msg_name = (name_ptr), \
     msg.msg_namelen = (name_len), msg.msg_iov = (iov_ptr), \
     msg.msg_iovlen = (iov_count), errno = 0, sendmsg(fd, &msg, 0))

    if (SEND_MSG(&ipv4, 0, (struct iovec *)1, 1) != -1 ||
        errno != EFAULT) { close(fd); return -1; }
    if (SEND_MSG(&ipv4, 0, &huge, 1) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }
    if (SEND_MSG(&ipv4, 0, many, 2000) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }
    /* A length that still fits a signed ssize_t is merely too long; one that
     * does not is rejected outright while the array is imported. */
    if (SEND_MSG(&ipv4, 0, &signed_max, 1) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }
    if (SEND_MSG(&ipv4, 0, &unsigned_max, 1) != -1 ||
        errno != EINVAL) { close(fd); return -1; }
    if (SEND_MSG(&ipv4, 0, &bad_base, 1) != -1 ||
        errno != EDESTADDRREQ) { close(fd); return -1; }
    /* A lazy socket must import the iovec array before rejecting a destination
     * from the wrong family, just as a socket with an existing relay does. */
    if (SEND_MSG(&ipv6, sizeof(ipv6), (struct iovec *)1, 1) != -1 ||
        errno != EFAULT) { close(fd); return -1; }

    struct mmsghdr batch;
    memset(&batch, 0, sizeof(batch));
    batch.msg_hdr.msg_name = &ipv4;
    batch.msg_hdr.msg_namelen = 0;
    batch.msg_hdr.msg_iovlen = 1;
    batch.msg_hdr.msg_iov = (struct iovec *)1;
    errno = 0;
    if (sendmmsg(fd, &batch, 1, 0) != -1 || errno != EFAULT) { close(fd); return -1; }
    batch.msg_hdr.msg_iov = &huge;
    errno = 0;
    if (sendmmsg(fd, &batch, 1, 0) != -1 || errno != EMSGSIZE) { close(fd); return -1; }
    batch.msg_hdr.msg_iov = &unsigned_max;
    errno = 0;
    if (sendmmsg(fd, &batch, 1, 0) != -1 || errno != EINVAL) { close(fd); return -1; }
    batch.msg_hdr.msg_iov = &bad_base;
    errno = 0;
    if (sendmmsg(fd, &batch, 1, 0) != -1 || errno != EDESTADDRREQ) { close(fd); return -1; }
    if (close(fd) != 0) return -1;

    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (SEND_MSG(&unspecified, sizeof(unspecified), (struct iovec *)1, 1) != -1 ||
        errno != EFAULT) { close(fd); return -1; }
    if (SEND_MSG(&unspecified, sizeof(unspecified), &bad_base, 1) != -1 ||
        errno != EDESTADDRREQ) { close(fd); return -1; }

#undef SEND_MSG

    return close(fd);
}

/* `udp_sendmsg` itself refuses only a datagram over the UDP length field;
 * the tighter IP-layer ceiling (65507 on the IPv4 transmission path, 65527
 * on IPv6) surfaces once a destination is known. The ceiling follows the
 * destination's transmission family, not the socket family: a v4-mapped
 * name on a dual-stack socket takes the IPv4 ceiling. */
static int check_datagram_size_limits(void) {
    static char payload[70000];
    memset(payload, 'x', sizeof payload);

    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    if (inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr) != 1) return -1;

    struct sockaddr_in6 mapped;
    memset(&mapped, 0, sizeof(mapped));
    mapped.sin6_family = AF_INET6;
    mapped.sin6_port = htons(9);
    if (inet_pton(AF_INET6, "::ffff:127.0.0.1", &mapped.sin6_addr) != 1) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    /* Use direct loopback routing to test the native IP ceiling. Proxied
     * envelope limits are covered separately by udp_payload_limit.c. */
    /* 65507 sits at the IPv4 ceiling: it must not be answered EMSGSIZE. */
    errno = 0;
    if (sendto(fd, payload, 65507, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) == -1 &&
        errno == EMSGSIZE) { close(fd); return -1; }
    errno = 0;
    if (sendto(fd, payload, 65508, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }
    errno = 0;
    if (sendto(fd, payload, 65535, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }

    /* An iovec split around the ceiling hits the same verdict. */
    struct iovec split[2] = {
        { .iov_base = payload, .iov_len = 60000 },
        { .iov_base = payload, .iov_len = 5508 },
    };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &ipv4;
    msg.msg_namelen = sizeof(ipv4);
    msg.msg_iov = split;
    msg.msg_iovlen = 2;

    errno = 0;
    if (sendmsg(fd, &msg, 0) != -1 || errno != EMSGSIZE) { close(fd); return -1; }

    /* The length verdict precedes the missing-destination one. */
    errno = 0;
    if (sendto(fd, payload, 70000, 0, NULL, 0) != -1 || errno != EMSGSIZE) {
        close(fd); return -1;
    }

    /* A connected socket sending with no name still hits the family ceiling
     * of its recorded peer once the datagram is over the UDP length field. */
    if (close(fd) != 0) return -1;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&ipv4, sizeof(ipv4)) != 0) { close(fd); return -1; }
    errno = 0;
    if (sendto(fd, payload, 65508, 0, NULL, 0) != -1 || errno != EMSGSIZE) {
        close(fd); return -1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &ipv4;
    msg.msg_namelen = 0;
    msg.msg_iov = split;
    msg.msg_iovlen = 2;
    errno = 0;
    if (sendmsg(fd, &msg, 0) != -1 || errno != EMSGSIZE) { close(fd); return -1; }
    if (close(fd) != 0) return -1;

    /* A dual-stack socket sending a v4-mapped name keeps the IPv4 ceiling. */
    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    errno = 0;
    if (sendto(fd, payload, 65508, 0, (struct sockaddr *)&mapped, sizeof(mapped)) != -1 ||
        errno != EMSGSIZE) { close(fd); return -1; }
    return close(fd);
}

/* sendmmsg clamps vlen to UIO_MAXIOV instead of rejecting it. The fresh
 * socket has no relay yet, so lazy runs take the kernel's own clamp while
 * stable runs exercise the virtualized one; through the dead proxy the
 * virtualized batch fails fast in the relay worker and the syscall still
 * reports every entry sent. */
static int check_sendmmsg_vlen_clamp(void) {
    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &ipv4.sin_addr) != 1) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    static struct mmsghdr msgs[1200];
    static struct iovec iovs[1200];
    static char one = 'x';
    for (int i = 0; i < 1200; ++i) {
        iovs[i].iov_base = &one;
        iovs[i].iov_len = 1;
        msgs[i].msg_hdr.msg_name = &ipv4;
        msgs[i].msg_hdr.msg_namelen = sizeof(ipv4);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    errno = 0;
    if (sendmmsg(fd, msgs, 1200, 0) != 1024) { close(fd); return -1; }
    return close(fd);
}

/* Once a proxied send has relay-ized the fd (lazily on first send or at
 * socket creation in stable mode), a named sendmmsg entry must keep UDP
 * semantics instead of reaching the injected AF_UNIX endpoint, which would
 * reject the non-AF_UNIX name with EINVAL. */
static int check_sendmmsg_on_relayed_socket(void) {
    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &ipv4.sin_addr) != 1) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (sendto(fd, "warm", 4, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) == -1 &&
        (errno == ENETUNREACH || errno == EHOSTUNREACH || errno == ENETDOWN)) {
        close(fd);
        return 0;
    }
    static char one = 'x';
    struct iovec iov = { .iov_base = &one, .iov_len = 1 };
    struct mmsghdr batch;
    memset(&batch, 0, sizeof(batch));
    batch.msg_hdr.msg_name = &ipv4;
    batch.msg_hdr.msg_namelen = sizeof(ipv4);
    batch.msg_hdr.msg_iov = &iov;
    batch.msg_hdr.msg_iovlen = 1;
    errno = 0;
    if (sendmmsg(fd, &batch, 1, 0) != 1 &&
        !(errno == ENETUNREACH || errno == EHOSTUNREACH || errno == ENETDOWN)) {
        close(fd);
        return -1;
    }
    return close(fd);
}

/* An empty sendmmsg batch reads no entry, so a null msgvec succeeds; a
 * non-empty one still faults reading the array. */
static int check_sendmmsg_empty_batch(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    errno = 0;
    if (sendmmsg(fd, NULL, 0, 0) != 0) { close(fd); return -1; }
    errno = 0;
    if (sendmmsg(fd, NULL, 1, 0) != -1 || errno != EFAULT) { close(fd); return -1; }
    return close(fd);
}

/* A dropped AF_UNSPEC name hands the datagram to the connected peer. Linux
 * only reaches a v4-mapped peer from the IPv4 fast path, which this call
 * bypasses, so the peer here is IPv6 to keep the check portable. */
static int check_connected_unspecified_name(const char *port) {
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons((unsigned short)strtoul(port, NULL, 10));
    if (inet_pton(AF_INET6, "::1", &address.sin6_addr) != 1) return -1;

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { close(fd); return -1; }
    struct sockaddr_in6 unspecified;
    memset(&unspecified, 0, sizeof(unspecified));
    unspecified.sin6_family = AF_UNSPEC;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&unspecified,
               sizeof(unspecified)) != 1) { close(fd); return -1; }
    return close(fd);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (check_empty_name(AF_INET) != 0) return 3;
    if (check_empty_name(AF_INET6) != 0) return 4;
    if (check_socket_relative_names() != 0) return 5;
    if (check_connected_unspecified_name(argv[1]) != 0) return 6;
    if (check_iovec_import_order() != 0) return 7;
    if (check_datagram_size_limits() != 0) return 9;
    if (check_sendmmsg_vlen_clamp() != 0) return 10;
    if (check_sendmmsg_on_relayed_socket() != 0) return 11;
    if (check_sendmmsg_empty_batch() != 0) return 12;
    if (write(STDOUT_FILENO, "send-destination-ok", 19) != 19) return 8;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_address_semantics_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_address_semantics_probe.c");
    let bin = dir.path().join("udp_address_semantics_probe");
    fs::write(
        &src,
        r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    struct sockaddr_in ipv4;
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(9);
    if (inet_pton(AF_INET, "203.0.113.1", &ipv4.sin_addr) != 1) return 2;

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 3;
    ssize_t sent = sendto(fd, "x", 1, 0, (struct sockaddr *)&ipv4, sizeof(ipv4));
    if (sent != 1) {
        dprintf(STDERR_FILENO, "dual-stack sendto rc=%zd errno=%d\n", sent, errno);
        return 4;
    }
    if (connect(fd, (struct sockaddr *)&ipv4, sizeof(ipv4)) != 0) return 5;
    if (close(fd) != 0) return 6;

    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 7;
    errno = 0;
    if (bind(fd, (struct sockaddr *)&ipv4, sizeof(ipv4)) != -1 ||
        errno != EINVAL) return 8;
    if (close(fd) != 0) return 9;

    struct {
        struct sockaddr_in address;
        unsigned char padding[8];
    } padded_ipv4;
    memset(&padded_ipv4, 0, sizeof(padded_ipv4));
    padded_ipv4.address = ipv4;
    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 10;
    errno = 0;
    if (bind(fd, (struct sockaddr *)&padded_ipv4, sizeof(padded_ipv4)) != -1 ||
        errno != EAFNOSUPPORT) return 11;
    if (close(fd) != 0) return 12;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 13;
    struct sockaddr_in zero_port = ipv4;
    zero_port.sin_port = 0;
    errno = 0;
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&zero_port,
               sizeof(zero_port)) != -1 || errno != EINVAL) return 14;

    struct sockaddr unknown;
    memset(&unknown, 0, sizeof(unknown));
    unknown.sa_family = 1234;
    errno = 0;
    if (sendto(fd, "x", 1, 0, &unknown, sizeof(unknown)) != -1 ||
        errno != EAFNOSUPPORT) return 15;
    if (close(fd) != 0) return 16;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 17;
    struct sockaddr_in unspecified;
    memset(&unspecified, 0, sizeof(unspecified));
    unspecified.sin_family = AF_UNSPEC;
    if (bind(fd, (struct sockaddr *)&unspecified, sizeof(unspecified)) != 0) return 18;
    if (close(fd) != 0) return 19;

    if (write(STDOUT_FILENO, "address-semantics-ok", 20) != 20) return 20;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_name_length_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_name_length_probe.c");
    let bin = dir.path().join("udp_name_length_probe");
    fs::write(
        &src,
        r#"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int check_getsockname(int fd) {
    socklen_t zero = 0;
    if (getsockname(fd, NULL, &zero) != 0 || zero != sizeof(struct sockaddr_in)) return -1;

    struct sockaddr_in address;
    memset(&address, 0xaa, sizeof(address));
    struct sockaddr_in unchanged = address;
    socklen_t negative = (socklen_t)-1;
    errno = 0;
    if (getsockname(fd, (struct sockaddr *)&address, &negative) != -1 ||
        errno != EINVAL || negative != (socklen_t)-1 ||
        memcmp(&address, &unchanged, sizeof(address)) != 0) return -1;
    return 0;
}

static int check_getpeername(int fd) {
    socklen_t zero = 0;
    if (getpeername(fd, NULL, &zero) != 0 || zero != sizeof(struct sockaddr_in)) return -1;

    struct sockaddr_in address;
    memset(&address, 0xaa, sizeof(address));
    struct sockaddr_in unchanged = address;
    socklen_t negative = (socklen_t)-1;
    errno = 0;
    if (getpeername(fd, (struct sockaddr *)&address, &negative) != -1 ||
        errno != EINVAL || negative != (socklen_t)-1 ||
        memcmp(&address, &unchanged, sizeof(address)) != 0) return -1;
    return 0;
}

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;
    if (check_getsockname(fd) != 0) return 3;

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(9);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0) return 4;
    if (check_getpeername(fd) != 0) return 5;

    if (write(STDOUT_FILENO, "name-lengths-ok", 15) != 15) return 6;
    return close(fd);
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_getsockopt_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_getsockopt_probe.c");
    let bin = dir.path().join("udp_getsockopt_probe");
    fs::write(
        &src,
        r#"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;

    for (socklen_t input_len = 0; input_len <= sizeof(int) + 1; ++input_len) {
        unsigned char value[sizeof(int) + 1];
        memset(value, 0xaa, sizeof(value));
        socklen_t output_len = input_len;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, value, &output_len) != 0) return 3;
        socklen_t expected_len = input_len < sizeof(int) ? input_len : sizeof(int);
        if (output_len != expected_len) return 4;
        int expected = SOCK_DGRAM;
        if (memcmp(value, &expected, expected_len) != 0) return 5;
        for (socklen_t index = expected_len; index < sizeof(value); ++index) {
            if (value[index] != 0xaa) return 6;
        }
    }

    socklen_t zero = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, NULL, &zero) != 0 || zero != 0) return 7;
    socklen_t one = 1;
    errno = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, NULL, &one) != -1 ||
        errno != EFAULT || one != 1) return 8;

    unsigned char unchanged[sizeof(int)];
    memset(unchanged, 0xaa, sizeof(unchanged));
    socklen_t negative = (socklen_t)-4;
    errno = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, unchanged, &negative) != -1 ||
        errno != EINVAL || negative != (socklen_t)-4) return 9;
    for (size_t index = 0; index < sizeof(unchanged); ++index) {
        if (unchanged[index] != 0xaa) return 10;
    }

    if (write(STDOUT_FILENO, "getsockopt-ok", 13) != 13) return 11;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_source_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_source_probe.c");
    let bin = dir.path().join("udp_recvmmsg_source_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char *queries[] = {
    "recvmmsg-query-one", "recvmmsg-query-two", "recvmmsg-query-three",
    "recvmmsg-query-four"
};
static const char *responses[] = {
    "recvmmsg-first-response",
    "recvmmsg-second-response",
    "recvmmsg-third-response",
    "recvmmsg-fourth-response"
};

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static int same_address(const struct sockaddr_in *left,
                        const struct sockaddr_in *right) {
    return left->sin_family == right->sin_family &&
           left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

int main(int argc, char **argv) {
    if (argc != 6) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in expected_sources[4];
    if (parse_address(argv[1], &destination) != 0) return 3;
    for (int i = 0; i < 4; ++i) {
        if (parse_address(argv[i + 2], &expected_sources[i]) != 0) return 4;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 5;
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 6;

    struct iovec send_iov[4];
    struct mmsghdr send_msgs[4];
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int i = 0; i < 4; ++i) {
        send_iov[i].iov_base = (void *)queries[i];
        send_iov[i].iov_len = strlen(queries[i]);
        send_msgs[i].msg_hdr.msg_name = &destination;
        send_msgs[i].msg_hdr.msg_namelen = sizeof(destination);
        send_msgs[i].msg_hdr.msg_iov = &send_iov[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(fd, send_msgs, 4, 0) != 4) return 7;

    char first[7];
    char second[64];
    struct iovec recv_iov[2] = {
        { .iov_base = first, .iov_len = sizeof(first) },
        { .iov_base = second, .iov_len = sizeof(second) },
    };
    struct sockaddr_in sources[2];
    struct mmsghdr recv_msgs[2];
    unsigned char controls[2][64];
    memset(controls, 0xa5, sizeof(controls));
    memset(sources, 0, sizeof(sources));
    memset(recv_msgs, 0, sizeof(recv_msgs));
    for (int i = 0; i < 2; ++i) {
        recv_msgs[i].msg_hdr.msg_name = &sources[i];
        recv_msgs[i].msg_hdr.msg_namelen = sizeof(sources[i]);
        recv_msgs[i].msg_hdr.msg_iov = &recv_iov[i];
        recv_msgs[i].msg_hdr.msg_iovlen = 1;
        recv_msgs[i].msg_hdr.msg_control = controls[i];
        recv_msgs[i].msg_hdr.msg_controllen = sizeof(controls[i]);
    }
    struct timespec batch_timeout = { .tv_sec = 5, .tv_nsec = 0 };
    if (recvmmsg(fd, recv_msgs, 2, MSG_TRUNC, &batch_timeout) != 2) return 8;
    for (int i = 0; i < 2; ++i) {
        if (recv_msgs[i].msg_hdr.msg_controllen != 0 ||
            CMSG_FIRSTHDR(&recv_msgs[i].msg_hdr) != NULL) return 18;
    }
    if (batch_timeout.tv_sec < 0 || batch_timeout.tv_sec >= 5 ||
        batch_timeout.tv_nsec < 0 || batch_timeout.tv_nsec >= 1000000000) return 17;
    if (recv_msgs[0].msg_len != strlen(responses[0]) ||
        (recv_msgs[0].msg_hdr.msg_flags & MSG_TRUNC) == 0 ||
        memcmp(first, responses[0], sizeof(first)) != 0) return 9;
    if (recv_msgs[1].msg_len != strlen(responses[1]) ||
        recv_msgs[1].msg_hdr.msg_flags != 0 ||
        memcmp(second, responses[1], strlen(responses[1])) != 0) return 10;
    for (int i = 0; i < 2; ++i) {
        if (recv_msgs[i].msg_hdr.msg_namelen != sizeof(sources[i]) ||
            !same_address(&sources[i], &expected_sources[i])) return 11;
    }

    char third[64];
    struct sockaddr_in third_source;
    socklen_t third_source_len = sizeof(third_source);
    ssize_t third_len = recvfrom(fd, third, sizeof(third), 0,
                                 (struct sockaddr *)&third_source,
                                 &third_source_len);
    if (third_len != (ssize_t)strlen(responses[2]) ||
        memcmp(third, responses[2], (size_t)third_len) != 0) return 12;
    if (third_source_len != sizeof(third_source) ||
        !same_address(&third_source, &expected_sources[2])) return 13;

    char fourth[64];
    struct iovec fourth_iov = { .iov_base = fourth, .iov_len = sizeof(fourth) };
    struct sockaddr_in fourth_source;
    struct msghdr fourth_msg;
    memset(&fourth_msg, 0, sizeof(fourth_msg));
    fourth_msg.msg_name = &fourth_source;
    fourth_msg.msg_namelen = sizeof(fourth_source);
    fourth_msg.msg_iov = &fourth_iov;
    fourth_msg.msg_iovlen = 1;
    ssize_t fourth_len = recvmsg(fd, &fourth_msg, 0);
    if (fourth_len != (ssize_t)strlen(responses[3]) ||
        memcmp(fourth, responses[3], (size_t)fourth_len) != 0) return 14;
    if (fourth_msg.msg_namelen != sizeof(fourth_source) ||
        !same_address(&fourth_source, &expected_sources[3])) return 15;
    if (write(STDOUT_FILENO, "recvmmsg-ok", 11) != 11) return 16;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_error_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_error_probe.c");
    let bin = dir.path().join("udp_recvmmsg_error_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int check_oversized_iovec(int fd, size_t length) {
    char buffer[1];
    struct iovec iov = { .iov_base = buffer, .iov_len = length };
    struct mmsghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;

    errno = 0;
    if (recvmsg(fd, &msg.msg_hdr, MSG_DONTWAIT) != -1 || errno != EINVAL) return -1;
    errno = 0;
    if (recvmmsg(fd, &msg, 1, MSG_DONTWAIT, NULL) != -1 || errno != EINVAL) return -1;
    return 0;
}

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;

    char buffer[1];
    struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct mmsghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;

    errno = 0;
    if (recvmmsg(fd, NULL, 0, MSG_DONTWAIT, NULL) != 0) return 3;

    /* vlen above UIO_MAXIOV is clamped to 1024, not rejected. */
    static struct mmsghdr clamp_msgs[1200];
    static struct iovec clamp_iov[1200];
    static char clamp_buf[1];
    for (int i = 0; i < 1200; ++i) {
        clamp_iov[i].iov_base = clamp_buf;
        clamp_iov[i].iov_len = sizeof(clamp_buf);
        clamp_msgs[i].msg_hdr.msg_iov = &clamp_iov[i];
        clamp_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    errno = 0;
    if (recvmmsg(fd, clamp_msgs, 1200, MSG_DONTWAIT, NULL) != -1 ||
        errno != EAGAIN) return 15;

    errno = 0;
    if (recvmmsg(fd, NULL, 1, MSG_DONTWAIT, NULL) != -1 || errno != EFAULT) return 4;

    struct timespec invalid = { .tv_sec = 0, .tv_nsec = 1000000000 };
    errno = 0;
    if (recvmmsg(fd, &msg, 1, MSG_DONTWAIT, &invalid) != -1 || errno != EINVAL) return 5;

    errno = 0;
    if (recvmmsg(fd, &msg, 1, MSG_DONTWAIT,
                 (struct timespec *)1) != -1 || errno != EFAULT) return 6;

    errno = 0;
    if (recvmmsg(fd, NULL, 0, MSG_DONTWAIT,
                 (struct timespec *)1) != -1 || errno != EFAULT) return 7;

    if (check_oversized_iovec(fd, (size_t)SSIZE_MAX + 1) != 0) return 8;
    if (check_oversized_iovec(fd, SIZE_MAX) != 0) return 9;

    msg.msg_hdr.msg_iovlen = 1025;
    errno = 0;
    if (recvmsg(fd, &msg.msg_hdr, MSG_DONTWAIT) != -1 || errno != EMSGSIZE) return 10;
    errno = 0;
    if (recvmmsg(fd, &msg, 1, MSG_DONTWAIT, NULL) != -1 || errno != EMSGSIZE) return 11;
    msg.msg_hdr.msg_iovlen = 1;

    int status = fcntl(fd, F_GETFL, 0);
    if (status < 0 || fcntl(fd, F_SETFL, status | O_NONBLOCK) != 0) return 12;
    errno = 0;
    if (recvmmsg(fd, &msg, 1, 0, NULL) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) return 13;

    if (write(STDOUT_FILENO, "recvmmsg-errors-ok", 18) != 18) return 14;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_timeout_fault_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_timeout_fault_probe.c");
    let bin = dir.path().join("udp_recvmmsg_timeout_fault_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int parse_address(char *value, struct sockaddr_in *address) {
    char *colon = strrchr(value, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, value, &address->sin_addr) == 1 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct sockaddr_in destination;
    if (parse_address(argv[1], &destination) != 0) return 3;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;
    const char *queries[2] = { "timeout-fault-one", "timeout-fault-two" };
    for (int index = 0; index < 2; ++index) {
        size_t length = strlen(queries[index]);
        if (sendto(fd, queries[index], length, 0,
                   (struct sockaddr *)&destination, sizeof(destination)) !=
            (ssize_t)length) return 5;
    }

    char buffers[2][32];
    struct iovec iovecs[2];
    struct mmsghdr messages[2];
    memset(messages, 0, sizeof(messages));
    for (int index = 0; index < 2; ++index) {
        iovecs[index].iov_base = buffers[index];
        iovecs[index].iov_len = sizeof(buffers[index]);
        messages[index].msg_hdr.msg_iov = &iovecs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 6;
    struct timespec *timeout = mmap(NULL, (size_t)page_size,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (timeout == MAP_FAILED) return 7;
    timeout->tv_sec = 5;
    timeout->tv_nsec = 0;
    if (mprotect(timeout, (size_t)page_size, PROT_READ) != 0) return 8;

    errno = 0;
    int received = recvmmsg(fd, messages, 2, 0, timeout);
    if (received != -1 || errno != EFAULT) {
        dprintf(STDERR_FILENO, "recvmmsg rc=%d errno=%d\n", received, errno);
        return 9;
    }
    if (munmap(timeout, (size_t)page_size) != 0) return 10;
    if (write(STDOUT_FILENO, "recvmmsg-timeout-fault-ok", 25) != 25) return 11;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_deadline_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_deadline_probe.c");
    let bin = dir.path().join("udp_recvmmsg_deadline_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;
    char buffer[1];
    struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct mmsghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 50000000 };
    if (recvmmsg(fd, &msg, 1, 0, &timeout) != 0) return 3;
    if (timeout.tv_sec != 0 || timeout.tv_nsec != 0) return 11;
    errno = 0;
    /* vlen above UIO_MAXIOV is clamped, so the call proceeds to the usual
       nonblocking empty-queue verdict instead of failing with EINVAL. */
    if (recvmmsg(fd, &msg, 1025, MSG_DONTWAIT, NULL) != -1 ||
        errno != EAGAIN) return 4;

    /* A short explicit timespec still returns zero ahead of a longer armed
       SO_RCVTIMEO: the earlier deadline keeps its own expiry result. */
    struct timeval socket_timeout = { .tv_sec = 3, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
                   sizeof(socket_timeout)) != 0) return 5;
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 6;
    timeout.tv_nsec = 50000000;
    if (recvmmsg(fd, &msg, 1, 0, &timeout) != 0) return 7;
    if (timeout.tv_sec != 0 || timeout.tv_nsec != 0) return 12;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 8;
    long waited = (now.tv_sec - start.tv_sec) * 1000L +
                  (now.tv_nsec - start.tv_nsec) / 1000000L;
    if (waited < 0 || waited > 2000) return 9;

    if (write(STDOUT_FILENO, "recvmmsg-deadline-ok", 20) != 20) return 10;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_partial_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_partial_probe.c");
    let bin = dir.path().join("udp_recvmmsg_partial_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static int same_address(const struct sockaddr_in *left,
                        const struct sockaddr_in *right) {
    return left->sin_family == right->sin_family &&
           left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in expected_source;
    if (parse_address(argv[1], &destination) != 0 ||
        parse_address(argv[2], &expected_source) != 0) return 3;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;
    const char query[] = "receive-metadata-query";
    if (sendto(fd, query, sizeof(query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(query) - 1)) return 5;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 6;
    void *mapping = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 7;
    struct mmsghdr *msgs = (struct mmsghdr *)((char *)mapping + page_size -
                                               sizeof(struct mmsghdr));
    char response[64];
    struct iovec iov = { .iov_base = response, .iov_len = sizeof(response) };
    struct sockaddr_in source;
    memset(msgs, 0, sizeof(*msgs));
    msgs[0].msg_hdr.msg_name = &source;
    msgs[0].msg_hdr.msg_namelen = sizeof(source);
    msgs[0].msg_hdr.msg_iov = &iov;
    msgs[0].msg_hdr.msg_iovlen = 1;
    if (mprotect((char *)mapping + page_size, (size_t)page_size, PROT_NONE) != 0) return 8;

    if (recvmmsg(fd, msgs, 2, 0, NULL) != 1) return 9;
    const char expected[] = "receive-metadata-response";
    if (msgs[0].msg_len != sizeof(expected) - 1 ||
        memcmp(response, expected, sizeof(expected) - 1) != 0) return 10;
    if (msgs[0].msg_hdr.msg_namelen != sizeof(source) ||
        !same_address(&source, &expected_source)) return 11;

    if (write(STDOUT_FILENO, "recvmmsg-partial-ok", 19) != 19) return 12;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_recvmmsg_flag_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_recvmmsg_flag_probe.c");
    let bin = dir.path().join("udp_recvmmsg_flag_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char *queries[] = {
    "recvmmsg-peek-query",
    "recvmmsg-wait-one-query",
    "recvmmsg-wait-two-query"
};
static const char *responses[] = {
    "recvmmsg-peek-response",
    "recvmmsg-wait-one-response",
    "recvmmsg-wait-two-response"
};

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static int same_address(const struct sockaddr_in *left,
                        const struct sockaddr_in *right) {
    return left->sin_family == right->sin_family &&
           left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

static int check_message(const struct mmsghdr *msg, const char *payload,
                         const char *expected,
                         const struct sockaddr_in *source,
                         const struct sockaddr_in *expected_source) {
    return msg->msg_len == strlen(expected) &&
           memcmp(payload, expected, strlen(expected)) == 0 &&
           msg->msg_hdr.msg_namelen == sizeof(*source) &&
           same_address(source, expected_source);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in expected_sources[3];
    if (parse_address(argv[1], &destination) != 0) return 3;
    for (int i = 0; i < 3; ++i) {
        if (parse_address(argv[i + 2], &expected_sources[i]) != 0) return 4;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 5;
    struct timeval socket_timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
                   sizeof(socket_timeout)) != 0) return 6;

    if (sendto(fd, queries[0], strlen(queries[0]), 0,
               (struct sockaddr *)&destination, sizeof(destination)) < 0) return 7;
    char peek_payload[64];
    struct sockaddr_in peek_source;
    struct iovec peek_iov = {
        .iov_base = peek_payload, .iov_len = sizeof(peek_payload)
    };
    struct mmsghdr peek_msg;
    memset(&peek_msg, 0, sizeof(peek_msg));
    peek_msg.msg_hdr.msg_name = &peek_source;
    peek_msg.msg_hdr.msg_namelen = sizeof(peek_source);
    peek_msg.msg_hdr.msg_iov = &peek_iov;
    peek_msg.msg_hdr.msg_iovlen = 1;
    if (recvmmsg(fd, &peek_msg, 1, MSG_PEEK, NULL) != 1 ||
        !check_message(&peek_msg, peek_payload, responses[0], &peek_source,
                       &expected_sources[0])) return 8;

    char consumed[64];
    struct sockaddr_in consumed_source;
    socklen_t consumed_source_len = sizeof(consumed_source);
    ssize_t consumed_len = recvfrom(fd, consumed, sizeof(consumed), 0,
                                    (struct sockaddr *)&consumed_source,
                                    &consumed_source_len);
    if (consumed_len != (ssize_t)strlen(responses[0]) ||
        memcmp(consumed, responses[0], (size_t)consumed_len) != 0 ||
        consumed_source_len != sizeof(consumed_source) ||
        !same_address(&consumed_source, &expected_sources[0])) return 9;

    struct iovec send_iov[2];
    struct mmsghdr send_msgs[2];
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int i = 0; i < 2; ++i) {
        send_iov[i].iov_base = (void *)queries[i + 1];
        send_iov[i].iov_len = strlen(queries[i + 1]);
        send_msgs[i].msg_hdr.msg_name = &destination;
        send_msgs[i].msg_hdr.msg_namelen = sizeof(destination);
        send_msgs[i].msg_hdr.msg_iov = &send_iov[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(fd, send_msgs, 2, 0) != 2) return 10;

    char wait_payloads[2][64];
    struct sockaddr_in wait_sources[2];
    struct iovec wait_iov[2];
    struct mmsghdr wait_msgs[2];
    memset(wait_msgs, 0, sizeof(wait_msgs));
    for (int i = 0; i < 2; ++i) {
        wait_iov[i].iov_base = wait_payloads[i];
        wait_iov[i].iov_len = sizeof(wait_payloads[i]);
        wait_msgs[i].msg_hdr.msg_name = &wait_sources[i];
        wait_msgs[i].msg_hdr.msg_namelen = sizeof(wait_sources[i]);
        wait_msgs[i].msg_hdr.msg_iov = &wait_iov[i];
        wait_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (recvmmsg(fd, wait_msgs, 2, MSG_WAITFORONE, NULL) != 1 ||
        !check_message(&wait_msgs[0], wait_payloads[0], responses[1],
                       &wait_sources[0], &expected_sources[1])) return 11;

    char final_payload[64];
    struct sockaddr_in final_source;
    socklen_t final_source_len = sizeof(final_source);
    ssize_t final_len = recvfrom(fd, final_payload, sizeof(final_payload), 0,
                                 (struct sockaddr *)&final_source,
                                 &final_source_len);
    if (final_len != (ssize_t)strlen(responses[2]) ||
        memcmp(final_payload, responses[2], (size_t)final_len) != 0 ||
        final_source_len != sizeof(final_source) ||
        !same_address(&final_source, &expected_sources[2])) return 12;

    if (write(STDOUT_FILENO, "recvmmsg-flags-ok", 17) != 17) return 13;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_udp_rcvtimeo_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_rcvtimeo_probe.c");
    let bin = dir.path().join("udp_rcvtimeo_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char batch_query_one[] = "rcvtimeo-batch-query-one";
static const char batch_query_two[] = "rcvtimeo-batch-query-two";
static const char batch_response_one[] = "rcvtimeo-batch-response-one";
static const char batch_response_two[] = "rcvtimeo-batch-response-two";
static const char late_query[] = "rcvtimeo-late-query";
static const char late_response[] = "rcvtimeo-late-response";
static const char prompt_query[] = "rcvtimeo-prompt-query";
static const char prompt_response[] = "rcvtimeo-prompt-response";

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static long elapsed_ms(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (now.tv_sec - start->tv_sec) * 1000L +
           (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static int set_rcvtimeo_ms(int fd, long ms) {
    struct timeval timeout = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static void reset_batch(struct mmsghdr *batch, struct iovec *iovs,
                        char (*buffers)[128], unsigned int count) {
    memset(batch, 0, sizeof(*batch) * count);
    for (unsigned int index = 0; index < count; index++) {
        iovs[index].iov_base = buffers[index];
        iovs[index].iov_len = sizeof(buffers[index]);
        batch[index].msg_hdr.msg_iov = &iovs[index];
        batch[index].msg_hdr.msg_iovlen = 1;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct sockaddr_in destination;
    if (parse_address(argv[1], &destination) != 0) return 3;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;
    if (set_rcvtimeo_ms(fd, 500) != 0) return 5;

    /* The stored timeout reads back through getsockopt. */
    struct timeval readback = { .tv_sec = 0, .tv_usec = 0 };
    socklen_t readback_len = sizeof(readback);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &readback, &readback_len) != 0) return 6;
    long readback_ms = readback.tv_sec * 1000L + readback.tv_usec / 1000L;
    if (readback_len != sizeof(readback) || readback_ms < 490 || readback_ms > 510) return 7;

    char buffer[128];
    struct timespec start;

    /* A quiet blocking recvfrom expires with EAGAIN at the socket timeout. */
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 8;
    errno = 0;
    if (recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) != -1 || errno != EAGAIN) return 9;
    long waited = elapsed_ms(&start);
    if (waited < 450 || waited > 5000) return 10;

    /* A quiet blocking recvmsg expires the same way. */
    struct iovec single_iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr single;
    memset(&single, 0, sizeof(single));
    single.msg_iov = &single_iov;
    single.msg_iovlen = 1;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 11;
    errno = 0;
    if (recvmsg(fd, &single, 0) != -1 || errno != EAGAIN) return 12;
    waited = elapsed_ms(&start);
    if (waited < 450 || waited > 5000) return 13;

    /* MSG_DONTWAIT returns immediately despite the socket timeout. */
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 14;
    errno = 0;
    if (recvfrom(fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL) != -1 ||
        errno != EAGAIN) return 15;
    waited = elapsed_ms(&start);
    if (waited < 0 || waited > 250) return 16;

    /* O_NONBLOCK returns immediately despite the socket timeout. */
    int status = fcntl(fd, F_GETFL);
    if (status < 0 || fcntl(fd, F_SETFL, status | O_NONBLOCK) != 0) return 17;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 18;
    errno = 0;
    if (recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) != -1 || errno != EAGAIN) return 19;
    waited = elapsed_ms(&start);
    if (waited < 0 || waited > 250) return 20;
    if (fcntl(fd, F_SETFL, status & ~O_NONBLOCK) != 0) return 21;

    /* A quiet recvmmsg without an explicit timeout expires with EAGAIN. */
    struct mmsghdr batch[3];
    struct iovec batch_iovs[3];
    char batch_buffers[3][128];
    reset_batch(batch, batch_iovs, batch_buffers, 3);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 22;
    errno = 0;
    if (recvmmsg(fd, batch, 1, 0, NULL) != -1 || errno != EAGAIN) return 23;
    waited = elapsed_ms(&start);
    if (waited < 450 || waited > 5000) return 24;

    /* The shorter socket timeout beats a longer explicit recvmmsg timeout. */
    struct timespec explicit_timeout = { .tv_sec = 3, .tv_nsec = 0 };
    reset_batch(batch, batch_iovs, batch_buffers, 3);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 25;
    errno = 0;
    if (recvmmsg(fd, batch, 2, 0, &explicit_timeout) != -1 || errno != EAGAIN) return 26;
    if (explicit_timeout.tv_sec != 3 || explicit_timeout.tv_nsec != 0) return 43;
    waited = elapsed_ms(&start);
    if (waited < 450 || waited > 2000) return 27;

    /* The socket timeout bounds each inter-datagram gap: a batch whose second
       response arrives after the first still completes, and the trailing
       quiet wait adds a full timeout, proving the deadline resets per entry. */
    if (sendto(fd, batch_query_one, sizeof(batch_query_one) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(batch_query_one) - 1)) return 28;
    if (sendto(fd, batch_query_two, sizeof(batch_query_two) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(batch_query_two) - 1)) return 29;
    reset_batch(batch, batch_iovs, batch_buffers, 3);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 30;
    if (recvmmsg(fd, batch, 3, 0, NULL) != 2) return 31;
    waited = elapsed_ms(&start);
    if (waited < 700 || waited > 5000) return 32;
    if (batch[0].msg_len != sizeof(batch_response_one) - 1 ||
        memcmp(batch_buffers[0], batch_response_one, sizeof(batch_response_one) - 1) != 0)
        return 33;
    if (batch[1].msg_len != sizeof(batch_response_two) - 1 ||
        memcmp(batch_buffers[1], batch_response_two, sizeof(batch_response_two) - 1) != 0)
        return 34;

    /* Clearing the timeout back to zero restores indefinite blocking: the
       late response lands after the old 500 ms deadline would have fired. */
    if (set_rcvtimeo_ms(fd, 0) != 0) return 35;
    if (sendto(fd, late_query, sizeof(late_query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(late_query) - 1)) return 36;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 37;
    ssize_t received = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (received != (ssize_t)(sizeof(late_response) - 1) ||
        memcmp(buffer, late_response, sizeof(late_response) - 1) != 0) return 38;
    waited = elapsed_ms(&start);
    if (waited < 600 || waited > 5000) return 39;

    /* A response inside the window still completes before the timeout. */
    if (set_rcvtimeo_ms(fd, 500) != 0) return 40;
    if (sendto(fd, prompt_query, sizeof(prompt_query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(prompt_query) - 1)) return 41;
    received = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (received != (ssize_t)(sizeof(prompt_response) - 1) ||
        memcmp(buffer, prompt_response, sizeof(prompt_response) - 1) != 0) return 42;

    if (close(fd) != 0) return 43;
    if (write(STDOUT_FILENO, "rcvtimeo-ok", 11) != 11) return 44;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn build_lazy_udp_rcvtimeo_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("lazy_udp_rcvtimeo_probe.c");
    let bin = dir.path().join("lazy_udp_rcvtimeo_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char prompt_query[] = "rcvtimeo-prompt-query";
static const char prompt_response[] = "rcvtimeo-prompt-response";

static int parse_address(const char *value, struct sockaddr_in *address) {
    char copy[64];
    if (snprintf(copy, sizeof(copy), "%s", value) >= (int)sizeof(copy)) return -1;
    char *colon = strrchr(copy, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)strtoul(colon + 1, NULL, 10));
    return inet_pton(AF_INET, copy, &address->sin_addr) == 1 ? 0 : -1;
}

static long elapsed_ms(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (now.tv_sec - start->tv_sec) * 1000L +
           (now.tv_nsec - start->tv_nsec) / 1000000L;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct sockaddr_in destination;
    if (parse_address(argv[1], &destination) != 0) return 3;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;

    /* The option is set before the first proxied send, so lazy replacement
       must transfer it to the injected endpoint. */
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 500000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 5;

    /* The first proxied send lazily replaces the descriptor with the relay
       endpoint; the prompt response proves the relay is live. */
    if (sendto(fd, prompt_query, sizeof(prompt_query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(prompt_query) - 1)) return 6;
    char buffer[128];
    ssize_t received = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (received != (ssize_t)(sizeof(prompt_response) - 1) ||
        memcmp(buffer, prompt_response, sizeof(prompt_response) - 1) != 0) return 7;

    struct timeval readback = { .tv_sec = 0, .tv_usec = 0 };
    socklen_t readback_len = sizeof(readback);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &readback, &readback_len) != 0 ||
        readback_len != sizeof(readback) ||
        readback.tv_sec != 0 || readback.tv_usec < 490000 || readback.tv_usec > 510000)
        return 8;

    /* SO_RCVTIMEO armed on the replaced descriptor bounds a quiet receive. */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 9;
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 10;
    errno = 0;
    if (recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) != -1 || errno != EAGAIN) return 11;
    long waited = elapsed_ms(&start);
    if (waited < 450 || waited > 5000) return 12;

    if (write(STDOUT_FILENO, "lazy-rcvtimeo-ok", 16) != 16) return 13;
    return 0;
}
"#,
    )
    .unwrap();
    let status = Command::new("cc")
        .arg(&src)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(status.success());
    (dir, bin)
}

fn spawn_changed_source_udp_exchange() -> (SocketAddr, SocketAddr, thread::JoinHandle<()>) {
    spawn_changed_source_udp_rounds(1)
}

/// Answers `rounds` queries from a source address that differs from the
/// destination, so a probe can check every receive call shape against the same
/// v4-mapped source.
fn spawn_changed_source_udp_rounds(
    rounds: usize,
) -> (SocketAddr, SocketAddr, thread::JoinHandle<()>) {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let response_source = sender.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        for _ in 0..rounds {
            let mut query = [0_u8; 128];
            let (n, peer) = receiver.recv_from(&mut query).unwrap();
            assert_eq!(&query[..n], UDP_METADATA_QUERY);
            sender.send_to(UDP_METADATA_RESPONSE, peer).unwrap();
        }
    });
    (destination, response_source, server_thread)
}

fn spawn_changed_source_udp_batch_exchange() -> (SocketAddr, [SocketAddr; 4], thread::JoinHandle<()>)
{
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver.local_addr().unwrap();
    let senders = std::array::from_fn::<_, 4, _>(|_| UdpSocket::bind("127.0.0.1:0").unwrap());
    let response_sources = senders
        .each_ref()
        .map(|sender| sender.local_addr().unwrap());
    let server_thread = thread::spawn(move || {
        for (index, sender) in senders.into_iter().enumerate() {
            let mut query = [0_u8; 128];
            let (n, peer) = receiver.recv_from(&mut query).unwrap();
            assert_eq!(&query[..n], UDP_RECVMMSG_QUERIES[index]);
            sender.send_to(UDP_RECVMMSG_RESPONSES[index], peer).unwrap();
        }
    });
    (destination, response_sources, server_thread)
}

fn spawn_udp_recvmmsg_timeout_fault_exchange() -> (SocketAddr, thread::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        for (expected, response) in [
            (b"timeout-fault-one".as_slice(), b"response-one".as_slice()),
            (b"timeout-fault-two".as_slice(), b"response-two".as_slice()),
        ] {
            let mut query = [0_u8; 32];
            let (length, peer) = server.recv_from(&mut query).unwrap();
            assert_eq!(&query[..length], expected);
            server.send_to(response, peer).unwrap();
        }
    });
    (destination, server_thread)
}

fn spawn_udp_recvmmsg_flag_exchange() -> (SocketAddr, [SocketAddr; 3], thread::JoinHandle<()>) {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver.local_addr().unwrap();
    let senders = std::array::from_fn::<_, 3, _>(|_| UdpSocket::bind("127.0.0.1:0").unwrap());
    let response_sources = senders
        .each_ref()
        .map(|sender| sender.local_addr().unwrap());
    let server_thread = thread::spawn(move || {
        for (index, sender) in senders.into_iter().enumerate() {
            let mut query = [0_u8; 128];
            let (n, peer) = receiver.recv_from(&mut query).unwrap();
            assert_eq!(&query[..n], UDP_RECVMMSG_FLAG_QUERIES[index]);
            if index == 2 {
                thread::sleep(Duration::from_millis(200));
            }
            sender
                .send_to(UDP_RECVMMSG_FLAG_RESPONSES[index], peer)
                .unwrap();
        }
    });
    (destination, response_sources, server_thread)
}

fn udp_rcvtimeo_script() -> [(&'static [u8], &'static [u8], Duration); 4] {
    [
        (
            UDP_RCVTIMEO_BATCH_QUERIES[0],
            UDP_RCVTIMEO_BATCH_RESPONSES[0],
            Duration::ZERO,
        ),
        (
            UDP_RCVTIMEO_BATCH_QUERIES[1],
            UDP_RCVTIMEO_BATCH_RESPONSES[1],
            UDP_RCVTIMEO_BATCH_GAP,
        ),
        (
            UDP_RCVTIMEO_LATE_QUERY,
            UDP_RCVTIMEO_LATE_RESPONSE,
            UDP_RCVTIMEO_LATE_DELAY,
        ),
        (
            UDP_RCVTIMEO_PROMPT_QUERY,
            UDP_RCVTIMEO_PROMPT_RESPONSE,
            Duration::ZERO,
        ),
    ]
}

fn spawn_udp_rcvtimeo_exchange() -> (SocketAddr, thread::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        for (expected_query, response, delay) in udp_rcvtimeo_script() {
            let mut query = [0_u8; 128];
            let (n, peer) = server.recv_from(&mut query).unwrap();
            assert_eq!(&query[..n], expected_query);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            server.send_to(response, peer).unwrap();
        }
    });
    (destination, server_thread)
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

enum SocketModeSelector<'a> {
    Flag(&'a str),
    DeprecatedEnv(&'a str),
}

struct IdleReapProbeRun {
    threads: usize,
    stderr: String,
}

/// Runs the idle-reap probe under one socket-mode selector and samples the
/// supervisor's thread count while the probe's sockets are open. Stable mode
/// starts a relay reader and writer per socket at `socket(2)` time and lazy
/// mode starts none until the first proxied send, so comparing two runs
/// identifies the selected mode without depending on how many notification
/// workers the host's core count produces.
fn run_idle_reap_probe(probe: &Path, selector: SocketModeSelector<'_>) -> IdleReapProbeRun {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
    match selector {
        SocketModeSelector::Flag(mode) => command.arg("--udp-socket-mode").arg(mode),
        SocketModeSelector::DeprecatedEnv(mode) => command.env("SUP_UDP_SOCKET_MODE", mode),
    };
    let mut child = command
        .arg("--proxy")
        .arg("socks5://127.0.0.1:9")
        .arg("--enable-udp")
        .arg("--")
        .arg(probe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "open\n");
    let threads = process_thread_count(child.id());

    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "status={:?}", output.status);
    IdleReapProbeRun {
        threads,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn process_thread_count(pid: u32) -> usize {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
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

fn build_independent_udp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_independent_io");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_independent_io.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    (dir, probe)
}

#[test]
fn stable_direct_udp_sends_without_waiting_for_responses() {
    independent_udp_io("stable", "direct");
}

#[test]
fn stable_socks_udp_sends_without_waiting_for_responses() {
    independent_udp_io("stable", "socks");
}

#[test]
fn lazy_socks_udp_sends_without_waiting_for_responses() {
    independent_udp_io("lazy", "socks");
}

#[test]
fn dns_udp_pipelines_queries_and_preserves_partial_frames() {
    independent_udp_io("lazy", "dns");
}

fn independent_udp_io(mode: &str, route: &str) {
    let (_dir, probe) = build_independent_udp_probe();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let destination = if route == "dns" {
        "198.51.100.12:53".parse().unwrap()
    } else {
        udp_addr
    };
    let route_owned = route.to_string();
    let server = thread::spawn(move || {
        let mut control = if route_owned == "direct" {
            None
        } else {
            let (mut stream, _) = socks.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socks5_greet(&mut stream);
            read_socks5_request(&mut stream);
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend_from_slice(&udp_addr.port().to_be_bytes());
            stream.write_all(&reply).unwrap();
            Some(stream)
        };
        let mut peer = None;
        let started = Instant::now();
        for i in 0..6 {
            let query = if route_owned == "dns" {
                let stream = control.as_mut().unwrap();
                let mut frame = [0; 4];
                stream.read_exact(&mut frame).unwrap();
                assert_eq!(&frame[..2], &[0, 2]);
                frame[2..].to_vec()
            } else {
                let mut buf = [0; 64];
                let (n, source) = udp.recv_from(&mut buf).unwrap();
                peer = Some(source);
                if route_owned == "socks" {
                    parse_udp_packet(&buf[..n]).1.to_vec()
                } else {
                    buf[..n].to_vec()
                }
            };
            assert_eq!(query, [i, 0]);
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "burst serialized on replies"
        );
        thread::sleep(Duration::from_millis(250));
        for i in [5, 4, 3, 2, 1, 0, 6] {
            let response = [i, 1];
            match route_owned.as_str() {
                "dns" => {
                    let stream = control.as_mut().unwrap();
                    // Split both the length prefix and payload across wakes.
                    for byte in [0, 2, i, 1] {
                        stream.write_all(&[byte]).unwrap();
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                "socks" => {
                    udp.send_to(&encode_udp_packet(destination, &response), peer.unwrap())
                        .unwrap();
                }
                _ => {
                    udp.send_to(&response, peer.unwrap()).unwrap();
                }
            }
        }
        if let Some(mut control) = control {
            let _ = control.read(&mut [0]);
        }
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
    command.args([
        "--proxy",
        &format!("socks5://{socks_addr}"),
        "--udp-socket-mode",
        mode,
    ]);
    if route == "dns" {
        command.arg("--enable-dns");
    } else {
        command.arg("--enable-udp");
    }
    if route == "socks" {
        command.arg("--proxy-local");
    }
    let output = command
        .arg("--")
        .arg(probe)
        .arg(destination.ip().to_string())
        .arg(destination.port().to_string())
        .arg("burst")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "independent-io-ok\n"
    );
    server.join().unwrap();
}

#[test]
fn stable_udp_silent_peer_churn_reaps_workers_without_response_timeout() {
    let (_dir, probe) = build_independent_udp_probe();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = sink.local_addr().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .args(["--enable-udp", "--udp-socket-mode", "stable", "--"])
        .arg(probe)
        .arg(destination.ip().to_string())
        .arg(destination.port().to_string())
        .arg("churn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let pid = child.id();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    let baseline = process_thread_count(pid);
    child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let sampler = thread::spawn(move || {
        let mut peak = 0;
        while done_rx.try_recv().is_err() {
            peak = peak.max(process_thread_count(pid));
            thread::sleep(Duration::from_millis(5));
        }
        peak
    });
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "closed\n");
    let deadline = Instant::now() + Duration::from_secs(3);
    let remaining = loop {
        let count = process_udp_relay_thread_count(pid);
        if count == 0 || Instant::now() >= deadline {
            break count;
        }
        thread::sleep(Duration::from_millis(20));
    };
    done_tx.send(()).unwrap();
    let peak = sampler.join().unwrap();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(child.wait().unwrap().success());
    eprintln!("2000 silent UDP sockets: baseline={baseline}, peak={peak}, relay workers after reap={remaining}");
    // Two workers per admitted relay plus supervisor threads and a small
    // scheduling margin. The old path retained ~2000 blocked writers.
    assert!(peak < 400, "retired UDP workers accumulated: {peak}");
    assert!(
        remaining == 0,
        "closed UDP workers waited for the peer: {remaining}"
    );
}

fn process_udp_relay_thread_count(pid: u32) -> usize {
    fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .filter(|name| name.starts_with("yatht-udp-relay"))
        .count()
}

#[test]
fn pipelined_dns_replies_keep_original_destinations_with_reused_ids() {
    let (_dir, probe) = build_independent_udp_probe();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let server = thread::spawn(move || {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut handlers = Vec::new();
        for first in 0..2 {
            let (mut stream, _) = socks.accept().unwrap();
            let barrier = Arc::clone(&barrier);
            handlers.push(thread::spawn(move || {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socks5_greet(&mut stream);
                read_socks5_request(&mut stream);
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                for index in [first, first + 2] {
                    let mut query = [0; 5];
                    stream.read_exact(&mut query).unwrap();
                    assert_eq!(query, [0, 3, 0x12, 0x34, index]);
                }
                barrier.wait();
                for index in [first + 2, first] {
                    stream.write_all(&[0, 3, 0x12, 0x34, index]).unwrap();
                }
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .args([
            "--enable-dns",
            "--proxy",
            &format!("socks5://{socks_addr}"),
            "--",
        ])
        .arg(probe)
        .args(["198.51.100.12", "53", "dns-sources"])
        .output()
        .unwrap();
    assert_success(&output);
    server.join().unwrap();
}

#[test]
fn udp_payload_limits_include_socks_headers_without_reducing_direct_limits() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_payload_limit");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_payload_limit.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for mode in ["lazy", "stable"] {
        for (ip, direct_limit, proxy_limit) in [
            ("127.0.0.1", 65507, 65497),
            ("::ffff:127.0.0.1", 65507, 65485),
            ("::1", 65527, 65485),
        ] {
            for proxied in [false, true] {
                for batch_first in [false, true] {
                    let udp = UdpSocket::bind(if !proxied && ip == "::1" {
                        "[::1]:0"
                    } else {
                        "127.0.0.1:0"
                    })
                    .unwrap();
                    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let port = udp.local_addr().unwrap().port();
                    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
                    let socks_addr = socks.local_addr().unwrap();
                    let server = thread::spawn(move || {
                        let mut control = if proxied {
                            let (mut stream, _) = socks.accept().unwrap();
                            socks5_greet(&mut stream);
                            read_socks5_request(&mut stream);
                            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                            reply.extend_from_slice(&port.to_be_bytes());
                            stream.write_all(&reply).unwrap();
                            Some(stream)
                        } else {
                            None
                        };
                        for _ in 0..2 {
                            let mut buf = vec![0; 65535];
                            let (n, peer) = udp.recv_from(&mut buf).unwrap();
                            udp.send_to(&buf[..n], peer).unwrap();
                        }
                        if let Some(stream) = control.as_mut() {
                            let _ = stream.read(&mut [0]);
                        }
                    });
                    let mut command = Command::new(env!("CARGO_BIN_EXE_yatht"));
                    command.args([
                        "--enable-udp",
                        "--udp-socket-mode",
                        mode,
                        "--proxy",
                        &format!("socks5://{socks_addr}"),
                    ]);
                    if proxied {
                        command.arg("--proxy-local");
                    }
                    let output = command
                        .arg("--")
                        .arg(&probe)
                        .arg(ip)
                        .arg(port.to_string())
                        .arg(if proxied { proxy_limit } else { direct_limit }.to_string())
                        .arg(if batch_first { "1" } else { "0" })
                        .output()
                        .unwrap();
                    assert_success(&output);
                    server.join().unwrap();
                }
            }
        }
    }
}

#[test]
fn stalled_dns_writes_do_not_block_other_udp_routes() {
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("udp_route_backpressure");
    assert!(Command::new("cc")
        .args([
            "tests/probes/udp_route_backpressure.c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o"
        ])
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    for mode in ["lazy", "stable"] {
        let direct = UdpSocket::bind("127.0.0.1:0").unwrap();
        direct
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let direct_port = direct.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let mut buf = [0; 64];
            let (n, peer) = direct.recv_from(&mut buf).unwrap();
            direct.send_to(&buf[..n], peer).unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let accept = || {
                let deadline = Instant::now() + Duration::from_secs(6);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            return stream;
                        }
                        Err(err)
                            if err.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(err) => panic!("proxy accept failed: {err}"),
                    }
                }
            };
            let mut dns = accept();
            let size = 4096_i32;
            // SAFETY: size points to a live integer option value for this fd.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        dns.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        (&size as *const i32).cast(),
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
            socks5_greet(&mut dns);
            read_socks5_request(&mut dns);
            dns.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let mut warmup = [0; 4];
            dns.read_exact(&mut warmup).unwrap();
            dns.write_all(&warmup).unwrap();
            // Retain the stream but never drain further queries.
            let mut socks = accept();
            socks5_greet(&mut socks);
            read_socks5_request(&mut socks);
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend_from_slice(&udp.local_addr().unwrap().port().to_be_bytes());
            socks.write_all(&reply).unwrap();
            let mut packet = [0; 64];
            let (n, peer) = udp.recv_from(&mut packet).unwrap();
            udp.send_to(&packet[..n], peer).unwrap();
            let _ = socks.read(&mut [0]);
            drop(dns);
        });
        let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
            .args([
                "--enable-dns",
                "--enable-udp",
                "--udp-socket-mode",
                mode,
                "--proxy",
                &format!("socks5://{proxy_addr}"),
                "--",
            ])
            .arg(&probe)
            .arg(direct_port.to_string())
            .output()
            .unwrap();
        assert_success(&output);
        eprintln!("{mode}: {}", String::from_utf8_lossy(&output.stdout));
        echo.join().unwrap();
        server.join().unwrap();
    }
}

#[test]
fn dns_stream_limit_counts_drops_without_evicting_healthy_streams() {
    let (dir, probe) = build_independent_udp_probe();
    for mode in ["lazy", "stable"] {
        let metrics = dir.path().join(format!("{mode}.jsonl"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..16 {
                let (mut stream, _) = listener.accept().unwrap();
                handlers.push(thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socks5_greet(&mut stream);
                    read_socks5_request(&mut stream);
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    loop {
                        let mut frame = [0; 5];
                        match stream.read_exact(&mut frame) {
                            Ok(()) => stream.write_all(&frame).unwrap(),
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionReset
                                ) =>
                            {
                                break
                            }
                            Err(err) => panic!("DNS stream failed: {err}"),
                        }
                    }
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
            .args([
                "--enable-dns",
                "--enable-udp",
                "--udp-socket-mode",
                mode,
                "--proxy",
                &format!("socks5://{address}"),
                "--metrics-file",
            ])
            .arg(&metrics)
            .arg("--")
            .arg(&probe)
            .args(["198.51.100.1", "53", "dns-cap"])
            .output()
            .unwrap();
        assert_success(&output);
        server.join().unwrap();
        let events = fs::read_to_string(metrics).unwrap();
        let summary: serde_json::Value =
            serde_json::from_str(events.lines().last().unwrap()).unwrap();
        assert_eq!(summary["event"], "run_summary");
        assert_eq!(summary["udp_dropped_jobs"], 2);
        assert_eq!(summary["udp_dropped_pending_responses"], 0);
    }
}
