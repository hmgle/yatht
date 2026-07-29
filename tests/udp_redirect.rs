use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

const UDP_METADATA_QUERY: &[u8] = b"receive-metadata-query";
const UDP_METADATA_RESPONSE: &[u8] = b"receive-metadata-response";
const UDP_RECVMMSG_QUERIES: [&[u8]; 3] = [
    b"recvmmsg-query-one",
    b"recvmmsg-query-two",
    b"recvmmsg-query-three",
];
const UDP_RECVMMSG_RESPONSES: [&[u8]; 3] = [
    b"recvmmsg-first-response",
    b"recvmmsg-second-response",
    b"recvmmsg-third-response",
];

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
fn stable_udp_direct_receive_reports_actual_response_source() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_receive_metadata_probe();
    let (destination, response_source, server_thread) = spawn_changed_source_udp_exchange();

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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

    let socks_thread = thread::spawn(move || {
        let (mut client, _) = tcp.accept().unwrap();
        socks5_greet(&mut client);
        let _associate_dest = read_socks5_request(&mut client);
        let port = udp_addr.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();

        for response in [b"batch-one-ok".as_slice(), b"batch-two-ok".as_slice()] {
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .env("SUP_UDP_SOCKET_MODE", "stable")
        .arg("--proxy")
        .arg(format!("socks5://{tcp_addr}"))
        .arg("--enable-udp")
        .arg("--")
        .arg(&probe)
        .arg(destination.to_string())
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "batch-one-ok:batch-two-ok"
    );
    assert_eq!(
        payload_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (destination, b"batch-one".to_vec())
    );
    assert_eq!(
        payload_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        (destination, b"batch-two".to_vec())
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

fn build_udp_mmsg_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("udp_mmsg_probe.c");
    let bin = dir.path().join("udp_mmsg_probe");
    fs::write(
        &src,
        r#"
#define _GNU_SOURCE
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
    struct mmsghdr send_msgs[2];
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int i = 0; i < 2; ++i) {
        send_msgs[i].msg_hdr.msg_name = &dest;
        send_msgs[i].msg_hdr.msg_namelen = sizeof(dest);
        send_msgs[i].msg_hdr.msg_iov = &send_iov[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(fd, send_msgs, 2, 0) != 2) return 7;
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
    struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
    struct sockaddr_in msg_source;
    struct msghdr msg;
    memset(&msg_source, 0, sizeof(msg_source));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &msg_source;
    msg.msg_namelen = sizeof(msg_source);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ssize_t received_len = recvmsg(fd, &msg, 0);
    if (received_len != (ssize_t)sizeof(received)) return 10;
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
    "recvmmsg-query-one", "recvmmsg-query-two", "recvmmsg-query-three"
};
static const char *responses[] = {
    "recvmmsg-first-response",
    "recvmmsg-second-response",
    "recvmmsg-third-response"
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
    if (argc != 5) return 2;
    struct sockaddr_in destination;
    struct sockaddr_in expected_sources[3];
    if (parse_address(argv[1], &destination) != 0) return 3;
    for (int i = 0; i < 3; ++i) {
        if (parse_address(argv[i + 2], &expected_sources[i]) != 0) return 4;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 5;
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 6;

    struct iovec send_iov[3];
    struct mmsghdr send_msgs[3];
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int i = 0; i < 3; ++i) {
        send_iov[i].iov_base = (void *)queries[i];
        send_iov[i].iov_len = strlen(queries[i]);
        send_msgs[i].msg_hdr.msg_name = &destination;
        send_msgs[i].msg_hdr.msg_namelen = sizeof(destination);
        send_msgs[i].msg_hdr.msg_iov = &send_iov[i];
        send_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(fd, send_msgs, 3, 0) != 3) return 7;

    char first[7];
    char second[64];
    struct iovec recv_iov[2] = {
        { .iov_base = first, .iov_len = sizeof(first) },
        { .iov_base = second, .iov_len = sizeof(second) },
    };
    struct sockaddr_in sources[2];
    struct mmsghdr recv_msgs[2];
    memset(sources, 0, sizeof(sources));
    memset(recv_msgs, 0, sizeof(recv_msgs));
    for (int i = 0; i < 2; ++i) {
        recv_msgs[i].msg_hdr.msg_name = &sources[i];
        recv_msgs[i].msg_hdr.msg_namelen = sizeof(sources[i]);
        recv_msgs[i].msg_hdr.msg_iov = &recv_iov[i];
        recv_msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (recvmmsg(fd, recv_msgs, 2, MSG_TRUNC, NULL) != 2) return 8;
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
    if (write(STDOUT_FILENO, "recvmmsg-ok", 11) != 11) return 14;
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
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let response_source = sender.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let mut query = [0_u8; 128];
        let (n, peer) = receiver.recv_from(&mut query).unwrap();
        assert_eq!(&query[..n], UDP_METADATA_QUERY);
        sender.send_to(UDP_METADATA_RESPONSE, peer).unwrap();
    });
    (destination, response_source, server_thread)
}

fn spawn_changed_source_udp_batch_exchange() -> (SocketAddr, [SocketAddr; 3], thread::JoinHandle<()>)
{
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
            assert_eq!(&query[..n], UDP_RECVMMSG_QUERIES[index]);
            sender.send_to(UDP_RECVMMSG_RESPONSES[index], peer).unwrap();
        }
    });
    (destination, response_sources, server_thread)
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
