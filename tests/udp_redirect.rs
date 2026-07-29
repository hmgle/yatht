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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
fn stable_udp_recvmmsg_honors_an_empty_queue_deadline() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_udp_recvmmsg_deadline_probe();
    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
        .env("SUP_UDP_SOCKET_MODE", "stable")
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
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

    errno = 0;
    if (recvmmsg(fd, NULL, 0, MSG_DONTWAIT, NULL) != 0) return 3;

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

    int status = fcntl(fd, F_GETFL, 0);
    if (status < 0 || fcntl(fd, F_SETFL, status | O_NONBLOCK) != 0) return 8;
    errno = 0;
    if (recvmmsg(fd, &msg, 1, 0, NULL) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) return 9;

    if (write(STDOUT_FILENO, "recvmmsg-errors-ok", 18) != 18) return 10;
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
    errno = 0;
    if (recvmmsg(fd, &msg, 1025, MSG_DONTWAIT, NULL) != -1 ||
        errno != EINVAL) return 4;

    /* A short explicit timespec still returns zero ahead of a longer armed
       SO_RCVTIMEO: the earlier deadline keeps its own expiry result. */
    struct timeval socket_timeout = { .tv_sec = 3, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout,
                   sizeof(socket_timeout)) != 0) return 5;
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 6;
    if (recvmmsg(fd, &msg, 1, 0, &timeout) != 0) return 7;
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

    /* The first proxied send lazily replaces the descriptor with the relay
       endpoint; the prompt response proves the relay is live. */
    if (sendto(fd, prompt_query, sizeof(prompt_query) - 1, 0,
               (struct sockaddr *)&destination, sizeof(destination)) !=
        (ssize_t)(sizeof(prompt_query) - 1)) return 5;
    char buffer[128];
    ssize_t received = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (received != (ssize_t)(sizeof(prompt_response) - 1) ||
        memcmp(buffer, prompt_response, sizeof(prompt_response) - 1) != 0) return 6;

    /* SO_RCVTIMEO armed on the replaced descriptor bounds a quiet receive. */
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 500000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 7;
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 8;
    errno = 0;
    if (recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) != -1 || errno != EAGAIN) return 9;
    long waited = elapsed_ms(&start);
    if (waited < 450 || waited > 5000) return 10;

    if (write(STDOUT_FILENO, "lazy-rcvtimeo-ok", 16) != 16) return 11;
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

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
