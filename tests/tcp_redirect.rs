use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn redirects_local_tcp_connect_through_socks5() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let Some(curl) = find_in_path("curl") else {
        return;
    };

    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        let mut req = [0_u8; 1024];
        let _ = stream.read(&mut req).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });

    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks.local_addr().unwrap();
    let (dest_tx, dest_rx) = mpsc::channel();
    let socks_thread = thread::spawn(move || {
        let (mut client, _) = socks.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        handle_socks5_connect(&mut client, dest_tx);
    });

    let bin = env!("CARGO_BIN_EXE_yatht");
    let output = Command::new(bin)
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--proxy-local")
        .arg("--")
        .arg(curl)
        .arg("-fsS")
        .arg(format!("http://127.0.0.1:{}/", target_addr.port()))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");

    let dest = dest_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(dest, target_addr);

    socks_thread.join().unwrap();
    target_thread.join().unwrap();
}

fn handle_socks5_connect(client: &mut TcpStream, dest_tx: mpsc::Sender<SocketAddr>) {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting[0], 5);
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).unwrap();
    assert!(methods.contains(&0));
    client.write_all(&[5, 0]).unwrap();

    let mut head = [0_u8; 4];
    client.read_exact(&mut head).unwrap();
    assert_eq!(&head[..3], &[5, 1, 0]);
    assert_eq!(head[3], 1);
    let mut ip = [0_u8; 4];
    let mut port = [0_u8; 2];
    client.read_exact(&mut ip).unwrap();
    client.read_exact(&mut port).unwrap();
    let dest = SocketAddr::from((Ipv4Addr::from(ip), u16::from_be_bytes(port)));
    dest_tx.send(dest).unwrap();

    let mut upstream = TcpStream::connect(dest).unwrap();
    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();

    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let n = client.read(&mut buf).unwrap();
        assert_ne!(n, 0);
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    upstream.write_all(&request).unwrap();

    loop {
        let n = upstream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        client.write_all(&buf[..n]).unwrap();
    }
}

fn find_in_path(name: &str) -> Option<String> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.into_os_string().to_string_lossy().into_owned());
        }
    }
    None
}
