use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

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
    let metrics_dir = tempfile::tempdir().unwrap();
    let metrics_path = metrics_dir.path().join("tcp-setup.jsonl");

    let bin = env!("CARGO_BIN_EXE_yatht");
    let output = Command::new(bin)
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--proxy-local")
        .arg("--metrics-file")
        .arg(&metrics_path)
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

    let events = fs::read_to_string(metrics_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let setup = events
        .iter()
        .find(|event| event["event"] == "tcp_setup")
        .expect("missing TCP setup metric");
    assert_eq!(setup["outcome"], "completed");
    assert!(setup["target_cookie"].as_u64().is_some());
    assert!(setup["proxy_cookie"].as_u64().is_some());
    let summary = events.last().unwrap();
    assert_eq!(summary["event"], "run_summary");
    assert_eq!(summary["tcp_setup_completed"], 1);
    assert_eq!(summary["dropped_metric_events"], 0);
}

#[test]
fn keeps_proxy_alive_for_descendant_after_parent_exits() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let (_probe_dir, probe) = build_descendant_tcp_probe();
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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--proxy-local")
        .arg("--")
        .arg(&probe)
        .arg("parent")
        .arg(target_addr.to_string())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7), "status={:?}", output.status);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        target_addr
    );
    socks_thread.join().unwrap();
    target_thread.join().unwrap();
}

#[test]
fn preserves_tcp_socket_identity_aliases_and_epoll_registration() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

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

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--proxy-local")
        .arg("--")
        .arg(env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tcp_socket_semantics_probe",
            "--nocapture",
        ])
        .env("YATHT_TCP_SEMANTICS_PROBE", "1")
        .env("YATHT_TCP_TARGET", target_addr.to_string())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        target_addr
    );
    socks_thread.join().unwrap();
    target_thread.join().unwrap();
}

#[test]
fn preserves_tcp_socket_state_when_socks5_rejects_connect() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }

    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
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
        let dest = read_socks5_connect_request(&mut client);
        dest_tx.send(dest).unwrap();
        client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_yatht"))
        .arg("--proxy")
        .arg(format!("socks5://{socks_addr}"))
        .arg("--proxy-local")
        .arg("--")
        .arg(env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tcp_proxy_rejection_semantics_probe",
            "--nocapture",
        ])
        .env("YATHT_TCP_REJECTION_PROBE", "1")
        .env("YATHT_TCP_TARGET", target_addr.to_string())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        dest_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        target_addr
    );
    socks_thread.join().unwrap();
}

#[test]
#[ignore]
fn tcp_socket_semantics_probe() {
    if env::var_os("YATHT_TCP_SEMANTICS_PROBE").is_none() {
        return;
    }
    let target = env::var("YATHT_TCP_TARGET")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap();
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(
        fd >= 0,
        "socket failed: {}",
        std::io::Error::last_os_error()
    );
    bind_ipv4(fd, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    set_socket_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set_socket_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    let identity = socket_identity(fd);
    let local_addr = socket_address(fd);
    let alias = unsafe { libc::dup(fd) };
    assert!(
        alias >= 0,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );

    let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    assert!(
        epoll >= 0,
        "epoll_create1 failed: {}",
        std::io::Error::last_os_error()
    );
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 0x0059_4154_4854,
    };
    let rc = unsafe { libc::epoll_ctl(epoll, libc::EPOLL_CTL_ADD, fd, &mut event) };
    assert_eq!(
        rc,
        0,
        "epoll_ctl failed: {}",
        std::io::Error::last_os_error()
    );

    connect_ipv4(fd, target);
    assert_eq!(socket_identity(fd), identity);
    assert_eq!(socket_identity(alias), identity);
    assert_eq!(socket_address(fd), local_addr);
    assert_eq!(get_socket_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
    assert_eq!(get_socket_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY), 1);

    let mut stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let child_status = Command::new(env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tcp_inherited_socket_writer",
            "--nocapture",
        ])
        .env("YATHT_INHERITED_TCP_FD", alias.to_string())
        .status()
        .unwrap();
    assert!(child_status.success(), "inherited socket writer failed");
    unsafe { libc::close(alias) };
    let mut ready = libc::epoll_event { events: 0, u64: 0 };
    let count = unsafe { libc::epoll_wait(epoll, &mut ready, 1, 2_000) };
    assert_eq!(count, 1, "epoll did not observe the proxied response");
    assert_ne!(ready.events & libc::EPOLLIN as u32, 0);
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.ends_with("\r\n\r\nok"), "response={response:?}");
    unsafe { libc::close(epoll) };
}

#[test]
#[ignore]
fn tcp_proxy_rejection_semantics_probe() {
    if env::var_os("YATHT_TCP_REJECTION_PROBE").is_none() {
        return;
    }
    let target = env::var("YATHT_TCP_TARGET")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap();
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(
        fd >= 0,
        "socket failed: {}",
        std::io::Error::last_os_error()
    );
    bind_ipv4(fd, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    set_socket_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set_socket_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    let identity = socket_identity(fd);
    let local_addr = socket_address(fd);

    assert_eq!(connect_ipv4_error(fd, target), libc::ECONNREFUSED);
    assert_eq!(socket_identity(fd), identity);
    assert_eq!(socket_address(fd), local_addr);
    assert_eq!(get_socket_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
    assert_eq!(get_socket_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY), 1);
    unsafe { libc::close(fd) };
}

#[test]
#[ignore]
fn tcp_inherited_socket_writer() {
    let Some(fd) = env::var("YATHT_INHERITED_TCP_FD")
        .ok()
        .and_then(|value| value.parse::<libc::c_int>().ok())
    else {
        return;
    };
    let mut stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
}

fn handle_socks5_connect(client: &mut TcpStream, dest_tx: mpsc::Sender<SocketAddr>) {
    let dest = read_socks5_connect_request(client);
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

fn read_socks5_connect_request(client: &mut TcpStream) -> SocketAddr {
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
    SocketAddr::from((Ipv4Addr::from(ip), u16::from_be_bytes(port)))
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

fn bind_ipv4(fd: libc::c_int, address: SocketAddr) {
    let address = socket_addr_in(address);
    let rc = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind failed: {}", std::io::Error::last_os_error());
}

fn connect_ipv4(fd: libc::c_int, address: SocketAddr) {
    let address = socket_addr_in(address);
    let rc = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "connect failed: {}", std::io::Error::last_os_error());
}

fn connect_ipv4_error(fd: libc::c_int, address: SocketAddr) -> libc::c_int {
    let address = socket_addr_in(address);
    let rc = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(rc, -1, "connect unexpectedly succeeded");
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn socket_addr_in(address: SocketAddr) -> libc::sockaddr_in {
    let SocketAddr::V4(address) = address else {
        panic!("expected IPv4 address");
    };
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn socket_identity(fd: libc::c_int) -> (libc::dev_t, libc::ino_t) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut stat) };
    assert_eq!(rc, 0, "fstat failed: {}", std::io::Error::last_os_error());
    (stat.st_dev, stat.st_ino)
}

fn socket_address(fd: libc::c_int) -> SocketAddr {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockname failed: {}",
        std::io::Error::last_os_error()
    );
    SocketAddr::from((
        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    ))
}

fn set_socket_int(fd: libc::c_int, level: libc::c_int, option: libc::c_int, value: libc::c_int) {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt failed: {}",
        std::io::Error::last_os_error()
    );
}

fn get_socket_int(fd: libc::c_int, level: libc::c_int, option: libc::c_int) -> libc::c_int {
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockopt failed: {}",
        std::io::Error::last_os_error()
    );
    value
}

fn build_descendant_tcp_probe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("descendant_tcp_probe.rs");
    let bin = dir.path().join("descendant_tcp_probe");
    fs::write(
        &src,
        r#"
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args[1] == "child" {
        thread::sleep(Duration::from_millis(100));
        let mut stream = TcpStream::connect(&args[2]).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        print!("{}", response.rsplit("\r\n\r\n").next().unwrap());
        return;
    }

    Command::new(env::current_exe().unwrap())
        .arg("child")
        .arg(&args[2])
        .spawn()
        .unwrap();
    std::process::exit(7);
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
