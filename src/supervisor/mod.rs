use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::{EffectiveConfig, Route};
use crate::proxy;
use crate::seccomp::{self, SeccompNotif, SeccompNotifAddfd};

const CHILD_STAGE_ENV: &str = "SUP_CHILD_STAGE";
const TARGET_PATH_ENV: &str = "SUP_TARGET_PATH";
const TARGET_ARGV_ENV: &str = "SUP_TARGET_ARGV";
const TRAP_SET_ENV: &str = "SUP_TRAP_SET";
const CONTROL_FD: RawFd = 3;
const MAX_UDP_PAYLOAD: usize = 65_535;
const MAX_NOTIFICATION_WORKERS: usize = 64;
const NOTIFICATION_QUEUE_PER_WORKER: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Destination {
    pub ip: IpAddr,
    pub port: u16,
}

impl Destination {
    pub fn authority(self) -> String {
        match self.ip {
            IpAddr::V4(ip) => format!("{ip}:{}", self.port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", self.port),
        }
    }
}

pub fn is_child_stage() -> bool {
    std::env::var_os(CHILD_STAGE_ENV).is_some()
}

pub fn run(cfg: EffectiveConfig) -> Result<i32> {
    if cfg.command.is_empty() {
        bail!("missing command");
    }

    let target_path = resolve_target(&cfg.command[0])?;
    let argv = cfg.command.clone();
    let (parent_sock, child_sock) = socketpair().context("create control socketpair")?;
    let trap_set = if cfg.enable_dns || cfg.enable_udp {
        seccomp::TrapSet::with_udp()
    } else {
        seccomp::TrapSet::tcp_only()
    };

    let mut command = Command::new(std::env::current_exe().context("resolve current executable")?);
    command
        .env(CHILD_STAGE_ENV, "1")
        .env(
            TARGET_PATH_ENV,
            encode_os(&target_path.as_os_str().to_os_string())?,
        )
        .env(TARGET_ARGV_ENV, encode_os_list(&argv)?)
        .env(TRAP_SET_ENV, trap_set.encode());

    let child_fd = child_sock;
    let parent_fd = parent_sock;
    unsafe {
        command.pre_exec(move || {
            if child_fd != CONTROL_FD && libc::dup2(child_fd, CONTROL_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if parent_fd != CONTROL_FD {
                libc::close(parent_fd);
            }
            if child_fd != CONTROL_FD {
                libc::close(child_fd);
            }
            Ok(())
        });
    }

    let mut child = command.spawn().context("spawn child stage")?;
    close_fd(child_sock);

    let listener_fd = match recv_listener_fd(parent_sock, child.id()) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            close_fd(parent_sock);
            return Err(err).context("duplicate seccomp listener fd");
        }
    };
    if let Err(err) = write_all_fd(parent_sock, b"G") {
        let _ = child.kill();
        let _ = child.wait();
        close_fd(parent_sock);
        return Err(err).context("ack child stage");
    }
    close_fd(parent_sock);

    let cfg = Arc::new(cfg);
    let relays = Arc::new(UdpRelayRegistry::default());
    let listener_fd = Arc::new(listener_fd);
    let loop_cfg = Arc::clone(&cfg);
    let loop_relays = Arc::clone(&relays);
    thread::spawn(move || notification_loop(listener_fd, loop_cfg, loop_relays));

    let status = child.wait().context("wait for target")?;
    if let Some(code) = status.code() {
        Ok(code)
    } else if let Some(signal) = status.signal() {
        Ok(128 + signal)
    } else {
        Ok(1)
    }
}

pub fn run_child_stage() -> Result<i32> {
    let target_path = decode_os(
        std::env::var(TARGET_PATH_ENV)
            .context("child stage missing target path")?
            .as_str(),
    )?;
    let argv = decode_os_list(
        std::env::var(TARGET_ARGV_ENV)
            .context("child stage missing target argv")?
            .as_str(),
    )?;
    let trap_set = seccomp::TrapSet::decode(
        std::env::var(TRAP_SET_ENV)
            .context("child stage missing trap set")?
            .as_str(),
    )
    .context("child stage has invalid trap set")?;

    set_no_new_privs().context("set PR_SET_NO_NEW_PRIVS")?;
    let listener_fd = seccomp::install_listener(trap_set).context("install seccomp listener")?;
    write_all_fd(CONTROL_FD, &listener_fd.to_ne_bytes()).context("send listener fd number")?;

    let mut ack = [0_u8; 1];
    read_exact_fd(CONTROL_FD, &mut ack).context("wait for supervisor ack")?;
    close_fd(listener_fd);
    close_fd(CONTROL_FD);

    exec_target(target_path.into(), argv)
}

fn notification_loop(
    listener_fd: Arc<OwnedFd>,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let worker_count = notification_worker_count();
    let (tx, rx) = mpsc::sync_channel::<SeccompNotif>(
        worker_count.saturating_mul(NOTIFICATION_QUEUE_PER_WORKER),
    );
    let (blocking_tx, blocking_rx) = mpsc::sync_channel::<SeccompNotif>(
        worker_count.saturating_mul(NOTIFICATION_QUEUE_PER_WORKER),
    );
    let rx = Arc::new(Mutex::new(rx));
    let blocking_rx = Arc::new(Mutex::new(blocking_rx));
    for _ in 0..worker_count {
        let worker_rx = Arc::clone(&rx);
        let worker_listener_fd = Arc::clone(&listener_fd);
        let worker_cfg = Arc::clone(&cfg);
        let worker_relays = Arc::clone(&relays);
        thread::spawn(move || {
            notification_worker(worker_listener_fd, worker_rx, worker_cfg, worker_relays)
        });
    }
    for _ in 0..worker_count {
        let worker_rx = Arc::clone(&blocking_rx);
        let worker_listener_fd = Arc::clone(&listener_fd);
        let worker_cfg = Arc::clone(&cfg);
        let worker_relays = Arc::clone(&relays);
        thread::spawn(move || {
            notification_worker(worker_listener_fd, worker_rx, worker_cfg, worker_relays)
        });
    }

    loop {
        let listener_raw_fd = listener_fd.as_raw_fd();
        match seccomp::notif_recv(listener_raw_fd) {
            Ok(notif) => {
                if is_blocking_recv_notification(&notif) {
                    if !try_queue_notification(
                        &blocking_tx,
                        listener_raw_fd,
                        notif,
                        cfg.debug,
                        "blocking recv",
                    ) {
                        return;
                    }
                    continue;
                }
                if !try_queue_notification(&tx, listener_raw_fd, notif, cfg.debug, "notification") {
                    return;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                if cfg.debug {
                    eprintln!("seccomp-unotify-proxy: notification loop stopped: {err}");
                }
                return;
            }
        }
    }
}

fn try_queue_notification(
    tx: &mpsc::SyncSender<SeccompNotif>,
    listener_fd: RawFd,
    notif: SeccompNotif,
    debug: bool,
    queue_name: &str,
) -> bool {
    match tx.try_send(notif) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(notif)) => {
            if debug {
                eprintln!("seccomp-unotify-proxy: {queue_name} queue full");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::EAGAIN);
            true
        }
        Err(mpsc::TrySendError::Disconnected(notif)) => {
            if debug {
                eprintln!("seccomp-unotify-proxy: {queue_name} workers stopped");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::EIO);
            false
        }
    }
}

fn notification_worker(
    listener_fd: Arc<OwnedFd>,
    rx: Arc<Mutex<mpsc::Receiver<SeccompNotif>>>,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    loop {
        let notif = {
            let rx = rx.lock().expect("notification worker receiver poisoned");
            rx.recv()
        };
        let Ok(notif) = notif else {
            return;
        };
        handle_notification(
            listener_fd.as_raw_fd(),
            notif,
            Arc::clone(&cfg),
            Arc::clone(&relays),
        );
    }
}

fn notification_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get().saturating_mul(2))
        .unwrap_or(4)
        .clamp(4, MAX_NOTIFICATION_WORKERS)
}

fn is_blocking_recv_notification(notif: &SeccompNotif) -> bool {
    matches!(
        notif.data.nr as libc::c_long,
        libc::SYS_recvfrom | libc::SYS_recvmsg
    )
}

fn handle_notification(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    match notif.data.nr as libc::c_long {
        libc::SYS_connect => handle_connect(listener_fd, notif, cfg, relays),
        libc::SYS_sendto => handle_sendto(listener_fd, notif, cfg, relays),
        libc::SYS_sendmsg => handle_sendmsg(listener_fd, notif, cfg, relays),
        libc::SYS_recvfrom => handle_recvfrom(listener_fd, notif, relays),
        libc::SYS_recvmsg => handle_recvmsg(listener_fd, notif, relays),
        _ => seccomp::send_continue(listener_fd, notif.id),
    }
}

fn handle_connect(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let addr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;
    if addr == 0 || addr_len < 2 {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    let raw = match read_sockaddr(notif.pid, addr, addr_len) {
        Ok(raw) => raw,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };

    let dest = match parse_sockaddr(&raw) {
        Ok(dest) => dest,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };

    if direct_connect_can_continue_before_socket_type(&cfg, dest) {
        if cfg.debug {
            eprintln!(
                "seccomp-unotify-proxy: direct {} for pid={} fd={}",
                dest.authority(),
                notif.pid,
                target_fd
            );
        }
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    match socket_type(notif.pid, target_fd) {
        Some(libc::SOCK_DGRAM) => {
            if udp_route_for(&cfg, dest).is_some() {
                if !seccomp::notif_id_valid(listener_fd, notif.id) {
                    return;
                }
                if cfg.debug {
                    eprintln!(
                        "seccomp-unotify-proxy: UDP connect relay {} for pid={} fd={}",
                        dest.authority(),
                        notif.pid,
                        target_fd
                    );
                }
                match relays.ensure(
                    listener_fd,
                    &cfg,
                    notif.id,
                    notif.pid,
                    target_fd,
                    Some(dest),
                ) {
                    Ok(_) => {
                        seccomp::send_success(listener_fd, notif.id);
                    }
                    Err(err) => {
                        if cfg.debug {
                            eprintln!("seccomp-unotify-proxy: UDP relay setup failed: {err:#}");
                        }
                        seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
                    }
                }
                return;
            }

            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        Some(libc::SOCK_STREAM) => {}
        Some(other) => {
            if cfg.debug {
                eprintln!(
                    "seccomp-unotify-proxy: unsupported socket type {} for pid={} fd={}",
                    other, notif.pid, target_fd
                );
            }
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        None => {
            if cfg.debug {
                eprintln!(
                    "seccomp-unotify-proxy: cannot inspect socket type for pid={} fd={}",
                    notif.pid, target_fd
                );
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            return;
        }
    }

    if cfg.route_for(dest.ip) == Route::Direct {
        if cfg.debug {
            eprintln!(
                "seccomp-unotify-proxy: direct {} for pid={} fd={}",
                dest.authority(),
                notif.pid,
                target_fd
            );
        }
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    if cfg.debug {
        eprintln!(
            "seccomp-unotify-proxy: proxy {} for pid={} fd={}",
            dest.authority(),
            notif.pid,
            target_fd
        );
    }

    let stream = match proxy::dial(&cfg.proxy, dest, cfg.connect_timeout) {
        Ok(stream) => stream,
        Err(err) => {
            if cfg.debug {
                eprintln!(
                    "seccomp-unotify-proxy: proxy dial {} failed: {err:#}",
                    dest.authority()
                );
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            return;
        }
    };

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    let target_flags = read_target_fd_flags(notif.pid, target_fd);
    if target_flags.status_flags & libc::O_NONBLOCK != 0 {
        let _ = set_nonblocking(stream.as_raw_fd());
    }

    let mut addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: seccomp::ADDFD_FLAG_SETFD,
        srcfd: stream.as_raw_fd() as u32,
        newfd: target_fd as u32,
        newfd_flags: target_flags.newfd_flags,
    };

    match seccomp::notif_addfd(listener_fd, &mut addfd) {
        Ok(_) => seccomp::send_success(listener_fd, notif.id),
        Err(err) => {
            if cfg.debug {
                eprintln!("seccomp-unotify-proxy: ADDFD failed: {err}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
        }
    }
}

fn handle_sendto(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let buf_ptr = notif.data.args[1];
    let len = notif.data.args[2] as usize;
    let addr = notif.data.args[4];
    let addr_len = notif.data.args[5] as usize;

    if addr == 0 || addr_len == 0 {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    let Some((dest, payload)) = read_udp_send(notif.pid, addr, addr_len, buf_ptr, len) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if udp_route_for(&cfg, dest).is_none() {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    match relays.ensure(listener_fd, &cfg, notif.id, notif.pid, target_fd, None) {
        Ok(handle) => {
            if handle.send(dest, payload).is_ok() {
                seccomp::send_value(listener_fd, notif.id, len as i64);
            } else {
                seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            }
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("seccomp-unotify-proxy: UDP relay setup failed: {err:#}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
        }
    }
}

fn handle_sendmsg(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let msg_ptr = notif.data.args[1];

    if msg_ptr == 0 {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    let msg = match read_msghdr(notif.pid, msg_ptr) {
        Ok(msg) => msg,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };
    if msg.name == 0 || msg.name_len == 0 {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    let raw = match read_sockaddr(notif.pid, msg.name, msg.name_len as usize) {
        Ok(raw) => raw,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };
    let dest = match parse_sockaddr(&raw) {
        Ok(dest) => dest,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };
    if udp_route_for(&cfg, dest).is_none() {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    let payload = match read_iovecs(notif.pid, msg.iov, msg.iov_len) {
        Ok(payload) => payload,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    let written = payload.len() as i64;
    match relays.ensure(listener_fd, &cfg, notif.id, notif.pid, target_fd, None) {
        Ok(handle) => {
            if handle.send(dest, payload).is_ok() {
                seccomp::send_value(listener_fd, notif.id, written);
            } else {
                seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            }
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("seccomp-unotify-proxy: UDP relay setup failed: {err:#}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
        }
    }
}

fn handle_recvfrom(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let target_fd = notif.data.args[0] as RawFd;
    let buf_ptr = notif.data.args[1];
    let len = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;
    let src_addr = notif.data.args[4];
    let addr_len_ptr = notif.data.args[5];

    let Some(handle) = relays.get(notif.pid, target_fd) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if len > MAX_UDP_PAYLOAD {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    let addr_len = if src_addr != 0 && addr_len_ptr != 0 {
        match read_socklen(notif.pid, addr_len_ptr) {
            Ok(addr_len) => Some(addr_len),
            Err(_) => {
                seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                return;
            }
        }
    } else {
        None
    };

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    match recv_from_relay_fd(notif.pid, target_fd, len, flags) {
        Ok(payload) => {
            if let Err(err) = write_proc_bytes(notif.pid, buf_ptr, &payload) {
                if err.kind() == io::ErrorKind::Interrupted {
                    seccomp::send_errno(listener_fd, notif.id, libc::EINTR);
                } else {
                    seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                }
                return;
            }
            if let Some(addr_len) = addr_len {
                if let Some(source) = handle.response_source(flags) {
                    if write_sockaddr_result(notif.pid, src_addr, addr_len_ptr, addr_len, source)
                        .is_err()
                    {
                        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                        return;
                    }
                }
            } else if flags & libc::MSG_PEEK == 0 {
                let _ = handle.response_source(flags);
            }
            seccomp::send_value(listener_fd, notif.id, payload.len() as i64);
        }
        Err(err) => seccomp::send_errno(listener_fd, notif.id, errno_from_io(&err)),
    }
}

fn handle_recvmsg(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let target_fd = notif.data.args[0] as RawFd;
    let msg_ptr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;

    let Some(handle) = relays.get(notif.pid, target_fd) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if msg_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let msg = match read_msghdr(notif.pid, msg_ptr) {
        Ok(msg) => msg,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    let iovecs = match read_iovec_targets(notif.pid, msg.iov, msg.iov_len) {
        Ok(iovecs) => iovecs,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    let capacity = iovecs
        .iter()
        .try_fold(0_usize, |acc, iov| acc.checked_add(iov.len))
        .filter(|len| *len <= MAX_UDP_PAYLOAD)
        .unwrap_or(MAX_UDP_PAYLOAD);

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    match recv_msg_from_relay_fd(notif.pid, target_fd, capacity, flags) {
        Ok(received) => {
            if write_iovec_payload(notif.pid, &iovecs, &received.payload).is_err()
                || write_proc_bytes(notif.pid, msg_ptr + 48, &received.msg_flags.to_ne_bytes())
                    .is_err()
            {
                seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                return;
            }
            if msg.name != 0 {
                if let Some(source) = handle.response_source(flags) {
                    if write_sockaddr_to_msghdr(notif.pid, msg_ptr, msg.name, msg.name_len, source)
                        .is_err()
                    {
                        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                        return;
                    }
                }
            } else if flags & libc::MSG_PEEK == 0 {
                let _ = handle.response_source(flags);
            }
            seccomp::send_value(listener_fd, notif.id, received.result_len as i64);
        }
        Err(err) => seccomp::send_errno(listener_fd, notif.id, errno_from_io(&err)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRouteKind {
    Dns,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RelayKey {
    pid: u32,
    fd: RawFd,
}

#[derive(Default)]
struct UdpRelayRegistry {
    inner: Mutex<HashMap<RelayKey, UdpRelayHandle>>,
}

#[derive(Clone)]
struct UdpRelayHandle {
    tx: mpsc::Sender<UdpJob>,
    default_dest: Arc<Mutex<Option<Destination>>>,
    pending_sources: Arc<Mutex<VecDeque<Destination>>>,
}

struct UdpJob {
    dest: Destination,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct UdpRelayConfig {
    proxy: crate::config::ProxyConfig,
    dns_server: Destination,
    enable_dns: bool,
    enable_udp: bool,
    timeout: Duration,
    debug: bool,
}

impl UdpRelayRegistry {
    fn ensure(
        &self,
        listener_fd: RawFd,
        cfg: &EffectiveConfig,
        notif_id: u64,
        pid: u32,
        fd: RawFd,
        default_dest: Option<Destination>,
    ) -> Result<UdpRelayHandle> {
        let key = RelayKey { pid, fd };
        if let Some(handle) = self.inner.lock().unwrap().get(&key).cloned() {
            if let Some(dest) = default_dest {
                handle.set_default_dest(dest);
            }
            return Ok(handle);
        }

        let (relay_socket, target_fd) = make_udp_pair().context("create UDP relay socket pair")?;
        let target_flags = read_target_fd_flags(pid, fd);
        if target_flags.status_flags & libc::O_NONBLOCK != 0 {
            let _ = set_nonblocking(target_fd);
        }

        let mut addfd = SeccompNotifAddfd {
            id: notif_id,
            flags: seccomp::ADDFD_FLAG_SETFD,
            srcfd: target_fd as u32,
            newfd: fd as u32,
            newfd_flags: target_flags.newfd_flags,
        };
        let addfd_result = seccomp::notif_addfd(listener_fd, &mut addfd);
        close_fd(target_fd);
        addfd_result.context("inject UDP relay fd")?;

        let relay_cfg = UdpRelayConfig {
            proxy: cfg.proxy.clone(),
            dns_server: parse_destination_addr(&cfg.dns_server).context("parse DNS server")?,
            enable_dns: cfg.enable_dns,
            enable_udp: cfg.enable_udp,
            timeout: cfg.connect_timeout,
            debug: cfg.debug,
        };
        let handle = start_udp_relay(relay_cfg, relay_socket, default_dest);
        self.inner.lock().unwrap().insert(key, handle.clone());
        Ok(handle)
    }

    fn get(&self, pid: u32, fd: RawFd) -> Option<UdpRelayHandle> {
        self.inner
            .lock()
            .unwrap()
            .get(&RelayKey { pid, fd })
            .cloned()
    }
}

impl UdpRelayHandle {
    fn set_default_dest(&self, dest: Destination) {
        *self.default_dest.lock().unwrap() = Some(dest);
    }

    fn send(&self, dest: Destination, payload: Vec<u8>) -> Result<()> {
        self.tx
            .send(UdpJob { dest, payload })
            .map_err(|_| anyhow!("UDP relay worker exited"))
    }

    fn response_source(&self, flags: i32) -> Option<Destination> {
        let mut pending = self.pending_sources.lock().unwrap();
        if flags & libc::MSG_PEEK != 0 {
            pending.front().copied()
        } else {
            pending.pop_front()
        }
    }
}

fn start_udp_relay(
    cfg: UdpRelayConfig,
    relay_socket: UdpSocket,
    default_dest: Option<Destination>,
) -> UdpRelayHandle {
    let socket = Arc::new(relay_socket);
    let (tx, rx) = mpsc::channel::<UdpJob>();
    let default_dest = Arc::new(Mutex::new(default_dest));
    let pending_sources = Arc::new(Mutex::new(VecDeque::new()));

    let read_socket = Arc::clone(&socket);
    let read_tx = tx.clone();
    let read_default_dest = Arc::clone(&default_dest);
    thread::spawn(move || {
        let mut buf = vec![0_u8; MAX_UDP_PAYLOAD];
        while let Ok(n) = read_socket.recv(&mut buf) {
            let Some(dest) = *read_default_dest.lock().unwrap() else {
                continue;
            };
            let payload = buf[..n].to_vec();
            if read_tx.send(UdpJob { dest, payload }).is_err() {
                break;
            }
        }
    });

    let write_pending_sources = Arc::clone(&pending_sources);
    thread::spawn(move || {
        let mut socks_udp = None;
        for job in rx {
            let source = job.dest;
            match forward_udp_job(&cfg, &mut socks_udp, job) {
                Ok(Some(response)) => {
                    let mut pending = write_pending_sources.lock().unwrap();
                    pending.push_back(source);
                    if socket.send(&response).is_err() {
                        let _ = pending.pop_back();
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    if cfg.debug {
                        eprintln!("seccomp-unotify-proxy: UDP relay forward failed: {err:#}");
                    }
                }
            }
        }
    });

    UdpRelayHandle {
        tx,
        default_dest,
        pending_sources,
    }
}

fn forward_udp_job(
    cfg: &UdpRelayConfig,
    socks_udp: &mut Option<proxy::Socks5UdpAssociation>,
    job: UdpJob,
) -> Result<Option<Vec<u8>>> {
    match udp_route_for_relay(cfg, job.dest) {
        Some(UdpRouteKind::Dns) => {
            proxy::dns_over_tcp(&cfg.proxy, cfg.dns_server, &job.payload, cfg.timeout).map(Some)
        }
        Some(UdpRouteKind::Generic) => {
            if socks_udp.is_none() {
                *socks_udp = Some(proxy::Socks5UdpAssociation::connect(
                    &cfg.proxy,
                    cfg.timeout,
                )?);
            }
            socks_udp
                .as_mut()
                .expect("SOCKS5 UDP association initialized")
                .send_datagram(job.dest, &job.payload, cfg.timeout)
        }
        None => Ok(None),
    }
}

fn udp_route_for(cfg: &EffectiveConfig, dest: Destination) -> Option<UdpRouteKind> {
    if cfg.enable_dns && dest.port == 53 {
        Some(UdpRouteKind::Dns)
    } else if cfg.enable_udp && cfg.route_for(dest.ip) == Route::Proxy {
        Some(UdpRouteKind::Generic)
    } else {
        None
    }
}

fn direct_connect_can_continue_before_socket_type(
    cfg: &EffectiveConfig,
    dest: Destination,
) -> bool {
    cfg.route_for(dest.ip) == Route::Direct && !(cfg.enable_dns && dest.port == 53)
}

fn udp_route_for_relay(cfg: &UdpRelayConfig, dest: Destination) -> Option<UdpRouteKind> {
    if cfg.enable_dns && dest.port == 53 {
        Some(UdpRouteKind::Dns)
    } else if cfg.enable_udp {
        Some(UdpRouteKind::Generic)
    } else {
        None
    }
}

fn make_udp_pair() -> io::Result<(UdpSocket, RawFd)> {
    let relay = UdpSocket::bind("127.0.0.1:0")?;
    let target = UdpSocket::bind("127.0.0.1:0")?;
    relay.connect(target.local_addr()?)?;
    target.connect(relay.local_addr()?)?;
    let target_fd = target.into_raw_fd();
    Ok((relay, target_fd))
}

fn read_udp_send(
    pid: u32,
    addr: u64,
    addr_len: usize,
    buf_ptr: u64,
    len: usize,
) -> Option<(Destination, Vec<u8>)> {
    if len > MAX_UDP_PAYLOAD {
        return None;
    }
    let raw_addr = read_sockaddr(pid, addr, addr_len).ok()?;
    let dest = parse_sockaddr(&raw_addr).ok()?;
    let payload = read_proc_bytes(pid, buf_ptr, len).ok()?;
    Some((dest, payload))
}

#[derive(Debug)]
struct TargetMsghdr {
    name: u64,
    name_len: u32,
    iov: u64,
    iov_len: u64,
}

fn read_msghdr(pid: u32, msg_ptr: u64) -> io::Result<TargetMsghdr> {
    let raw = read_proc_bytes(pid, msg_ptr, 56)?;
    Ok(TargetMsghdr {
        name: u64::from_ne_bytes(raw[0..8].try_into().unwrap()),
        name_len: u32::from_ne_bytes(raw[8..12].try_into().unwrap()),
        iov: u64::from_ne_bytes(raw[16..24].try_into().unwrap()),
        iov_len: u64::from_ne_bytes(raw[24..32].try_into().unwrap()),
    })
}

fn read_iovecs(pid: u32, iov_ptr: u64, iov_len: u64) -> io::Result<Vec<u8>> {
    let iovecs = read_iovec_targets(pid, iov_ptr, iov_len)?;
    let total = iovec_total_len(&iovecs)?;
    read_iovec_payload(pid, &iovecs, total)
}

#[derive(Clone, Copy)]
struct TargetIovec {
    base: u64,
    len: usize,
}

struct RelayRecvmsg {
    payload: Vec<u8>,
    result_len: usize,
    msg_flags: i32,
}

fn read_iovec_targets(pid: u32, iov_ptr: u64, iov_len: u64) -> io::Result<Vec<TargetIovec>> {
    if iov_len > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many iovecs",
        ));
    }
    let mut iovecs = Vec::with_capacity(iov_len as usize);
    for index in 0..iov_len {
        let raw = read_proc_bytes(pid, iov_ptr + index * 16, 16)?;
        let base = u64::from_ne_bytes(raw[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(raw[8..16].try_into().unwrap()) as usize;
        iovecs.push(TargetIovec { base, len });
    }
    Ok(iovecs)
}

fn iovec_total_len(iovecs: &[TargetIovec]) -> io::Result<usize> {
    iovecs.iter().try_fold(0_usize, |acc, iov| {
        acc.checked_add(iov.len)
            .filter(|len| *len <= MAX_UDP_PAYLOAD)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UDP payload too large"))
    })
}

fn read_iovec_payload(pid: u32, iovecs: &[TargetIovec], total_len: usize) -> io::Result<Vec<u8>> {
    let mut payload = vec![0_u8; total_len];
    if total_len == 0 {
        return Ok(payload);
    }

    let mut local = Vec::new();
    let mut remote = Vec::new();
    let mut offset = 0;
    for iov in iovecs.iter().copied().filter(|iov| iov.len > 0) {
        local.push(libc::iovec {
            iov_base: unsafe { payload.as_mut_ptr().add(offset) }.cast(),
            iov_len: iov.len,
        });
        remote.push(libc::iovec {
            iov_base: iov.base as usize as *mut libc::c_void,
            iov_len: iov.len,
        });
        offset += iov.len;
    }

    process_vm_readv_all(pid, &mut local, &mut remote)?;
    Ok(payload)
}

fn recv_from_relay_fd(pid: u32, fd: RawFd, len: usize, flags: i32) -> io::Result<Vec<u8>> {
    let duplicated = duplicate_remote_fd(pid, fd)?;
    let mut payload = vec![0_u8; len];
    loop {
        let rc = unsafe {
            libc::recv(
                duplicated.as_raw_fd(),
                payload.as_mut_ptr().cast(),
                payload.len(),
                flags,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        payload.truncate(rc as usize);
        return Ok(payload);
    }
}

fn recv_msg_from_relay_fd(
    pid: u32,
    fd: RawFd,
    capacity: usize,
    flags: i32,
) -> io::Result<RelayRecvmsg> {
    let duplicated = duplicate_remote_fd(pid, fd)?;
    let mut payload = vec![0_u8; capacity];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    loop {
        let rc = unsafe { libc::recvmsg(duplicated.as_raw_fd(), &mut msg, flags) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let copied_len = (rc as usize).min(payload.len());
        payload.truncate(copied_len);
        return Ok(RelayRecvmsg {
            payload,
            result_len: rc as usize,
            msg_flags: msg.msg_flags,
        });
    }
}

fn write_iovec_payload(pid: u32, iovecs: &[TargetIovec], payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    let mut local = Vec::new();
    let mut remote = Vec::new();
    let mut offset = 0;
    for iov in iovecs.iter().copied().filter(|iov| iov.len > 0) {
        if offset >= payload.len() {
            break;
        }
        let len = (payload.len() - offset).min(iov.len);
        local.push(libc::iovec {
            iov_base: payload[offset..offset + len].as_ptr() as *mut libc::c_void,
            iov_len: len,
        });
        remote.push(libc::iovec {
            iov_base: iov.base as usize as *mut libc::c_void,
            iov_len: len,
        });
        offset += len;
    }

    process_vm_writev_all(pid, &mut local, &mut remote)
}

fn read_socklen(pid: u32, addr: u64) -> io::Result<u32> {
    let raw = read_proc_bytes(pid, addr, std::mem::size_of::<libc::socklen_t>())?;
    Ok(u32::from_ne_bytes(raw.try_into().unwrap()))
}

fn write_sockaddr_result(
    pid: u32,
    addr: u64,
    addr_len_ptr: u64,
    addr_len: u32,
    source: Destination,
) -> io::Result<()> {
    let raw = sockaddr_bytes(source);
    let write_len = (addr_len as usize).min(raw.len());
    write_proc_bytes(pid, addr, &raw[..write_len])?;
    write_proc_bytes(pid, addr_len_ptr, &(raw.len() as u32).to_ne_bytes())
}

fn write_sockaddr_to_msghdr(
    pid: u32,
    msg_ptr: u64,
    addr: u64,
    addr_len: u32,
    source: Destination,
) -> io::Result<()> {
    let raw = sockaddr_bytes(source);
    let write_len = (addr_len as usize).min(raw.len());
    write_proc_bytes(pid, addr, &raw[..write_len])?;
    write_proc_bytes(pid, msg_ptr + 8, &(raw.len() as u32).to_ne_bytes())
}

fn sockaddr_bytes(dest: Destination) -> Vec<u8> {
    match dest.ip {
        IpAddr::V4(ip) => {
            let mut raw = vec![0_u8; 16];
            raw[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&dest.port.to_be_bytes());
            raw[4..8].copy_from_slice(&ip.octets());
            raw
        }
        IpAddr::V6(ip) => {
            let mut raw = vec![0_u8; 28];
            raw[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&dest.port.to_be_bytes());
            raw[8..24].copy_from_slice(&ip.octets());
            raw
        }
    }
}

fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

fn socket_type(pid: u32, fd: RawFd) -> Option<i32> {
    if let Ok(duplicated) = duplicate_remote_fd(pid, fd) {
        return socket_type_from_fd(duplicated.as_raw_fd());
    }

    let file = File::open(format!("/proc/{pid}/fd/{fd}")).ok()?;
    socket_type_from_fd(file.as_raw_fd())
}

fn socket_type_from_fd(fd: RawFd) -> Option<i32> {
    let mut ty: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&ty) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        None
    } else {
        Some(ty)
    }
}

fn exec_target(target_path: PathBuf, argv: Vec<OsString>) -> Result<i32> {
    if argv.is_empty() {
        bail!("target argv is empty");
    }

    let mut command = Command::new(&target_path);
    command.arg0(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }

    let env = std::env::vars_os()
        .filter(|(key, _)| {
            key != CHILD_STAGE_ENV
                && key != TARGET_PATH_ENV
                && key != TARGET_ARGV_ENV
                && key != TRAP_SET_ENV
        })
        .collect::<Vec<_>>();
    command.env_clear().envs(env);

    let err = command.exec();
    Err(anyhow!("exec {}: {err}", target_path.display()))
}

fn resolve_target(cmd: &OsStr) -> Result<PathBuf> {
    let path = PathBuf::from(cmd);
    if path.components().count() > 1 {
        return Ok(path);
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(cmd);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("cannot find command {:?}", cmd);
}

fn is_executable(path: &PathBuf) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

fn read_sockaddr(pid: u32, addr: u64, addr_len: usize) -> io::Result<Vec<u8>> {
    let len = addr_len.min(128);
    read_proc_bytes(pid, addr, len)
}

fn read_proc_bytes(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut raw = vec![0_u8; len];
    if len == 0 {
        return Ok(raw);
    }
    process_vm_read(pid, addr, &mut raw)?;
    Ok(raw)
}

fn write_proc_bytes(pid: u32, mut addr: u64, mut buf: &[u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    while !buf.is_empty() {
        let written = process_vm_write(pid, addr, buf)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        addr += written as u64;
        buf = &buf[written..];
    }
    Ok(())
}

fn process_vm_read(pid: u32, mut addr: u64, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let rc = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short process_vm_readv",
            ));
        }
        let read = rc as usize;
        addr += read as u64;
        buf = &mut buf[read..];
    }
    Ok(())
}

fn process_vm_write(pid: u32, addr: u64, buf: &[u8]) -> io::Result<usize> {
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: buf.len(),
    };
    loop {
        let rc = unsafe { libc::process_vm_writev(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn process_vm_readv_all(
    pid: u32,
    local: &mut [libc::iovec],
    remote: &mut [libc::iovec],
) -> io::Result<()> {
    let mut local_start = 0;
    let mut remote_start = 0;
    let mut remaining = iovecs_len(local);
    while remaining > 0 {
        let rc = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                local[local_start..].as_ptr(),
                (local.len() - local_start) as libc::c_ulong,
                remote[remote_start..].as_ptr(),
                (remote.len() - remote_start) as libc::c_ulong,
                0,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short process_vm_readv",
            ));
        }
        let read = (rc as usize).min(remaining);
        advance_iovecs(local, &mut local_start, read);
        advance_iovecs(remote, &mut remote_start, read);
        remaining -= read;
    }
    Ok(())
}

fn process_vm_writev_all(
    pid: u32,
    local: &mut [libc::iovec],
    remote: &mut [libc::iovec],
) -> io::Result<()> {
    let mut local_start = 0;
    let mut remote_start = 0;
    let mut remaining = iovecs_len(local);
    while remaining > 0 {
        let rc = unsafe {
            libc::process_vm_writev(
                pid as libc::pid_t,
                local[local_start..].as_ptr(),
                (local.len() - local_start) as libc::c_ulong,
                remote[remote_start..].as_ptr(),
                (remote.len() - remote_start) as libc::c_ulong,
                0,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        let written = (rc as usize).min(remaining);
        advance_iovecs(local, &mut local_start, written);
        advance_iovecs(remote, &mut remote_start, written);
        remaining -= written;
    }
    Ok(())
}

fn iovecs_len(iovecs: &[libc::iovec]) -> usize {
    iovecs.iter().map(|iov| iov.iov_len).sum()
}

fn advance_iovecs(iovecs: &mut [libc::iovec], start: &mut usize, mut bytes: usize) {
    while bytes > 0 {
        let iov = &mut iovecs[*start];
        if bytes >= iov.iov_len {
            bytes -= iov.iov_len;
            *start += 1;
        } else {
            iov.iov_base = unsafe { (iov.iov_base as *mut u8).add(bytes) }.cast();
            iov.iov_len -= bytes;
            bytes = 0;
        }
    }
}

fn parse_destination_addr(raw: &str) -> Result<Destination> {
    let socket_addr = raw
        .to_socket_addrs()
        .with_context(|| format!("resolve destination {raw}"))?
        .next()
        .ok_or_else(|| anyhow!("destination {raw} resolved to no addresses"))?;
    Ok(Destination {
        ip: socket_addr.ip(),
        port: socket_addr.port(),
    })
}

fn parse_sockaddr(raw: &[u8]) -> Result<Destination> {
    if raw.len() < 2 {
        bail!("sockaddr too short");
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;
    match family {
        libc::AF_INET => parse_sockaddr_in(raw),
        libc::AF_INET6 => parse_sockaddr_in6(raw),
        _ => bail!("unsupported sockaddr family {family}"),
    }
}

fn parse_sockaddr_in(raw: &[u8]) -> Result<Destination> {
    if raw.len() < 8 {
        bail!("sockaddr_in too short");
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    Ok(Destination {
        ip: IpAddr::V4(ip),
        port,
    })
}

fn parse_sockaddr_in6(raw: &[u8]) -> Result<Destination> {
    if raw.len() < 28 {
        bail!("sockaddr_in6 too short");
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&raw[8..24]);
    Ok(Destination {
        ip: IpAddr::V6(Ipv6Addr::from(octets)),
        port,
    })
}

#[derive(Default)]
struct TargetFdFlags {
    status_flags: i32,
    newfd_flags: u32,
}

fn read_target_fd_flags(pid: u32, fd: RawFd) -> TargetFdFlags {
    let mut flags = TargetFdFlags::default();

    if let Ok(duplicated) = duplicate_remote_fd(pid, fd) {
        let rc = unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFL) };
        if rc >= 0 {
            flags.status_flags = rc;
        }
    } else if let Ok(file) = File::open(format!("/proc/{pid}/fd/{fd}")) {
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if rc >= 0 {
            flags.status_flags = rc;
        }
    }

    if let Ok(fdinfo) = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) {
        for line in fdinfo.lines() {
            if let Some(raw) = line.strip_prefix("flags:") {
                if let Ok(parsed) = i32::from_str_radix(raw.trim(), 8) {
                    if parsed & libc::O_CLOEXEC != 0 {
                        flags.newfd_flags |= libc::O_CLOEXEC as u32;
                    }
                }
            }
        }
    }

    flags
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socketpair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

fn recv_listener_fd(sock: RawFd, child_pid: u32) -> io::Result<OwnedFd> {
    let mut raw = [0_u8; std::mem::size_of::<RawFd>()];
    read_exact_fd(sock, &mut raw)?;
    let child_listener_fd = RawFd::from_ne_bytes(raw);
    duplicate_remote_fd(child_pid, child_listener_fd)
}

fn duplicate_remote_fd(pid: u32, fd: RawFd) -> io::Result<OwnedFd> {
    let pidfd = match pidfd_open(pid, libc::PIDFD_THREAD) {
        Ok(pidfd) => pidfd,
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => pidfd_open(pid, 0)?,
        Err(err) => return Err(err),
    };
    let duplicated = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated as RawFd) })
    }
}

fn pidfd_open(pid: u32, flags: libc::c_uint) -> io::Result<OwnedFd> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, flags) };
    if pidfd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) })
    }
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = unsafe { libc::read(fd, buf[offset..].as_mut_ptr().cast(), buf.len() - offset) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        }
        offset += n as usize;
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn encode_os(value: &OsString) -> Result<String> {
    serde_json::to_string(value.as_bytes()).context("encode os string")
}

fn decode_os(raw: &str) -> Result<OsString> {
    let bytes: Vec<u8> = serde_json::from_str(raw).context("decode os string")?;
    Ok(OsString::from_vec(bytes))
}

fn encode_os_list(values: &[OsString]) -> Result<String> {
    let bytes = values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    serde_json::to_string(&bytes).context("encode os string list")
}

fn decode_os_list(raw: &str) -> Result<Vec<OsString>> {
    let bytes: Vec<Vec<u8>> = serde_json::from_str(raw).context("decode os string list")?;
    Ok(bytes.into_iter().map(OsString::from_vec).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr() {
        let raw = [
            libc::AF_INET as u8,
            0,
            0x01,
            0xbb,
            203,
            0,
            113,
            10,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let dest = parse_sockaddr(&raw).unwrap();
        assert_eq!(dest.ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(dest.port, 443);
    }

    #[test]
    fn direct_connect_fast_path_skips_socket_type_when_dns_disabled() {
        let cfg = test_config(false);
        let dest = Destination {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 443,
        };

        assert!(direct_connect_can_continue_before_socket_type(&cfg, dest));
    }

    #[test]
    fn direct_connect_fast_path_preserves_dns_udp_detection() {
        let cfg = test_config(true);
        let dest = Destination {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 53,
        };

        assert!(!direct_connect_can_continue_before_socket_type(&cfg, dest));
    }

    #[test]
    fn os_list_round_trips() {
        let values = vec![
            OsString::from("curl"),
            OsString::from("https://example.com"),
        ];
        let encoded = encode_os_list(&values).unwrap();
        let decoded = decode_os_list(&encoded).unwrap();
        assert_eq!(values, decoded);
    }

    fn test_config(enable_dns: bool) -> EffectiveConfig {
        EffectiveConfig {
            proxy: crate::config::ProxyConfig::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                username: None,
                password: None,
            },
            bypass_local: true,
            bypass_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            enable_dns,
            enable_udp: false,
            dns_server: "1.1.1.1:53".to_string(),
            debug: false,
            command: Vec::new(),
        }
    }
}
