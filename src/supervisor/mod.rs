use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
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
// Upper bound on relay responses buffered ahead of the target's recv. Caps
// memory when the target stops reading and keeps the source queue from growing
// without limit; once full, further responses are dropped rather than enqueued.
const MAX_PENDING_SOURCES: usize = 1_024;
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
    let (blocking_tx, blocking_rx) = mpsc::channel::<SeccompNotif>();
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
                    if !queue_blocking_notification(&blocking_tx, listener_raw_fd, notif, cfg.debug)
                    {
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

fn queue_blocking_notification(
    tx: &mpsc::Sender<SeccompNotif>,
    listener_fd: RawFd,
    notif: SeccompNotif,
    debug: bool,
) -> bool {
    match tx.send(notif) {
        Ok(()) => true,
        Err(mpsc::SendError(notif)) => {
            if debug {
                eprintln!("seccomp-unotify-proxy: blocking recv workers stopped");
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

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    let dest = match parse_sockaddr(&raw) {
        Ok(dest) => dest,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };

    if direct_connect_can_continue_before_socket_type(&cfg, dest) {
        // A direct route normally just continues, but if this fd was already
        // turned into a relay socketpair the AF_UNIX socket cannot accept an
        // AF_INET connect -- route the direct peer through the existing relay
        // instead. A plain fd (including every TCP fd) has no relay entry and
        // falls through to send_continue.
        if direct_connect_through_relay(listener_fd, &notif, &relays, target_fd, dest) {
            return;
        }
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
            if let Some(kind) = udp_route_for(&cfg, dest) {
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
                    Some((dest, kind)),
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

            // Direct-routed UDP connect: reuse an existing relay for this fd if
            // one exists (same AF_UNIX reason as above), else continue.
            if direct_connect_through_relay(listener_fd, &notif, &relays, target_fd, dest) {
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
    let Some(dest) = read_send_destination(notif.pid, addr, addr_len) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    let Some((existing, route)) = resolve_udp_send(&cfg, &relays, notif.pid, target_fd, dest) else {
        // Direct destination on a plain (non-relay) fd: the kernel socket is a
        // real UDP socket, so let the syscall run unmodified.
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if len > MAX_UDP_PAYLOAD {
        seccomp::send_errno(listener_fd, notif.id, libc::EMSGSIZE);
        return;
    }
    let Ok(payload) = read_proc_bytes(notif.pid, buf_ptr, len) else {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    };
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    let handle = match relay_for_send(&cfg, &relays, listener_fd, &notif, target_fd, existing) {
        Some(handle) => handle,
        None => return,
    };
    if handle.send(dest, payload, route).is_ok() {
        seccomp::send_value(listener_fd, notif.id, len as i64);
    } else {
        seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
    }
}

/// Decides how a UDP send to `dest` must be handled.
///
/// A proxied/DNS destination always routes through a relay (created on demand).
/// A direct destination only routes through a relay when the fd has *already*
/// been turned into an AF_UNIX relay socketpair by an earlier proxied send or
/// connect -- that fd can no longer carry an AF_INET sendto, so the relay must
/// perform the direct send. On a plain fd a direct destination returns `None`,
/// telling the caller to let the original syscall run.
fn resolve_udp_send(
    cfg: &EffectiveConfig,
    relays: &UdpRelayRegistry,
    pid: u32,
    fd: RawFd,
    dest: Destination,
) -> Option<(Option<UdpRelayHandle>, UdpRouteKind)> {
    match udp_route_for(cfg, dest) {
        Some(kind) => Some((None, kind)),
        None => relays
            .lookup_handle(pid, fd, true)
            .map(|handle| (Some(handle), UdpRouteKind::Direct)),
    }
}

/// If `fd` already has a relay, records `dest` as the relay's default direct
/// peer and emulates a successful connect (the injected AF_UNIX fd cannot accept
/// an AF_INET connect itself). Returns `true` when it handled the notification.
/// Returns `false` for a plain fd so the caller can continue the syscall.
fn direct_connect_through_relay(
    listener_fd: RawFd,
    notif: &SeccompNotif,
    relays: &UdpRelayRegistry,
    fd: RawFd,
    dest: Destination,
) -> bool {
    let Some(handle) = relays.lookup_handle(notif.pid, fd, true) else {
        return false;
    };
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return true;
    }
    handle.set_default_dest(dest, UdpRouteKind::Direct);
    seccomp::send_success(listener_fd, notif.id);
    true
}

/// Resolves the relay handle a send should use: an already-relay-ized fd reuses
/// its existing handle, otherwise a relay is created (injecting the socketpair).
/// Emits the seccomp error response itself on failure and returns `None`.
fn relay_for_send(
    cfg: &EffectiveConfig,
    relays: &UdpRelayRegistry,
    listener_fd: RawFd,
    notif: &SeccompNotif,
    target_fd: RawFd,
    existing: Option<UdpRelayHandle>,
) -> Option<UdpRelayHandle> {
    if let Some(handle) = existing {
        return Some(handle);
    }
    match relays.ensure(listener_fd, cfg, notif.id, notif.pid, target_fd, None) {
        Ok(handle) => Some(handle),
        Err(err) => {
            if cfg.debug {
                eprintln!("seccomp-unotify-proxy: UDP relay setup failed: {err:#}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            None
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
    let Some((existing, route)) = resolve_udp_send(&cfg, &relays, notif.pid, target_fd, dest) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };

    let iovecs = match read_iovec_targets(notif.pid, msg.iov, msg.iov_len) {
        Ok(iovecs) => iovecs,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    // Match the sendto path: an oversized datagram cannot be sent, so report
    // EMSGSIZE rather than EFAULT (the buffer is valid, just too large).
    let total = match iovec_total_len(&iovecs) {
        Ok(total) => total,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EMSGSIZE);
            return;
        }
    };
    let payload = match read_iovec_payload(notif.pid, &iovecs, total) {
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
    let handle = match relay_for_send(&cfg, &relays, listener_fd, &notif, target_fd, existing) {
        Some(handle) => handle,
        None => return,
    };
    if handle.send(dest, payload, route).is_ok() {
        seccomp::send_value(listener_fd, notif.id, written);
    } else {
        seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
    }
}

fn lookup_relay_for_recv(
    listener_fd: RawFd,
    notif: &SeccompNotif,
    relays: &UdpRelayRegistry,
    target_fd: RawFd,
    flags: i32,
) -> Option<(UdpRelayHandle, OwnedFd)> {
    match relays.lookup(notif.pid, target_fd, false) {
        RelayLookup::Ready(handle, relay_fd) => Some((handle, relay_fd)),
        RelayLookup::Missing => {
            seccomp::send_continue(listener_fd, notif.id);
            None
        }
        RelayLookup::Creating => match recv_request_is_nonblocking(notif.pid, target_fd, flags) {
            Ok(true) => {
                seccomp::send_errno(listener_fd, notif.id, libc::EAGAIN);
                None
            }
            Ok(false) => match relays.lookup(notif.pid, target_fd, true) {
                RelayLookup::Ready(handle, relay_fd) => Some((handle, relay_fd)),
                RelayLookup::Missing => {
                    seccomp::send_continue(listener_fd, notif.id);
                    None
                }
                RelayLookup::Creating => unreachable!("waited lookup cannot return Creating"),
            },
            Err(err) => {
                seccomp::send_errno(listener_fd, notif.id, errno_from_io(&err));
                None
            }
        },
    }
}

fn recv_request_is_nonblocking(pid: u32, fd: RawFd, flags: i32) -> io::Result<bool> {
    if flags & libc::MSG_DONTWAIT != 0 {
        return Ok(true);
    }
    let duplicated = duplicate_remote_fd(pid, fd)?;
    Ok(fd_status_flags(duplicated.as_raw_fd())? & libc::O_NONBLOCK != 0)
}

fn handle_recvfrom(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let target_fd = notif.data.args[0] as RawFd;
    let buf_ptr = notif.data.args[1];
    let len = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;
    let src_addr = notif.data.args[4];
    let addr_len_ptr = notif.data.args[5];

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    let Some((handle, relay_fd)) =
        lookup_relay_for_recv(listener_fd, &notif, &relays, target_fd, flags)
    else {
        return;
    };
    // A single UDP datagram never exceeds MAX_UDP_PAYLOAD, so cap the local
    // receive buffer instead of continuing the syscall on the relay fd: a plain
    // send_continue would bypass source rewrite and leave pending_sources
    // unpopped, desyncing the source queue from the datagram stream (mirrors
    // the recvmsg capacity clamp below).
    let capacity = len.min(MAX_UDP_PAYLOAD);
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
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

    match recv_from_relay_fd(
        listener_fd,
        notif.id,
        relay_fd.as_raw_fd(),
        capacity,
        flags,
        &handle.pending_sources,
    ) {
        Ok(received) => {
            let source = received.source;
            if let Err(err) = write_proc_bytes(notif.pid, buf_ptr, &received.payload) {
                if err.kind() == io::ErrorKind::Interrupted {
                    seccomp::send_errno(listener_fd, notif.id, libc::EINTR);
                } else {
                    seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                }
                return;
            }
            if let Some(addr_len) = addr_len {
                if let Some(source) = source {
                    if write_sockaddr_result(notif.pid, src_addr, addr_len_ptr, addr_len, source)
                        .is_err()
                    {
                        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                        return;
                    }
                }
            }
            seccomp::send_value(listener_fd, notif.id, received.result_len as i64);
        }
        Err(err) => send_recv_error(listener_fd, notif.id, &err),
    }
}

fn handle_recvmsg(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let target_fd = notif.data.args[0] as RawFd;
    let msg_ptr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    let Some((handle, relay_fd)) =
        lookup_relay_for_recv(listener_fd, &notif, &relays, target_fd, flags)
    else {
        return;
    };
    if msg_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
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

    match recv_msg_from_relay_fd(
        listener_fd,
        notif.id,
        relay_fd.as_raw_fd(),
        capacity,
        flags,
        &handle.pending_sources,
    ) {
        Ok(received) => {
            let source = received.source;
            if write_iovec_payload(notif.pid, &iovecs, &received.payload).is_err()
                || write_proc_bytes(notif.pid, msg_ptr + 48, &received.msg_flags.to_ne_bytes())
                    .is_err()
            {
                seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                return;
            }
            if msg.name != 0 {
                if let Some(source) = source {
                    if write_sockaddr_to_msghdr(notif.pid, msg_ptr, msg.name, msg.name_len, source)
                        .is_err()
                    {
                        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                        return;
                    }
                }
            }
            seccomp::send_value(listener_fd, notif.id, received.result_len as i64);
        }
        Err(err) => send_recv_error(listener_fd, notif.id, &err),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRouteKind {
    /// Resolve over the configured DNS-over-TCP proxy path.
    Dns,
    /// Forward through the SOCKS5 UDP association.
    Generic,
    /// Send straight to the destination on a plain UDP socket. Used when an fd
    /// has already been turned into a relay socketpair but the target now sends
    /// to a direct-routed destination: the injected AF_UNIX fd cannot carry an
    /// AF_INET sendto/connect, so the relay must perform the direct send itself.
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RelayKey {
    tgid: u32,
    fd: RawFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FdIdentity {
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// Relay slot state. `Creating` is a single-flight marker published under the
/// lock while a relay's sockets/fd are built outside it; concurrent lookups for
/// the same key wait for it to resolve rather than missing the (still empty)
/// map and continuing a recv on the original fd -- which would then block
/// forever once ADDFD swaps in the relay socket.
enum RelayState {
    Creating,
    Ready(UdpRelayHandle),
}

enum RelayLookup {
    Ready(UdpRelayHandle, OwnedFd),
    Creating,
    Missing,
}

#[derive(Default)]
struct UdpRelayRegistry {
    inner: Mutex<HashMap<RelayKey, RelayState>>,
    created: Condvar,
}

#[derive(Clone)]
struct UdpRelayHandle {
    tx: mpsc::Sender<UdpJob>,
    default_dest: Arc<Mutex<Option<(Destination, UdpRouteKind)>>>,
    pending_sources: Arc<Mutex<VecDeque<Destination>>>,
    relay_fd: Arc<OwnedFd>,
    target_identity: FdIdentity,
    shutdown: Arc<AtomicBool>,
}

struct UdpJob {
    dest: Destination,
    payload: Vec<u8>,
    route: UdpRouteKind,
}

#[derive(Clone)]
struct UdpRelayConfig {
    proxy: crate::config::ProxyConfig,
    dns_server: Destination,
    timeout: Duration,
    debug: bool,
}

fn relay_key(pid: u32, fd: RawFd) -> RelayKey {
    RelayKey {
        tgid: thread_group_id(pid).unwrap_or(pid),
        fd,
    }
}

fn valid_relay_locked(
    relays: &mut HashMap<RelayKey, RelayState>,
    key: RelayKey,
    pid: u32,
    fd: RawFd,
) -> Option<UdpRelayHandle> {
    let handle = match relays.get(&key) {
        Some(RelayState::Ready(handle)) => handle.clone(),
        // A relay under construction has no usable fd yet; callers must wait on
        // the condvar rather than treat this as a hit or a miss.
        Some(RelayState::Creating) | None => return None,
    };
    if handle.target_fd_matches(pid, fd) {
        Some(handle)
    } else {
        if let Some(RelayState::Ready(stale)) = relays.remove(&key) {
            stale.shutdown();
        }
        None
    }
}

fn build_udp_relay_config(cfg: &EffectiveConfig) -> Result<UdpRelayConfig> {
    let dns_server = if cfg.enable_dns {
        parse_destination_addr(&cfg.dns_server).context("parse DNS server")?
    } else {
        Destination {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0,
        }
    };

    Ok(UdpRelayConfig {
        proxy: cfg.proxy.clone(),
        dns_server,
        timeout: cfg.connect_timeout,
        debug: cfg.debug,
    })
}

impl UdpRelayRegistry {
    fn ensure(
        &self,
        listener_fd: RawFd,
        cfg: &EffectiveConfig,
        notif_id: u64,
        pid: u32,
        fd: RawFd,
        default_dest: Option<(Destination, UdpRouteKind)>,
    ) -> Result<UdpRelayHandle> {
        // Fast path: reuse an existing relay. This still validates the target
        // fd identity, but it no longer returns an unused duplicate to ensure().
        if let Some(handle) = self.lookup_handle(pid, fd, true) {
            if let Some((dest, route)) = default_dest {
                handle.set_default_dest(dest, route);
            }
            return Ok(handle);
        }

        let key = relay_key(pid, fd);

        // Claim the key under the lock before building anything. Publishing a
        // Creating marker keeps the expensive setup (datagram socketpair,
        // reading the target fd flags via pidfd + /proc, fstat) outside the lock
        // -- so it never blocks lookups for unrelated keys -- while still making a
        // concurrent lookup for THIS key wait for the relay instead of missing
        // the empty map and continuing its recv on the original fd.
        {
            let mut relays = self.inner.lock().unwrap();
            loop {
                if let Some(handle) = valid_relay_locked(&mut relays, key, pid, fd) {
                    if let Some((dest, route)) = default_dest {
                        handle.set_default_dest(dest, route);
                    }
                    return Ok(handle);
                }
                match relays.get(&key) {
                    // Another thread is building this relay: wait for it to
                    // finish, then re-check (it may have become Ready, failed
                    // and been removed, or turned stale).
                    Some(RelayState::Creating) => {
                        relays = self.created.wait(relays).unwrap();
                    }
                    // Free to claim: publish the marker and build below.
                    _ => {
                        relays.insert(key, RelayState::Creating);
                        break;
                    }
                }
            }
        }

        // We own the Creating marker for `key`. The guard clears it and wakes
        // waiters on every early return (build error, injection failure) so a
        // failed attempt never strands lookups waiting forever.
        let mut guard = CreatingGuard::new(self, key);

        let relay_cfg = build_udp_relay_config(cfg)?;
        let (relay_socket, target_fd) =
            make_relay_pair().context("create UDP relay datagram socketpair")?;
        let target_flags = read_target_fd_flags(pid, fd);
        if target_flags.status_flags & libc::O_NONBLOCK != 0 {
            let _ = set_nonblocking(target_fd.as_raw_fd());
        }
        let target_identity =
            fd_identity(target_fd.as_raw_fd()).context("stat UDP relay target socket")?;

        let mut addfd = SeccompNotifAddfd {
            id: notif_id,
            flags: seccomp::ADDFD_FLAG_SETFD,
            srcfd: target_fd.as_raw_fd() as u32,
            newfd: fd as u32,
            newfd_flags: target_flags.newfd_flags,
        };
        seccomp::notif_addfd(listener_fd, &mut addfd).context("inject UDP relay fd")?;
        drop(target_fd);

        let handle = start_udp_relay(relay_cfg, relay_socket, default_dest, target_identity);
        // Publish the ready relay and hand the marker off to Ready in one
        // critical section so waiters wake to a usable handle.
        guard.commit(RelayState::Ready(handle.clone()));
        Ok(handle)
    }

    /// Fast relay lookup. Probes the map under the lock first, so the common
    /// case -- a recvfrom/recvmsg on a plain fd with no relay -- costs a single
    /// cheap map miss with no fd duplication. Only on a hit is the target fd
    /// duplicated (once, outside the lock) and its identity verified; the
    /// duplicated fd is handed back so the caller can recv on it without
    /// duplicating again. A stale entry (fd reused for a different socket) is
    /// removed, but only if the entry we saw is still the current one, so a
    /// concurrent insert of a fresh relay is never clobbered.
    fn lookup(&self, pid: u32, fd: RawFd, wait_creating: bool) -> RelayLookup {
        let key = relay_key(pid, fd);
        let handle = {
            let mut relays = self.inner.lock().unwrap();
            loop {
                match relays.get(&key) {
                    Some(RelayState::Ready(handle)) => break handle.clone(),
                    // A relay is mid-creation for this key: wait for it rather
                    // than reporting a miss, which would continue this recv on
                    // the original fd and then block forever once the relay
                    // socket is injected.
                    Some(RelayState::Creating) => {
                        if !wait_creating {
                            return RelayLookup::Creating;
                        }
                        relays = self.created.wait(relays).unwrap();
                    }
                    None => return RelayLookup::Missing,
                }
            }
        };
        let duplicated = match handle.duplicate_target_fd(pid, fd) {
            Ok(duplicated) => duplicated,
            Err(_) => {
                self.remove_ready_if_current(key, handle.target_identity);
                return RelayLookup::Missing;
            }
        };
        let identity = match fd_identity(duplicated.as_raw_fd()) {
            Ok(identity) => identity,
            Err(_) => {
                self.remove_ready_if_current(key, handle.target_identity);
                return RelayLookup::Missing;
            }
        };
        if handle.target_identity == identity {
            RelayLookup::Ready(handle, duplicated)
        } else {
            self.remove_ready_if_current(key, handle.target_identity);
            RelayLookup::Missing
        }
    }

    fn lookup_handle(&self, pid: u32, fd: RawFd, wait_creating: bool) -> Option<UdpRelayHandle> {
        let key = relay_key(pid, fd);
        let handle = {
            let mut relays = self.inner.lock().unwrap();
            loop {
                match relays.get(&key) {
                    Some(RelayState::Ready(handle)) => break handle.clone(),
                    Some(RelayState::Creating) => {
                        if !wait_creating {
                            return None;
                        }
                        relays = self.created.wait(relays).unwrap();
                    }
                    None => return None,
                }
            }
        };
        match handle.remote_fd_identity(pid, fd) {
            Ok(identity) if identity == handle.target_identity => Some(handle),
            _ => {
                self.remove_ready_if_current(key, handle.target_identity);
                None
            }
        }
    }

    fn remove_ready_if_current(&self, key: RelayKey, target_identity: FdIdentity) {
        let removed = {
            let mut relays = self.inner.lock().unwrap();
            if matches!(relays.get(&key), Some(RelayState::Ready(current)) if current.target_identity == target_identity)
            {
                relays.remove(&key)
            } else {
                None
            }
        };
        if let Some(RelayState::Ready(handle)) = removed {
            handle.shutdown();
        }
    }
}

/// Owns the single-flight `Creating` marker for one relay key. On drop it clears
/// the marker (unless committed) and always wakes threads waiting in `lookup`/
/// `ensure`, so a failed creation attempt can never strand a waiter.
struct CreatingGuard<'a> {
    registry: &'a UdpRelayRegistry,
    key: RelayKey,
    committed: bool,
}

impl<'a> CreatingGuard<'a> {
    fn new(registry: &'a UdpRelayRegistry, key: RelayKey) -> Self {
        CreatingGuard {
            registry,
            key,
            committed: false,
        }
    }

    fn commit(&mut self, state: RelayState) {
        let mut relays = self.registry.inner.lock().unwrap();
        relays.insert(self.key, state);
        self.committed = true;
        drop(relays);
        self.registry.created.notify_all();
    }
}

impl Drop for CreatingGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let mut relays = self.registry.inner.lock().unwrap();
            // Only remove our own Creating marker; never clobber a Ready relay
            // (there is none we own) or another thread's later claim.
            if matches!(relays.get(&self.key), Some(RelayState::Creating)) {
                relays.remove(&self.key);
            }
            drop(relays);
            self.registry.created.notify_all();
        }
    }
}

impl UdpRelayHandle {
    fn set_default_dest(&self, dest: Destination, route: UdpRouteKind) {
        *self.default_dest.lock().unwrap() = Some((dest, route));
    }

    fn send(&self, dest: Destination, payload: Vec<u8>, route: UdpRouteKind) -> Result<()> {
        self.tx
            .send(UdpJob {
                dest,
                payload,
                route,
            })
            .map_err(|_| anyhow!("UDP relay worker exited"))
    }

    /// Duplicates the target fd from the *currently notifying* thread rather than
    /// a cached thread-group-leader pidfd. The leader can exit (becoming a zombie
    /// with no accessible fd table) while worker threads keep using the relay, and
    /// a thread may not share the leader's fd table at all; the notifying thread is
    /// guaranteed alive for the duration of the seccomp stop, so its fd table is the
    /// reliable source for the duplicate.
    fn duplicate_target_fd(&self, pid: u32, fd: RawFd) -> io::Result<OwnedFd> {
        duplicate_remote_fd(pid, fd)
    }

    fn remote_fd_identity(&self, pid: u32, fd: RawFd) -> io::Result<FdIdentity> {
        let duplicated = self.duplicate_target_fd(pid, fd)?;
        fd_identity(duplicated.as_raw_fd())
    }

    fn target_fd_matches(&self, pid: u32, fd: RawFd) -> bool {
        matches!(self.remote_fd_identity(pid, fd), Ok(identity) if identity == self.target_identity)
    }

    fn shutdown(&self) {
        if !self.shutdown.swap(true, Ordering::SeqCst) {
            let _ = unsafe { libc::shutdown(self.relay_fd.as_raw_fd(), libc::SHUT_RDWR) };
        }
    }
}

fn start_udp_relay(
    cfg: UdpRelayConfig,
    relay_socket: OwnedFd,
    default_dest: Option<(Destination, UdpRouteKind)>,
    target_identity: FdIdentity,
) -> UdpRelayHandle {
    let relay_fd = Arc::new(relay_socket);
    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<UdpJob>();
    let default_dest = Arc::new(Mutex::new(default_dest));
    let pending_sources = Arc::new(Mutex::new(VecDeque::new()));

    let read_fd = Arc::clone(&relay_fd);
    let read_tx = tx.clone();
    let read_default_dest = Arc::clone(&default_dest);
    let read_shutdown = Arc::clone(&shutdown);
    thread::spawn(move || {
        let mut buf = vec![0_u8; MAX_UDP_PAYLOAD];
        loop {
            let n = match recv_relay_socket(read_fd.as_raw_fd(), &mut buf) {
                Ok(n) => n,
                // A signal can interrupt the blocking recv; retry rather than
                // terminating the reader, which would silently break the
                // connected-UDP return path (target recvfrom would hang).
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if read_shutdown.load(Ordering::SeqCst) {
                break;
            }
            let Some((dest, route)) = *read_default_dest.lock().unwrap() else {
                continue;
            };
            let payload = buf[..n].to_vec();
            if read_tx
                .send(UdpJob {
                    dest,
                    payload,
                    route,
                })
                .is_err()
            {
                break;
            }
        }
    });

    let write_pending_sources = Arc::clone(&pending_sources);
    let write_fd = Arc::clone(&relay_fd);
    let write_shutdown = Arc::clone(&shutdown);
    thread::spawn(move || {
        let mut socks_udp = None;
        let mut direct_udp = None;
        for job in rx {
            if write_shutdown.load(Ordering::SeqCst) {
                break;
            }
            let source = job.dest;
            match forward_udp_job(&cfg, &mut socks_udp, &mut direct_udp, job) {
                Ok(Some(response)) => {
                    let mut pending = write_pending_sources.lock().unwrap();
                    // Drop the response if the target is not draining fast
                    // enough. The socketpair send below uses MSG_DONTWAIT, so a
                    // successful send means the datagram is actually queued.
                    if pending.len() >= MAX_PENDING_SOURCES {
                        if cfg.debug {
                            eprintln!(
                                "seccomp-unotify-proxy: UDP relay pending queue full, dropping response"
                            );
                        }
                        continue;
                    }
                    pending.push_back(source);
                    if !send_relay_response(write_fd.as_raw_fd(), &response) {
                        let _ = pending.pop_back();
                        if write_shutdown.load(Ordering::SeqCst) {
                            break;
                        }
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
        relay_fd,
        target_identity,
        shutdown,
    }
}

fn recv_relay_socket(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let rc = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// Sends the relay response back to the target without blocking. AF_UNIX
/// datagram socketpairs report a full peer queue as EAGAIN instead of silently
/// dropping the packet, so a successful send keeps pending_sources synchronized
/// with the queued datagram stream.
fn send_relay_response(fd: RawFd, response: &[u8]) -> bool {
    loop {
        let rc = unsafe {
            libc::send(
                fd,
                response.as_ptr().cast(),
                response.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if rc >= 0 {
            return rc as usize == response.len();
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return false;
    }
}

fn forward_udp_job(
    cfg: &UdpRelayConfig,
    socks_udp: &mut Option<proxy::Socks5UdpAssociation>,
    direct_udp: &mut Option<UdpSocket>,
    job: UdpJob,
) -> Result<Option<Vec<u8>>> {
    // The route was decided by the notification handler, which has the full
    // routing table. Honour it verbatim so a datagram bound for a direct route
    // is never accidentally tunnelled through the proxy (and vice versa).
    match job.route {
        UdpRouteKind::Dns => {
            proxy::dns_over_tcp(&cfg.proxy, cfg.dns_server, &job.payload, cfg.timeout).map(Some)
        }
        UdpRouteKind::Generic => {
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
        UdpRouteKind::Direct => forward_direct_udp(direct_udp, job.dest, &job.payload, cfg.timeout),
    }
}

/// Sends a datagram straight to its destination on a plain UDP socket, reusing a
/// cached socket across jobs and rebinding only when the address family changes.
/// Mirrors the single request/response model of the proxy paths: one datagram is
/// read back (within the timeout) so the connected-UDP return path stays fed.
fn forward_direct_udp(
    direct_udp: &mut Option<UdpSocket>,
    dest: Destination,
    payload: &[u8],
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    let family_matches = direct_udp
        .as_ref()
        .and_then(|sock| sock.local_addr().ok())
        .map(|addr| addr.is_ipv4() == dest.ip.is_ipv4())
        .unwrap_or(false);
    if !family_matches {
        let bind = if dest.ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        *direct_udp = Some(sock);
    }
    let sock = direct_udp
        .as_ref()
        .expect("direct UDP socket initialized above");
    sock.send_to(payload, SocketAddr::new(dest.ip, dest.port))?;

    let mut buf = vec![0_u8; MAX_UDP_PAYLOAD];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock
                || err.kind() == io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(err) => Err(err.into()),
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

fn make_relay_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }
}

fn read_send_destination(pid: u32, addr: u64, addr_len: usize) -> Option<Destination> {
    let raw_addr = read_sockaddr(pid, addr, addr_len).ok()?;
    parse_sockaddr(&raw_addr).ok()
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

#[derive(Clone, Copy)]
struct TargetIovec {
    base: u64,
    len: usize,
}

struct RelayRecvmsg {
    payload: Vec<u8>,
    result_len: usize,
    msg_flags: i32,
    source: Option<Destination>,
}

struct RelayRecvfrom {
    payload: Vec<u8>,
    result_len: usize,
    source: Option<Destination>,
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

fn recv_from_relay_fd(
    listener_fd: RawFd,
    notif_id: u64,
    relay_fd: RawFd,
    capacity: usize,
    flags: i32,
    pending: &Mutex<VecDeque<Destination>>,
) -> io::Result<RelayRecvfrom> {
    let nonblocking = recv_is_nonblocking(relay_fd, flags);
    let mut payload = vec![0_u8; capacity];
    loop {
        if !nonblocking && !seccomp::notif_id_valid(listener_fd, notif_id) {
            return Err(notification_interrupted());
        }
        let (result, source) = claim_datagram(pending, flags, || unsafe {
            libc::recv(
                relay_fd,
                payload.as_mut_ptr().cast(),
                payload.len(),
                flags | libc::MSG_DONTWAIT,
            )
        });
        match result {
            Ok(rc) => {
                let result_len = rc as usize;
                payload.truncate(result_len.min(payload.len()));
                return Ok(RelayRecvfrom {
                    payload,
                    result_len,
                    source,
                });
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if err.kind() == io::ErrorKind::WouldBlock && !nonblocking {
                    wait_for_relay_readable(listener_fd, notif_id, relay_fd)?;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

/// Runs `recv` while holding the pending-sources lock, and on success claims
/// the matching source in the same critical section. This keeps the datagram
/// and its source address bound together: without it, two threads receiving
/// concurrently on a shared (unconnected) relay could pop sources in a
/// different order than they received datagrams. errno is captured inside the
/// lock, before any other syscall can clobber it.
fn claim_datagram(
    pending: &Mutex<VecDeque<Destination>>,
    flags: i32,
    recv: impl FnOnce() -> libc::ssize_t,
) -> (io::Result<libc::ssize_t>, Option<Destination>) {
    let mut pending = pending.lock().unwrap();
    let rc = recv();
    if rc < 0 {
        return (Err(io::Error::last_os_error()), None);
    }
    let source = if flags & libc::MSG_PEEK != 0 {
        pending.front().copied()
    } else {
        pending.pop_front()
    };
    (Ok(rc), source)
}

fn recv_msg_from_relay_fd(
    listener_fd: RawFd,
    notif_id: u64,
    relay_fd: RawFd,
    capacity: usize,
    flags: i32,
    pending: &Mutex<VecDeque<Destination>>,
) -> io::Result<RelayRecvmsg> {
    let nonblocking = recv_is_nonblocking(relay_fd, flags);
    let mut payload = vec![0_u8; capacity];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    loop {
        if !nonblocking && !seccomp::notif_id_valid(listener_fd, notif_id) {
            return Err(notification_interrupted());
        }
        let (result, source) = claim_datagram(pending, flags, || unsafe {
            libc::recvmsg(relay_fd, &mut msg, flags | libc::MSG_DONTWAIT)
        });
        match result {
            Ok(rc) => {
                let copied_len = (rc as usize).min(payload.len());
                payload.truncate(copied_len);
                return Ok(RelayRecvmsg {
                    payload,
                    result_len: rc as usize,
                    msg_flags: msg.msg_flags,
                    source,
                });
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if err.kind() == io::ErrorKind::WouldBlock && !nonblocking {
                    wait_for_relay_readable(listener_fd, notif_id, relay_fd)?;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

fn recv_is_nonblocking(fd: RawFd, flags: i32) -> bool {
    flags & libc::MSG_DONTWAIT != 0
        || fd_status_flags(fd)
            .map(|status_flags| status_flags & libc::O_NONBLOCK != 0)
            .unwrap_or(false)
}

fn wait_for_relay_readable(listener_fd: RawFd, notif_id: u64, fd: RawFd) -> io::Result<()> {
    const POLL_INTERVAL_MS: libc::c_int = 100;

    loop {
        if !seccomp::notif_id_valid(listener_fd, notif_id) {
            return Err(notification_interrupted());
        }

        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, POLL_INTERVAL_MS) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            continue;
        }
        // Data takes priority: if the socket is readable, let the caller's
        // recv consume it even when an error/hangup is also reported.
        if pollfd.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if pollfd.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // POLLERR/POLLHUP without POLLIN: returning Ok would make recv report
        // EAGAIN (MSG_DONTWAIT) and spin us straight back into poll. Surface
        // the socket error instead so the caller can fail the syscall.
        if pollfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            let err =
                socket_error(fd).unwrap_or_else(|| io::Error::from_raw_os_error(libc::ECONNRESET));
            return Err(err);
        }
        return Ok(());
    }
}

fn socket_error(fd: RawFd) -> Option<io::Error> {
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&err) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == 0 && err != 0 {
        Some(io::Error::from_raw_os_error(err))
    } else {
        None
    }
}

fn notification_interrupted() -> io::Error {
    io::Error::from_raw_os_error(libc::EINTR)
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

fn send_recv_error(listener_fd: RawFd, notif_id: u64, err: &io::Error) {
    if err.kind() == io::ErrorKind::Interrupted && !seccomp::notif_id_valid(listener_fd, notif_id) {
        return;
    }
    seccomp::send_errno(listener_fd, notif_id, errno_from_io(err));
}

fn socket_type(pid: u32, fd: RawFd) -> Option<i32> {
    let file = duplicate_remote_fd(pid, fd).ok()?;
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

fn fd_identity(fd: RawFd) -> io::Result<FdIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut stat) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(FdIdentity {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

fn fd_status_flags(fd: RawFd) -> io::Result<i32> {
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
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

fn thread_group_id(pid: u32) -> io::Result<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(raw) = line.strip_prefix("Tgid:") {
            return raw
                .trim()
                .parse()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing Tgid in proc status",
    ))
}

fn read_sockaddr(pid: u32, addr: u64, addr_len: usize) -> io::Result<Vec<u8>> {
    let family_len = addr_len.min(2);
    let family_raw = read_proc_bytes(pid, addr, family_len)?;
    if family_raw.len() < 2 {
        return Ok(family_raw);
    }

    let family = u16::from_ne_bytes([family_raw[0], family_raw[1]]) as i32;
    let needed_len = match family {
        libc::AF_INET => 8,
        libc::AF_INET6 => 28,
        _ => return Ok(family_raw),
    };
    read_proc_bytes(pid, addr, addr_len.min(needed_len).min(128))
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
        if let Ok(status_flags) = fd_status_flags(duplicated.as_raw_fd()) {
            flags.status_flags = status_flags;
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
    duplicate_remote_fd_from_pidfd(pidfd.as_raw_fd(), fd)
}

fn duplicate_remote_fd_from_pidfd(pidfd: RawFd, fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) };
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
    fn reads_only_sockaddr_family_for_unsupported_family() {
        let raw = (libc::AF_UNIX as u16).to_ne_bytes();
        let got = read_sockaddr(std::process::id(), raw.as_ptr() as u64, 128).unwrap();

        assert_eq!(got, raw);
    }

    #[test]
    fn relay_key_uses_thread_group_id() {
        let key = relay_key(std::process::id(), 9);

        assert_eq!(key.tgid, std::process::id());
        assert_eq!(key.fd, 9);
    }

    #[test]
    fn relay_lookup_reports_creating_without_waiting() {
        let registry = UdpRelayRegistry::default();
        let key = relay_key(std::process::id(), 9);
        registry
            .inner
            .lock()
            .unwrap()
            .insert(key, RelayState::Creating);

        assert!(matches!(
            registry.lookup(std::process::id(), 9, false),
            RelayLookup::Creating
        ));
    }

    #[test]
    fn relay_lookup_removes_stale_entry_when_dup_fails() {
        let registry = UdpRelayRegistry::default();
        let key = relay_key(std::process::id(), -1);
        let handle = test_relay_handle();
        registry
            .inner
            .lock()
            .unwrap()
            .insert(key, RelayState::Ready(handle.clone()));

        assert!(matches!(
            registry.lookup(std::process::id(), -1, false),
            RelayLookup::Missing
        ));
        assert!(!registry.inner.lock().unwrap().contains_key(&key));
        assert!(handle.shutdown.load(Ordering::SeqCst));
    }

    #[test]
    fn relay_socketpair_send_reports_full_queue() {
        let (relay, target) = make_relay_pair().unwrap();
        let rcvbuf: libc::c_int = 4096;
        let rc = unsafe {
            libc::setsockopt(
                target.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&rcvbuf as *const libc::c_int).cast(),
                std::mem::size_of_val(&rcvbuf) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);

        let payload = vec![1_u8; 1400];
        let mut sent = 0;
        for _ in 0..10_000 {
            if !send_relay_response(relay.as_raw_fd(), &payload) {
                break;
            }
            sent += 1;
        }
        assert!(sent > 0);
        assert!(sent < 10_000);

        let mut received = 0;
        let mut buf = vec![0_u8; 2048];
        loop {
            let rc = unsafe {
                libc::recv(
                    target.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                panic!("recv failed: {err}");
            }
            received += 1;
        }

        assert_eq!(received, sent);
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

    fn test_relay_handle() -> UdpRelayHandle {
        let (relay, target) = make_relay_pair().unwrap();
        let (tx, _rx) = mpsc::channel();
        UdpRelayHandle {
            tx,
            default_dest: Arc::new(Mutex::new(None)),
            pending_sources: Arc::new(Mutex::new(VecDeque::new())),
            relay_fd: Arc::new(relay),
            target_identity: fd_identity(target.as_raw_fd()).unwrap(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
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
