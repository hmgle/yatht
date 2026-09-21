use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use crossbeam_channel as channel;

use crate::config::{EffectiveConfig, Route, UdpSocketMode};
use crate::observability::{Observability, ObservabilityRuntime, TcpSetupTrace};
use crate::proxy;
use crate::proxy::warm::{
    ProxySessionSource, WarmCompletionError, WarmSessionPool, WARM_POOL_MAX_SESSIONS,
};
use crate::seccomp::{self, SeccompNotif, SeccompNotifAddfd};
use crate::tcp_broker::TcpBroker;

mod child;
mod connect;
mod dispatch;
mod proc_mem;
mod relay;
mod udp_recv;
mod udp_send;

pub use child::run_child_stage;
use child::*;
use connect::*;
use dispatch::*;
use proc_mem::*;
use relay::*;
use udp_recv::*;
use udp_send::*;

#[cfg(test)]
mod tests;

const CHILD_STAGE_ENV: &str = "SUP_CHILD_STAGE";
const TARGET_PATH_ENV: &str = "SUP_TARGET_PATH";
const TARGET_ARGV_ENV: &str = "SUP_TARGET_ARGV";
const TRAP_SET_ENV: &str = "SUP_TRAP_SET";
const CONTROL_FD: RawFd = 3;
// The largest datagram `udp_sendmsg` accepts before any destination verdict:
// one byte less than the UDP length field's capacity.
const MAX_UDP_PAYLOAD: usize = 65_535;
// Once a destination is known the IP layer refuses a datagram that cannot
// fit its header budget: 0xFFFF minus the UDP header, and minus the IPv4
// header too on the IPv4 path. The ceiling follows the *transmission* family
// of the destination, not the socket family — a dual-stack AF_INET6 socket
// sends a v4-mapped destination through the IPv4 path.
const MAX_IPV4_UDP_PAYLOAD: usize = 65_507;
const MAX_IPV6_UDP_PAYLOAD: usize = 65_527;

fn max_udp_payload_for(dest: Destination) -> usize {
    match dest.ip {
        IpAddr::V4(_) => MAX_IPV4_UDP_PAYLOAD,
        // A v4-mapped destination leaves the IPv6 socket but still takes
        // the IPv4 transmission path, so it inherits the IPv4 ceiling.
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => MAX_IPV4_UDP_PAYLOAD,
        IpAddr::V6(_) => MAX_IPV6_UDP_PAYLOAD,
    }
}

const SOCKADDR_IN_SIZE: usize = 16;
const SOCKADDR_IN6_MIN_SIZE: usize = 24;
const SOCKADDR_IN6_SIZE: usize = 28;
// Upper bound on relay responses buffered ahead of the target's recv. Caps
// memory when the target stops reading and keeps the source queue from growing
// without limit; once full, further responses are dropped rather than enqueued.
const MAX_PENDING_SOURCES: usize = 1_024;
const MAX_UDP_RELAYS: usize = 128;
const STABLE_RELAY_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
// `/proc/net/unix` is host-wide, so re-reading it costs work proportional to
// the machine rather than to the relays this supervisor owns. Sweeps that
// reclaim nothing back off geometrically once the grace window passes; a
// reclaim or a newly published relay restores the base cadence.
const STABLE_RELAY_SWEEP_MAX_INTERVAL: Duration = Duration::from_secs(30);
const STABLE_RELAY_SWEEP_IDLE_GRACE: u32 = 5;
// Reclaiming a relay is never latency critical, so the sweep yields to the
// notification workers and the receive reactor on a busy host.
const STABLE_RELAY_REAPER_NICE: libc::c_int = 5;
// Admission only waits when the relay budget is exhausted, so a short retry
// tolerates procfs lagging a concurrent close without slowing normal creation.
const STABLE_RELAY_REAP_ATTEMPTS: u32 = 3;
const STABLE_RELAY_REAP_INTERVAL: Duration = Duration::from_millis(1);
const UDP_RELAY_THREAD_STACK_SIZE: usize = 512 * 1_024;
const MAX_NOTIFICATION_WORKERS: usize = 64;
const NOTIFICATION_QUEUE_PER_WORKER: usize = 16;
const UDP_JOB_QUEUE_CAPACITY: usize = 16;
const THREAD_PIDFD_CACHE_MAX_ENTRIES: usize = 256;
const BLOCKING_RECV_POLL_INTERVAL_MS: libc::c_int = 100;
const BLOCKING_RECV_CHANNEL_BUDGET: usize = 64;
const LOCAL_BROKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const TARGET_TERMINATION_TIMEOUT: Duration = Duration::from_secs(1);
const TARGET_TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(1);
// After the target exits, adopted descendants may still be draining; the
// monitor polls for them this often only during that tail window.
const DESCENDANT_REAP_POLL_INTERVAL_MS: libc::c_int = 10;

struct NotificationFailure {
    reported: AtomicBool,
    shutting_down: AtomicBool,
    /// Write end of the failure pipe; the monitor waits on its read end, so
    /// reporting both wakes the monitor and carries the message.
    report_fd: OwnedFd,
}

struct BlockingRecvQueue {
    tx: channel::Sender<BlockingRecvNotification>,
    wake_fd: Arc<OwnedFd>,
}

#[derive(Clone, Copy)]
struct BlockingRecvNotification {
    notif: SeccompNotif,
    received_at: Instant,
}

struct QueuedNotification {
    notif: SeccompNotif,
    received_at: Instant,
    observability: Observability,
}

struct PendingBlockingRecv {
    notif: SeccompNotif,
    relay_fd: OwnedFd,
    relay: FdIdentity,
    state: BlockingRecvState,
}

#[derive(Clone, Copy)]
struct BlockingRecvWork {
    notif: SeccompNotif,
    relay: Option<FdIdentity>,
    terminal_revents: libc::c_short,
    state: BlockingRecvState,
}

#[derive(Clone, Copy, Default)]
struct BlockingRecvState {
    completed: usize,
    timeout_initialized: bool,
    deadline: Option<Instant>,
    rcvtimeo: Option<Duration>,
    rcvtimeo_deadline: Option<Instant>,
    // Set when the notification enters the supervisor queue; direct handler
    // calls leave it unset and use their dispatch time instead.
    received_at: Option<Instant>,
}

impl BlockingRecvState {
    /// Earliest pending timer. The explicit recvmmsg timespec and the socket
    /// `SO_RCVTIMEO` keep distinct expiry results, but the reactor only needs
    /// the next wake-up instant.
    fn next_deadline(&self) -> Option<Instant> {
        match (self.deadline, self.rcvtimeo_deadline) {
            (Some(explicit), Some(rcvtimeo)) => Some(explicit.min(rcvtimeo)),
            (explicit, rcvtimeo) => explicit.or(rcvtimeo),
        }
    }

    fn arm_rcvtimeo(&mut self, relay_fd: RawFd) {
        self.rcvtimeo = socket_recv_timeout(relay_fd);
        let start = self.received_at.unwrap_or_else(Instant::now);
        self.set_rcvtimeo_deadline(start);
    }

    /// Restarts the `SO_RCVTIMEO` window. The kernel bounds each blocking
    /// wait with the socket timeout, so batched receives re-arm it after
    /// every delivered datagram (anchored by the direct-kernel baseline
    /// probe); an `Instant` overflow degrades to an unbounded wait.
    fn reset_rcvtimeo_deadline(&mut self) {
        self.set_rcvtimeo_deadline(Instant::now());
    }

    fn set_rcvtimeo_deadline(&mut self, start: Instant) {
        self.rcvtimeo_deadline = self.rcvtimeo.and_then(|timeout| start.checked_add(timeout));
    }
}

struct BlockingRecvCompletion {
    work: BlockingRecvWork,
    handling: RecvHandling,
}

struct TargetGuard {
    child: Child,
    armed: bool,
}

enum RecvHandling {
    Completed,
    Deferred {
        relay_fd: OwnedFd,
        relay: FdIdentity,
        state: BlockingRecvState,
    },
}

impl NotificationFailure {
    fn report(&self, context: &str, err: io::Error) {
        if self.reported.swap(true, Ordering::AcqRel) {
            return;
        }
        // The pipe is empty until this first and only report, so a single
        // write carries the whole message without blocking.
        let message = format!("{context}: {err}");
        let _ = unsafe {
            libc::write(
                self.report_fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
            )
        };
    }
}

impl TargetGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut target_status = None;
        let _ = terminate_target_tree(&mut self.child, &mut target_status);
    }
}

// The seccomp filter kills non-x86_64 ABIs, so target userspace structs are the
// x86_64 Linux layouts regardless of the supervisor's Rust struct padding.
const X86_64_IOVEC_SIZE: usize = 16;
const X86_64_MSGHDR_SIZE: usize = 56;
const X86_64_MSGHDR_NAME_LEN_OFFSET: usize = 8;
const X86_64_MSGHDR_IOV_OFFSET: usize = 16;
const X86_64_MSGHDR_IOV_LEN_OFFSET: usize = 24;
const X86_64_MSGHDR_FLAGS_OFFSET: u64 = 48;
const X86_64_MMSGHDR_SIZE: usize = 64;
const X86_64_MMSGHDR_LEN_OFFSET: u64 = 56;
const X86_64_TIMESPEC_SIZE: usize = 16;
/// The kernel's `UIO_MAXIOV`: an iovec array may hold at most this many
/// segments (more is an error from `iovec_from_user`), while a `sendmmsg` or
/// `recvmmsg` batch length above it is silently clamped, not rejected.
const UIO_MAXIOV: usize = 1024;
const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const CLOSE_RANGE_KNOWN_FLAGS: u32 = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;

const _: () = assert!(std::mem::size_of::<libc::iovec>() == X86_64_IOVEC_SIZE);
const _: () = assert!(std::mem::size_of::<libc::msghdr>() == X86_64_MSGHDR_SIZE);
const _: () = assert!(std::mem::size_of::<libc::mmsghdr>() == X86_64_MMSGHDR_SIZE);

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

pub fn verify_pidfd_thread_support() -> io::Result<()> {
    pidfd_open(std::process::id(), libc::PIDFD_THREAD).map(drop)
}

pub fn run(cfg: EffectiveConfig) -> Result<i32> {
    if cfg.command.is_empty() {
        bail!("missing command");
    }

    let observability_runtime = ObservabilityRuntime::start(cfg.metrics_file.as_deref())?;
    let observability = observability_runtime.observability();
    let result = run_with_observability(cfg, observability.clone());
    let finish_result = observability_runtime.finish();
    match (result, finish_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err).context("finish performance metrics"),
        (Err(err), Err(metrics_err)) => Err(err).context(format!(
            "also failed to finish performance metrics: {metrics_err:#}"
        )),
    }
}

fn run_with_observability(cfg: EffectiveConfig, observability: Observability) -> Result<i32> {
    let target_path = resolve_target(&cfg.command[0])?;
    set_child_subreaper().context("become child subreaper")?;
    let argv = cfg.command.clone();
    let (parent_sock, child_sock) = socketpair().context("create control socketpair")?;
    let trap_set = if cfg.enable_udp && cfg.udp_socket_mode == UdpSocketMode::Stable {
        seccomp::TrapSet::with_udp()
    } else if cfg.enable_dns || cfg.enable_udp {
        seccomp::TrapSet::with_dns()
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

    let mut target = TargetGuard::new(command.spawn().context("spawn child stage")?);
    close_fd(child_sock);

    let listener_fd = match recv_listener_fd(parent_sock, target.child.id()) {
        Ok(fd) => fd,
        Err(err) => {
            close_fd(parent_sock);
            return Err(err).context("duplicate seccomp listener fd");
        }
    };
    let worker_count = notification_worker_count();
    let session_source = match proxy::warm::proxy_session_source_from_env() {
        Ok(source) => source,
        Err(err) => {
            close_fd(parent_sock);
            return Err(err).context("select proxy session source");
        }
    };
    // Warm pool fds are long-lived and outside per-flow accounting, so they
    // must come out of the broker's reserved headroom.
    let warm_reserved_fds = if session_source == ProxySessionSource::WarmOneShot {
        WARM_POOL_MAX_SESSIONS
    } else {
        0
    };
    let (tcp_broker, tcp_broker_reactor) =
        match TcpBroker::new(observability.clone(), worker_count, warm_reserved_fds) {
            Ok(broker) => broker,
            Err(err) => {
                close_fd(parent_sock);
                return Err(err).context("create TCP broker");
            }
        };
    let warm_pool = if session_source == ProxySessionSource::WarmOneShot {
        match WarmSessionPool::start(cfg.proxy.clone(), cfg.connect_timeout) {
            Ok(pool) => Some(Arc::new(pool)),
            Err(err) => {
                close_fd(parent_sock);
                return Err(err).context("start warm proxy session pool");
            }
        }
    } else {
        None
    };
    observability.record_proxy_session_source(session_source == ProxySessionSource::WarmOneShot);
    if let Err(err) = write_all_fd(parent_sock, b"G") {
        close_fd(parent_sock);
        return Err(err).context("ack child stage");
    }
    close_fd(parent_sock);

    let cfg = Arc::new(cfg);
    let relays = Arc::new(UdpRelayRegistry::with_observability(observability.clone()));
    let listener_fd = Arc::new(listener_fd);
    let (failure_rd, failure_wr) = create_failure_pipe().context("create failure pipe")?;
    let failure = Arc::new(NotificationFailure {
        reported: AtomicBool::new(false),
        shutting_down: AtomicBool::new(false),
        report_fd: failure_wr,
    });
    let reactor_failure = Arc::clone(&failure);
    let panic_failure = Arc::clone(&failure);
    let reactor_thread =
        thread::spawn(
            move || match std::panic::catch_unwind(|| tcp_broker_reactor.run()) {
                Ok(Ok(())) => {
                    if !reactor_failure.shutting_down.load(Ordering::Acquire) {
                        reactor_failure.report(
                            "TCP broker reactor stopped",
                            io::Error::new(io::ErrorKind::BrokenPipe, "TCP broker channel closed"),
                        );
                    }
                }
                Ok(Err(err)) => reactor_failure.report("TCP broker reactor failed", err),
                Err(_) => panic_failure.report(
                    "TCP broker reactor panicked",
                    io::Error::other("TCP broker reactor panicked"),
                ),
            },
        );
    let loop_cfg = Arc::clone(&cfg);
    let loop_relays = Arc::clone(&relays);
    let loop_failure = Arc::clone(&failure);
    let loop_state = Arc::clone(&failure);
    let loop_observability = observability.clone();
    let worker_tcp_broker = tcp_broker.clone();
    let loop_warm_pool = warm_pool.clone();
    let notification_thread = thread::spawn(move || {
        if std::panic::catch_unwind(|| {
            notification_loop(
                listener_fd,
                loop_cfg,
                loop_relays,
                worker_tcp_broker,
                loop_warm_pool,
                loop_state,
                loop_observability,
                worker_count,
            )
        })
        .is_err()
        {
            loop_failure.report(
                "seccomp notification loop panicked",
                io::Error::other("notification loop panicked"),
            );
        }
    });

    let monitor_result = monitor_target_tree(target.child_mut(), failure_rd.as_raw_fd(), &failure);
    failure.shutting_down.store(true, Ordering::Release);
    if let Err(monitor_err) = &monitor_result {
        // The notification loop only drains once every seccomp filter user is
        // gone; kill the tree before the joins below so a monitor failure with
        // a live target cannot hang them. If bounded cleanup fails, do not enter
        // an unbounded join while a target may still hold the filter.
        let mut target_status = None;
        if let Err(cleanup_err) = terminate_target_tree(target.child_mut(), &mut target_status) {
            eprintln!(
                "yatht: {monitor_err:#}; also failed to terminate target tree: {cleanup_err}"
            );
            std::process::exit(1);
        }
    }
    let notification_join_result = notification_thread
        .join()
        .map_err(|_| anyhow!("seccomp notification thread panicked"));
    // Workers are joined, so no lease can race the pool teardown.
    if let Some(pool) = &warm_pool {
        pool.shutdown();
        let stats = pool.snapshot();
        observability.record_warm_pool_stats(
            stats.hits,
            stats.misses,
            stats.stale,
            stats.expired,
            stats.replenish_failures,
            stats.pool_size_peak,
        );
    }
    let shutdown_result = tcp_broker.shutdown();
    let reactor_join_result = reactor_thread
        .join()
        .map_err(|_| anyhow!("TCP broker reactor thread panicked"));
    let status = monitor_result?;
    notification_join_result?;
    reactor_join_result?;
    shutdown_result.context("shut down TCP broker reactor")?;
    if let Some(message) = take_failure_message(failure_rd.as_raw_fd(), 0) {
        bail!("seccomp notification handling failed during shutdown: {message}");
    }
    target.disarm();
    if let Some(code) = status.code() {
        Ok(code)
    } else if let Some(signal) = status.signal() {
        Ok(128 + signal)
    } else {
        Ok(1)
    }
}

fn monitor_target_tree(
    child: &mut Child,
    failure_pipe: RawFd,
    failure: &NotificationFailure,
) -> Result<ExitStatus> {
    let pidfd = pidfd_open(child.id(), 0).context("open target pidfd")?;
    let pidfd_raw = pidfd.as_raw_fd();
    let mut target_status = None;
    // While the child lives, block on its pidfd and the failure pipe: an
    // idle supervisor wakes for neither instead of polling on a timer.
    while target_status.is_none() {
        if let Some(message) = take_failure_message(failure_pipe, 0) {
            terminate_target_tree(child, &mut target_status)
                .context("terminate target after notification failure")?;
            bail!("seccomp notification handling failed: {message}");
        }
        poll_readable(&[pidfd_raw, failure_pipe], -1)?;
        if let Some(message) = take_failure_message(failure_pipe, 0) {
            terminate_target_tree(child, &mut target_status)
                .context("terminate target after notification failure")?;
            bail!("seccomp notification handling failed: {message}");
        }
        if poll_readable(&[pidfd_raw], 0)? != 0 {
            target_status = child.try_wait().context("wait for target")?;
        }
    }
    let status = target_status.expect("target exited once the pidfd signaled");
    // The child is gone but adopted descendants may still be draining. Keep
    // the short poll only for this tail, which normally lasts milliseconds.
    loop {
        if let Some(message) = take_failure_message(failure_pipe, 0) {
            terminate_target_tree(child, &mut target_status)
                .context("terminate target after notification failure")?;
            bail!("seccomp notification handling failed: {message}");
        }
        if !reap_descendants_nonblocking()? {
            failure.shutting_down.store(true, Ordering::Release);
            if let Some(message) = take_failure_message(failure_pipe, 0) {
                bail!("seccomp notification handling failed: {message}");
            }
            return Ok(status);
        }
        let _ = poll_readable(&[failure_pipe], DESCENDANT_REAP_POLL_INTERVAL_MS);
    }
}

/// Creates the nonblocking, close-on-exec pipe that carries the one-shot
/// notification-failure message from worker threads to the target monitor.
fn create_failure_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 filled both descriptors on success.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}

/// Waits until one of `fds` is readable (or hangup/error) and returns the
/// ready descriptors as a bitmask, bit `i` for `fds[i]`. A timeout of -1
/// blocks indefinitely.
fn poll_readable(fds: &[RawFd], timeout_ms: libc::c_int) -> io::Result<u32> {
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    loop {
        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if rc >= 0 {
            let mut ready = 0;
            for (index, pollfd) in pollfds.iter().enumerate() {
                if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    ready |= 1 << index;
                }
            }
            return Ok(ready);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Reads a pending failure message from the pipe without blocking longer
/// than `timeout_ms`. `None` when nothing was reported in that window.
fn take_failure_message(fd: RawFd, timeout_ms: libc::c_int) -> Option<String> {
    if poll_readable(&[fd], timeout_ms).ok()? == 0 {
        return None;
    }
    let mut message = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n > 0 {
            message.extend_from_slice(&chunk[..n as usize]);
            continue;
        }
        if n == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    if message.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&message).into_owned())
}

fn terminate_target_tree(
    child: &mut Child,
    target_status: &mut Option<ExitStatus>,
) -> io::Result<()> {
    terminate_target_tree_until(
        child,
        target_status,
        Instant::now() + TARGET_TERMINATION_TIMEOUT,
    )
}

fn terminate_target_tree_until(
    child: &mut Child,
    target_status: &mut Option<ExitStatus>,
    deadline: Instant,
) -> io::Result<()> {
    if target_status.is_none() {
        if let Some(status) = child.try_wait()? {
            *target_status = Some(status);
        } else {
            let _ = child.kill();
            *target_status = Some(wait_for_target_exit(child, deadline)?);
        }
    }
    terminate_adopted_descendants_until(deadline)
}

#[cfg(test)]
fn terminate_adopted_descendants() -> io::Result<()> {
    terminate_adopted_descendants_until(Instant::now() + TARGET_TERMINATION_TIMEOUT)
}

fn terminate_adopted_descendants_until(deadline: Instant) -> io::Result<()> {
    loop {
        if !reap_descendants_nonblocking()? {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(termination_timeout("adopted descendants"));
        }

        for pid in direct_child_pids(std::process::id())? {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
        sleep_until_next_termination_poll(deadline);
    }
}

fn wait_for_target_exit(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
    poll_until_termination(deadline, || child.try_wait(), "target process")
}

fn poll_until_termination<T>(
    deadline: Instant,
    mut poll: impl FnMut() -> io::Result<Option<T>>,
    subject: &str,
) -> io::Result<T> {
    loop {
        if let Some(value) = poll()? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(termination_timeout(subject));
        }
        sleep_until_next_termination_poll(deadline);
    }
}

fn sleep_until_next_termination_poll(deadline: Instant) {
    let now = Instant::now();
    if now >= deadline {
        return;
    }
    thread::sleep(TARGET_TERMINATION_POLL_INTERVAL.min(deadline.duration_since(now)));
}

fn termination_timeout(subject: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out terminating {subject}"),
    )
}

fn reap_descendants_nonblocking() -> io::Result<bool> {
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if rc > 0 {
            continue;
        }
        if rc == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(false);
        }
        return Err(err);
    }
}

fn direct_child_pids(parent_pid: u32) -> io::Result<Vec<u32>> {
    let mut children = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(err) => return Err(err),
        };
        let is_child = status.lines().any(|line| {
            line.strip_prefix("PPid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
                == Some(parent_pid)
        });
        if is_child {
            children.push(pid);
        }
    }
    Ok(children)
}

impl Drop for RelaySlotGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.release_relay_slot();
        }
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
