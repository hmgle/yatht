//! One-shot warm proxy session pool (TCP_BROKER_ROADMAP.md M4A, RESEARCH 3.5).
//!
//! A warm session is a proxy connection driven through TCP connect and, for
//! SOCKS5, method negotiation and authentication -- everything up to but not
//! including the tunnel request. Leasing hands the connection to a setup
//! worker, which finishes the tunnel with the shared request helpers in the
//! parent module. Sessions are strictly one-shot: a leased connection never
//! returns to the pool, and a session that entered the tunnel state is never
//! reused. The pool is keyed implicitly: one supervisor run has exactly one
//! proxy endpoint and auth identity and no runtime config reload, so a single
//! pool covers the (endpoint, family, auth identity) key space.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};

use crate::config::ProxyConfig;
use crate::supervisor::Destination;

use super::{
    clear_handshake_timeouts, http_connect_frame, http_connect_read_reply, parse_socks5_auth_reply,
    parse_socks5_method_reply, read_socks5_reply_addr, socks5_auth_frame,
    socks5_connect_request_frame, socks5_greeting_frame, DialTimings, SOCKS5_METHOD_USER_PASS,
};

// Internal selector for the proxy session source; cold (dial per flow) stays
// the default and warm-one-shot is opt-in experimental. This dimension is
// orthogonal to the application socket contract and the stable data mover
// (TCP_BROKER_ROADMAP.md section 9) and must not be merged with them.
const PROXY_SESSION_ENV: &str = "SUP_TCP_PROXY_SESSION";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxySessionSource {
    Cold,
    WarmOneShot,
}

pub fn proxy_session_source_from_env() -> io::Result<ProxySessionSource> {
    match std::env::var(PROXY_SESSION_ENV) {
        Ok(value) => parse_proxy_session_source(&value),
        Err(std::env::VarError::NotPresent) => Ok(ProxySessionSource::Cold),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {PROXY_SESSION_ENV} value: {err}"),
        )),
    }
}

fn parse_proxy_session_source(value: &str) -> io::Result<ProxySessionSource> {
    match value {
        "cold" => Ok(ProxySessionSource::Cold),
        "warm-one-shot" => Ok(ProxySessionSource::WarmOneShot),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {PROXY_SESSION_ENV} value: {value}"),
        )),
    }
}

// Pre-registered bounds (roadmap M4A). The pool starts empty and only
// replenishes after observed demand, so idle supervisors hold zero warm fds.
//
// Sixteen sessions cost at most 16 fds, well inside the broker's policy
// headroom (>= 256 fds), while covering the short-connection bursts the
// request scenarios model; larger bursts simply fall back to cold dials.
pub const WARM_POOL_MAX_SESSIONS: usize = 16;
// Kept below common proxy idle timeouts so the pool retires sessions before
// the proxy does; the lease-time liveness check catches the remainder.
const WARM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Caps concurrent prewarm attempts so a slow proxy cannot pile up half-open
// connections; combined with the per-attempt deadline this bounds in-flight
// fd usage.
const MAX_INFLIGHT_WARMUPS: usize = 4;
// Replenish failures back off exponentially so a dead proxy costs a bounded
// connect rate instead of a busy loop.
const REPLENISH_BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const REPLENISH_BACKOFF_MAX: Duration = Duration::from_secs(5);
// Lease demand is measured over a sliding two-bucket window; the target pool
// size follows the busier bucket so bursts warm up quickly and quiet periods
// drain the pool back to zero.
const DEMAND_WINDOW: Duration = Duration::from_secs(10);
// Upper bound on one replenisher poll round; expiry sweeps and deadline
// checks run at least this often even without wakeups.
const REPLENISHER_TICK: Duration = Duration::from_millis(500);

#[derive(Default)]
struct WarmPoolStats {
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    expired: AtomicU64,
    replenish_failures: AtomicU64,
    pool_size_peak: AtomicU64,
}

// The snapshot is consumed by unit tests now and by the metrics run summary
// once schema v6 lands; the binary target alone does not read it yet.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WarmPoolSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub stale: u64,
    pub expired: u64,
    pub replenish_failures: u64,
    pub pool_size_peak: u64,
}

struct DemandWindow {
    bucket_started: Instant,
    current: usize,
    previous: usize,
}

impl DemandWindow {
    fn new(now: Instant) -> Self {
        Self {
            bucket_started: now,
            current: 0,
            previous: 0,
        }
    }

    fn roll(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.bucket_started);
        if elapsed >= DEMAND_WINDOW + DEMAND_WINDOW {
            self.previous = 0;
            self.current = 0;
            self.bucket_started = now;
        } else if elapsed >= DEMAND_WINDOW {
            self.previous = self.current;
            self.current = 0;
            self.bucket_started += DEMAND_WINDOW;
        }
    }

    fn record(&mut self, now: Instant) {
        self.roll(now);
        self.current = self.current.saturating_add(1);
    }

    fn target(&mut self, now: Instant) -> usize {
        self.roll(now);
        self.current.max(self.previous).min(WARM_POOL_MAX_SESSIONS)
    }
}

struct WarmSession {
    stream: TcpStream,
    warmed_at: Instant,
}

struct PoolInner {
    proxy: ProxyConfig,
    attempt_timeout: Duration,
    idle_timeout: Duration,
    idle: Mutex<VecDeque<WarmSession>>,
    demand: Mutex<DemandWindow>,
    wake_fd: OwnedFd,
    shutting_down: AtomicBool,
    stats: WarmPoolStats,
}

pub struct WarmSessionPool {
    inner: Arc<PoolInner>,
    replenisher: Mutex<Option<thread::JoinHandle<()>>>,
}

impl WarmSessionPool {
    pub fn start(proxy: ProxyConfig, attempt_timeout: Duration) -> io::Result<Self> {
        Self::start_with_idle_timeout(proxy, attempt_timeout, WARM_IDLE_TIMEOUT)
    }

    fn start_with_idle_timeout(
        proxy: ProxyConfig,
        attempt_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let inner = Arc::new(PoolInner {
            proxy,
            attempt_timeout,
            idle_timeout,
            idle: Mutex::new(VecDeque::new()),
            demand: Mutex::new(DemandWindow::new(Instant::now())),
            wake_fd: create_eventfd()?,
            shutting_down: AtomicBool::new(false),
            stats: WarmPoolStats::default(),
        });
        let thread_inner = Arc::clone(&inner);
        let handle = thread::Builder::new()
            .name("warm-session-pool".into())
            .spawn(move || replenisher_loop(thread_inner))?;
        Ok(Self {
            inner,
            replenisher: Mutex::new(Some(handle)),
        })
    }

    /// Takes one warm session, or `None` on a miss; the caller falls back to
    /// the cold dial path. Every call records demand and wakes the
    /// replenisher, so misses drive future prewarming.
    pub fn lease(&self) -> Option<TcpStream> {
        let now = Instant::now();
        self.inner
            .demand
            .lock()
            .expect("warm pool demand lock poisoned")
            .record(now);
        wake_eventfd(self.inner.wake_fd.as_raw_fd());
        if self.inner.shutting_down.load(Ordering::Acquire) {
            self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        loop {
            let session = self
                .inner
                .idle
                .lock()
                .expect("warm pool idle lock poisoned")
                .pop_front();
            let Some(session) = session else {
                self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if now.saturating_duration_since(session.warmed_at) > self.inner.idle_timeout {
                self.inner.stats.expired.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if !session_is_live(&session.stream) || session.stream.set_nonblocking(false).is_err() {
                self.inner.stats.stale.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.inner.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(session.stream);
        }
    }

    // Consumed by unit tests now and by the metrics run summary once schema
    // v6 lands; the binary target alone does not read it yet.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> WarmPoolSnapshot {
        let stats = &self.inner.stats;
        WarmPoolSnapshot {
            hits: stats.hits.load(Ordering::Relaxed),
            misses: stats.misses.load(Ordering::Relaxed),
            stale: stats.stale.load(Ordering::Relaxed),
            expired: stats.expired.load(Ordering::Relaxed),
            replenish_failures: stats.replenish_failures.load(Ordering::Relaxed),
            pool_size_peak: stats.pool_size_peak.load(Ordering::Relaxed),
        }
    }

    /// Stops the replenisher and closes every idle session. Idempotent; the
    /// pool must never extend supervisor lifetime, so `Drop` also calls this.
    pub fn shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
        wake_eventfd(self.inner.wake_fd.as_raw_fd());
        let handle = self
            .replenisher
            .lock()
            .expect("warm pool replenisher lock poisoned")
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.inner
            .idle
            .lock()
            .expect("warm pool idle lock poisoned")
            .clear();
    }
}

impl Drop for WarmSessionPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A warm session must be silent until the tunnel request: any readable
/// byte, hangup, or pending socket error disqualifies it.
fn session_is_live(stream: &TcpStream) -> bool {
    let mut pollfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pollfd` is a valid, exclusively borrowed pollfd for the call.
    let rc = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if rc != 0 {
        return false;
    }
    matches!(stream.take_error(), Ok(None))
}

/// Failure mode of completing a tunnel on a leased warm session.
///
/// `NothingSent` proves no request byte was handed to the kernel, so the
/// proxy cannot have observed a request and a cold retry is safe. Any other
/// failure must not be retried on another connection (RESEARCH 3.5).
pub enum WarmCompletionError {
    NothingSent(anyhow::Error),
    Fatal(anyhow::Error),
}

impl WarmCompletionError {
    pub fn into_error(self) -> anyhow::Error {
        match self {
            Self::NothingSent(err) | Self::Fatal(err) => err,
        }
    }
}

/// Finishes the tunnel on a leased warm session: sends the CONNECT request
/// and consumes the proxy reply. The stream is blocking; `timeout` is the
/// remainder of the flow's original connect deadline. `timings.connect`
/// stays `None` because no proxy TCP connect happened on this flow.
pub fn complete_warm_lease(
    proxy: &ProxyConfig,
    mut stream: TcpStream,
    dest: Destination,
    timeout: Duration,
    timings: &mut DialTimings,
) -> std::result::Result<TcpStream, WarmCompletionError> {
    let handshake_started = Instant::now();
    let result = (|| {
        stream
            .set_read_timeout(Some(timeout))
            .context("set warm session read timeout")
            .map_err(WarmCompletionError::Fatal)?;
        stream
            .set_write_timeout(Some(timeout))
            .context("set warm session write timeout")
            .map_err(WarmCompletionError::Fatal)?;
        let frame = match proxy {
            ProxyConfig::Socks5 { .. } => socks5_connect_request_frame(dest),
            ProxyConfig::Http { .. } => http_connect_frame(dest).into_bytes(),
        };
        write_all_tracked(&mut stream, &frame)?;
        match proxy {
            ProxyConfig::Socks5 { .. } => {
                let _ = read_socks5_reply_addr(&mut stream).map_err(WarmCompletionError::Fatal)?;
            }
            ProxyConfig::Http { .. } => {
                http_connect_read_reply(&mut stream).map_err(WarmCompletionError::Fatal)?;
            }
        }
        clear_handshake_timeouts(&stream)
            .context("clear warm session handshake timeouts")
            .map_err(WarmCompletionError::Fatal)?;
        Ok(())
    })();
    timings.handshake = Some(handshake_started.elapsed());
    result.map(|()| stream)
}

fn write_all_tracked(
    stream: &mut TcpStream,
    frame: &[u8],
) -> std::result::Result<(), WarmCompletionError> {
    let mut sent = 0;
    while sent < frame.len() {
        match stream.write(&frame[sent..]) {
            Ok(0) => {
                let err = anyhow!("warm proxy session accepted no request bytes");
                return Err(if sent == 0 {
                    WarmCompletionError::NothingSent(err)
                } else {
                    WarmCompletionError::Fatal(err)
                });
            }
            Ok(n) => sent += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                let err =
                    anyhow::Error::new(err).context("send tunnel request on warm proxy session");
                return Err(if sent == 0 {
                    WarmCompletionError::NothingSent(err)
                } else {
                    WarmCompletionError::Fatal(err)
                });
            }
        }
    }
    Ok(())
}

// ---- Replenisher: nonblocking prewarm state machine ----

#[derive(Clone, Copy)]
enum ReplyKind {
    Method,
    Auth,
}

enum WarmupPhase {
    Connecting,
    Sending {
        frame: Vec<u8>,
        sent: usize,
        reply: ReplyKind,
    },
    Reading {
        kind: ReplyKind,
        buf: [u8; 2],
        filled: usize,
    },
}

enum StepOutcome {
    Pending,
    Ready,
    // The payload documents each failure cause at its construction site;
    // failures surface to callers only as the replenish-failure counter.
    Failed(#[allow(dead_code)] io::Error),
}

struct Warmup {
    stream: TcpStream,
    phase: WarmupPhase,
    deadline: Instant,
    auth: Option<(String, String)>,
}

impl Warmup {
    fn start(proxy: &ProxyConfig, attempt_timeout: Duration) -> io::Result<Self> {
        let (endpoint, auth) = match proxy {
            ProxyConfig::Socks5 {
                addr,
                username,
                password,
            } => {
                let auth = if username.is_some() || password.is_some() {
                    Some((
                        username.clone().unwrap_or_default(),
                        password.clone().unwrap_or_default(),
                    ))
                } else {
                    None
                };
                (addr, auth)
            }
            ProxyConfig::Http { addr } => (addr, None),
        };
        let addr = resolve_first(endpoint)?;
        let stream = nonblocking_connect(addr)?;
        Ok(Self {
            stream,
            phase: WarmupPhase::Connecting,
            deadline: Instant::now() + attempt_timeout,
            auth,
        })
    }

    fn interest(&self) -> libc::c_short {
        match self.phase {
            WarmupPhase::Connecting | WarmupPhase::Sending { .. } => libc::POLLOUT,
            WarmupPhase::Reading { .. } => libc::POLLIN,
        }
    }

    fn step(&mut self, proxy: &ProxyConfig) -> StepOutcome {
        if Instant::now() >= self.deadline {
            return StepOutcome::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "warm session attempt deadline exceeded",
            ));
        }
        loop {
            match &mut self.phase {
                WarmupPhase::Connecting => {
                    match self.stream.take_error() {
                        Ok(None) => {}
                        Ok(Some(err)) | Err(err) => return StepOutcome::Failed(err),
                    }
                    match self.stream.peer_addr() {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                            return StepOutcome::Pending;
                        }
                        Err(err) => return StepOutcome::Failed(err),
                    }
                    match proxy {
                        // A warm HTTP proxy session is only a TCP connection.
                        ProxyConfig::Http { .. } => return StepOutcome::Ready,
                        ProxyConfig::Socks5 { .. } => {
                            self.phase = WarmupPhase::Sending {
                                frame: socks5_greeting_frame(self.auth.is_some()).to_vec(),
                                sent: 0,
                                reply: ReplyKind::Method,
                            };
                        }
                    }
                }
                WarmupPhase::Sending { frame, sent, reply } => {
                    match self.stream.write(&frame[*sent..]) {
                        Ok(0) => {
                            return StepOutcome::Failed(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "proxy accepted no handshake bytes",
                            ));
                        }
                        Ok(n) => *sent += n,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            return StepOutcome::Pending;
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => return StepOutcome::Failed(err),
                    }
                    if *sent == frame.len() {
                        self.phase = WarmupPhase::Reading {
                            kind: *reply,
                            buf: [0; 2],
                            filled: 0,
                        };
                    }
                }
                WarmupPhase::Reading { kind, buf, filled } => {
                    match self.stream.read(&mut buf[*filled..]) {
                        Ok(0) => {
                            return StepOutcome::Failed(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "proxy closed during warm handshake",
                            ));
                        }
                        Ok(n) => *filled += n,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            return StepOutcome::Pending;
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => return StepOutcome::Failed(err),
                    }
                    if *filled < buf.len() {
                        continue;
                    }
                    let reply = *buf;
                    match kind {
                        ReplyKind::Method => {
                            let method = match parse_socks5_method_reply(reply) {
                                Ok(method) => method,
                                Err(err) => return StepOutcome::Failed(io::Error::other(err)),
                            };
                            if method != SOCKS5_METHOD_USER_PASS {
                                return StepOutcome::Ready;
                            }
                            let Some((username, password)) = self.auth.as_ref() else {
                                return StepOutcome::Failed(io::Error::other(
                                    "proxy demanded auth without configured credentials",
                                ));
                            };
                            let frame = match socks5_auth_frame(username, password) {
                                Ok(frame) => frame,
                                Err(err) => return StepOutcome::Failed(io::Error::other(err)),
                            };
                            self.phase = WarmupPhase::Sending {
                                frame,
                                sent: 0,
                                reply: ReplyKind::Auth,
                            };
                        }
                        ReplyKind::Auth => {
                            return match parse_socks5_auth_reply(reply) {
                                Ok(()) => StepOutcome::Ready,
                                Err(err) => StepOutcome::Failed(io::Error::other(err)),
                            };
                        }
                    }
                }
            }
        }
    }
}

struct ReplenishBackoff {
    until: Option<Instant>,
    delay: Duration,
}

impl ReplenishBackoff {
    fn new() -> Self {
        Self {
            until: None,
            delay: REPLENISH_BACKOFF_INITIAL,
        }
    }

    fn ready(&self, now: Instant) -> bool {
        self.until.is_none_or(|until| now >= until)
    }

    fn trip(&mut self, now: Instant) {
        self.until = Some(now + self.delay);
        self.delay = (self.delay * 2).min(REPLENISH_BACKOFF_MAX);
    }

    fn reset(&mut self) {
        self.until = None;
        self.delay = REPLENISH_BACKOFF_INITIAL;
    }
}

fn replenisher_loop(inner: Arc<PoolInner>) {
    let mut inflight: Vec<Warmup> = Vec::new();
    let mut backoff = ReplenishBackoff::new();
    while !inner.shutting_down.load(Ordering::Acquire) {
        let now = Instant::now();
        sweep_expired_idle(&inner, now);

        let target = inner
            .demand
            .lock()
            .expect("warm pool demand lock poisoned")
            .target(now);
        let idle_len = inner
            .idle
            .lock()
            .expect("warm pool idle lock poisoned")
            .len();
        while inflight.len() < MAX_INFLIGHT_WARMUPS
            && idle_len + inflight.len() < target
            && backoff.ready(now)
        {
            match Warmup::start(&inner.proxy, inner.attempt_timeout) {
                Ok(warmup) => inflight.push(warmup),
                Err(_) => {
                    inner
                        .stats
                        .replenish_failures
                        .fetch_add(1, Ordering::Relaxed);
                    backoff.trip(now);
                    break;
                }
            }
        }

        let mut pollfds = Vec::with_capacity(1 + inflight.len());
        pollfds.push(libc::pollfd {
            fd: inner.wake_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        for warmup in &inflight {
            pollfds.push(libc::pollfd {
                fd: warmup.stream.as_raw_fd(),
                events: warmup.interest(),
                revents: 0,
            });
        }
        let timeout_ms = REPLENISHER_TICK.as_millis() as libc::c_int;
        // SAFETY: `pollfds` is a valid, exclusively borrowed pollfd slice for
        // the duration of the call.
        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                // A persistently failing poll leaves only the tick cadence;
                // sleep so the loop cannot spin hot.
                thread::sleep(REPLENISHER_TICK);
            }
            continue;
        }
        if pollfds[0].revents != 0 {
            let _ = drain_eventfd(inner.wake_fd.as_raw_fd());
        }

        let step_now = Instant::now();
        // Reverse iteration keeps pollfds[1 + index] aligned with inflight:
        // swap_remove moves an already-visited tail element into the hole.
        for index in (0..inflight.len()).rev() {
            let signaled = pollfds[1 + index].revents != 0;
            let expired = step_now >= inflight[index].deadline;
            if !signaled && !expired {
                continue;
            }
            match inflight[index].step(&inner.proxy) {
                StepOutcome::Pending => {}
                StepOutcome::Ready => {
                    let warmup = inflight.swap_remove(index);
                    let mut idle = inner.idle.lock().expect("warm pool idle lock poisoned");
                    idle.push_back(WarmSession {
                        stream: warmup.stream,
                        warmed_at: Instant::now(),
                    });
                    let size = idle.len() as u64;
                    drop(idle);
                    inner
                        .stats
                        .pool_size_peak
                        .fetch_max(size, Ordering::Relaxed);
                    backoff.reset();
                }
                StepOutcome::Failed(_) => {
                    inflight.swap_remove(index);
                    inner
                        .stats
                        .replenish_failures
                        .fetch_add(1, Ordering::Relaxed);
                    backoff.trip(Instant::now());
                }
            }
        }
    }
    // In-flight warmups drop here, closing their sockets; the shutdown call
    // drains the idle deque after joining this thread.
}

fn sweep_expired_idle(inner: &PoolInner, now: Instant) {
    let mut idle = inner.idle.lock().expect("warm pool idle lock poisoned");
    let before = idle.len();
    idle.retain(|session| now.saturating_duration_since(session.warmed_at) <= inner.idle_timeout);
    let dropped = (before - idle.len()) as u64;
    drop(idle);
    if dropped > 0 {
        inner.stats.expired.fetch_add(dropped, Ordering::Relaxed);
    }
}

fn resolve_first(endpoint: &str) -> io::Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    endpoint.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "proxy endpoint resolved to no addresses",
        )
    })
}

fn nonblocking_connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain socket creation; the raw fd is immediately wrapped in an
    // owning TcpStream so every early return closes it.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created, owned socket fd.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let (raw, len) = sockaddr_bytes(addr);
    // SAFETY: `raw` holds a valid sockaddr of `len` bytes for the call.
    let rc = unsafe { libc::connect(fd, raw.as_ptr().cast(), len as libc::socklen_t) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
    }
    Ok(stream)
}

fn sockaddr_bytes(addr: SocketAddr) -> ([u8; 28], usize) {
    let mut raw = [0_u8; 28];
    match addr {
        SocketAddr::V4(v4) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v4.port().to_be_bytes());
            raw[4..8].copy_from_slice(&v4.ip().octets());
            (raw, 16)
        }
        SocketAddr::V6(v6) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v6.port().to_be_bytes());
            raw[8..24].copy_from_slice(&v6.ip().octets());
            (raw, 28)
        }
    }
}

fn create_eventfd() -> io::Result<OwnedFd> {
    // SAFETY: plain eventfd creation; ownership transfers to OwnedFd.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a freshly created, owned eventfd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn wake_eventfd(fd: RawFd) {
    let value = 1_u64;
    // SAFETY: writes a u64 from a valid local to an owned eventfd.
    let rc = unsafe {
        libc::write(
            fd,
            (&value as *const u64).cast(),
            std::mem::size_of_val(&value),
        )
    };
    // A failed or saturated write is harmless: the replenisher also wakes on
    // its bounded tick.
    let _ = rc;
}

fn drain_eventfd(fd: RawFd) -> io::Result<()> {
    let mut value = 0_u64;
    loop {
        // SAFETY: reads a u64 into a valid local from an owned eventfd.
        let rc = unsafe {
            libc::read(
                fd,
                (&mut value as *mut u64).cast(),
                std::mem::size_of_val(&value),
            )
        };
        if rc >= 0 {
            continue;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(err);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener};
    use std::sync::mpsc;

    use super::*;

    const TEST_DEST: Destination = Destination {
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        port: 443,
    };

    fn socks5_config(addr: &SocketAddr, auth: bool) -> ProxyConfig {
        ProxyConfig::Socks5 {
            addr: addr.to_string(),
            username: auth.then(|| "user".to_string()),
            password: auth.then(|| "pass".to_string()),
        }
    }

    fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let started = Instant::now();
        while started.elapsed() < limit {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// Accepts up to `accepts` connections, performs the SOCKS5 greeting
    /// (and auth when configured), and hands the server side back.
    fn spawn_socks5_greeter(
        listener: TcpListener,
        accepts: usize,
        auth: bool,
    ) -> mpsc::Receiver<TcpStream> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..accepts {
                let Ok((mut conn, _)) = listener.accept() else {
                    return;
                };
                conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut greeting = [0_u8; 3];
                conn.read_exact(&mut greeting).unwrap();
                if auth {
                    assert_eq!(greeting, [5, 1, 2]);
                    conn.write_all(&[5, 2]).unwrap();
                    let mut head = [0_u8; 2];
                    conn.read_exact(&mut head).unwrap();
                    assert_eq!(head[0], 1);
                    let mut user = vec![0_u8; head[1] as usize];
                    conn.read_exact(&mut user).unwrap();
                    let mut pass_len = [0_u8; 1];
                    conn.read_exact(&mut pass_len).unwrap();
                    let mut pass = vec![0_u8; pass_len[0] as usize];
                    conn.read_exact(&mut pass).unwrap();
                    assert_eq!(user, b"user");
                    assert_eq!(pass, b"pass");
                    conn.write_all(&[1, 0]).unwrap();
                } else {
                    assert_eq!(greeting, [5, 1, 0]);
                    conn.write_all(&[5, 0]).unwrap();
                }
                if tx.send(conn).is_err() {
                    return;
                }
            }
        });
        rx
    }

    /// Records one miss to create demand, waits for the replenisher to warm
    /// a session, then leases it. Avoids repeated miss-leases so exactly one
    /// warm connection exists when the lease happens.
    fn lease_first_warm_session(pool: &WarmSessionPool) -> Option<TcpStream> {
        assert!(pool.lease().is_none(), "pool must start empty");
        assert!(wait_until(Duration::from_secs(3), || {
            pool.snapshot().pool_size_peak >= 1
        }));
        pool.lease()
    }

    #[test]
    fn parses_session_source_values() {
        assert_eq!(
            parse_proxy_session_source("cold").unwrap(),
            ProxySessionSource::Cold
        );
        assert_eq!(
            parse_proxy_session_source("warm-one-shot").unwrap(),
            ProxySessionSource::WarmOneShot
        );
        assert!(parse_proxy_session_source("warm").is_err());
        assert!(parse_proxy_session_source("").is_err());
    }

    #[test]
    fn demand_window_follows_recent_leases_and_caps_target() {
        let t0 = Instant::now();
        let mut window = DemandWindow::new(t0);
        for _ in 0..3 {
            window.record(t0);
        }
        assert_eq!(window.target(t0), 3);
        // The previous bucket keeps the target while the current one restarts.
        assert_eq!(window.target(t0 + DEMAND_WINDOW), 3);
        // Two idle windows drain the target back to zero.
        assert_eq!(window.target(t0 + DEMAND_WINDOW * 2), 0);
        for _ in 0..(WARM_POOL_MAX_SESSIONS + 8) {
            window.record(t0 + DEMAND_WINDOW * 2);
        }
        assert_eq!(
            window.target(t0 + DEMAND_WINDOW * 2),
            WARM_POOL_MAX_SESSIONS
        );
    }

    #[test]
    fn prewarms_after_demand_and_completes_leased_socks5_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_socks5_greeter(listener, 4, false);
        let pool =
            WarmSessionPool::start(socks5_config(&addr, false), Duration::from_secs(2)).unwrap();

        // The pool starts empty: the first lease is a recorded miss.
        let leased = lease_first_warm_session(&pool).expect("warm session after demand");

        let mut server_conn = server.recv_timeout(Duration::from_secs(2)).unwrap();
        let responder = thread::spawn(move || {
            let mut request = [0_u8; 10];
            server_conn.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            assert_eq!(&request[4..8], &[203, 0, 113, 1]);
            server_conn
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .unwrap();
            server_conn.write_all(b"ok").unwrap();
        });

        let mut timings = DialTimings::default();
        let mut stream = complete_warm_lease(
            &socks5_config(&addr, false),
            leased,
            TEST_DEST,
            Duration::from_secs(2),
            &mut timings,
        )
        .unwrap_or_else(|err| panic!("warm completion failed: {:#}", err.into_error()));
        assert!(timings.connect.is_none());
        assert!(timings.handshake.is_some());
        let mut payload = [0_u8; 2];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ok");
        responder.join().unwrap();

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.hits, 1);
        assert!(snapshot.misses >= 1);
        assert!(snapshot.pool_size_peak >= 1);
        pool.shutdown();
    }

    #[test]
    fn prewarms_authenticated_socks5_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_socks5_greeter(listener, 4, true);
        let pool =
            WarmSessionPool::start(socks5_config(&addr, true), Duration::from_secs(2)).unwrap();

        let leased = lease_first_warm_session(&pool).expect("warm authenticated session");
        drop(server.recv_timeout(Duration::from_secs(2)).unwrap());
        drop(leased);
        assert_eq!(pool.snapshot().hits, 1);
        pool.shutdown();
    }

    #[test]
    fn prewarms_http_session_as_plain_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = WarmSessionPool::start(
            ProxyConfig::Http {
                addr: addr.to_string(),
            },
            Duration::from_secs(2),
        )
        .unwrap();

        let leased = lease_first_warm_session(&pool).expect("warm HTTP session");
        let (mut server_conn, _) = listener.accept().unwrap();
        let responder = thread::spawn(move || {
            let mut buf = Vec::new();
            let mut byte = [0_u8; 1];
            server_conn
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            while !buf.ends_with(b"\r\n\r\n") {
                server_conn.read_exact(&mut byte).unwrap();
                buf.push(byte[0]);
            }
            let header = String::from_utf8(buf).unwrap();
            assert!(header.starts_with("CONNECT 203.0.113.1:443 HTTP/1.1\r\n"));
            server_conn
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
        });

        let mut timings = DialTimings::default();
        let stream = complete_warm_lease(
            &ProxyConfig::Http {
                addr: addr.to_string(),
            },
            leased,
            TEST_DEST,
            Duration::from_secs(2),
            &mut timings,
        )
        .unwrap_or_else(|err| panic!("warm HTTP completion failed: {:#}", err.into_error()));
        assert!(timings.connect.is_none());
        responder.join().unwrap();
        drop(stream);
        pool.shutdown();
    }

    #[test]
    fn lease_rejects_peer_closed_session_as_stale() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_socks5_greeter(listener, 1, false);
        let pool =
            WarmSessionPool::start(socks5_config(&addr, false), Duration::from_secs(2)).unwrap();

        assert!(pool.lease().is_none());
        assert!(wait_until(Duration::from_secs(3), || {
            pool.snapshot().pool_size_peak >= 1
        }));
        // Closing the server side makes the pooled session readable at EOF,
        // which the lease-time liveness check must reject.
        drop(server.recv_timeout(Duration::from_secs(2)).unwrap());
        assert!(wait_until(Duration::from_secs(3), || {
            pool.lease().is_none() && pool.snapshot().stale >= 1
        }));
        assert_eq!(pool.snapshot().hits, 0);
        pool.shutdown();
    }

    #[test]
    fn lease_rejects_idle_expired_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_socks5_greeter(listener, 1, false);
        let pool = WarmSessionPool::start_with_idle_timeout(
            socks5_config(&addr, false),
            Duration::from_secs(2),
            Duration::from_millis(50),
        )
        .unwrap();

        assert!(pool.lease().is_none());
        assert!(wait_until(Duration::from_secs(3), || {
            pool.snapshot().pool_size_peak >= 1
        }));
        let _server_conn = server.recv_timeout(Duration::from_secs(2)).unwrap();
        // Age every pooled session past the idle timeout, then observe the
        // expiry through either the lease check or the replenisher sweep.
        thread::sleep(Duration::from_millis(120));
        assert!(wait_until(Duration::from_secs(3), || {
            let _ = pool.lease();
            let snapshot = pool.snapshot();
            snapshot.expired >= 1 && snapshot.hits == 0
        }));
        pool.shutdown();
    }

    #[test]
    fn shutdown_closes_idle_sessions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_socks5_greeter(listener, 1, false);
        let pool =
            WarmSessionPool::start(socks5_config(&addr, false), Duration::from_secs(2)).unwrap();

        assert!(pool.lease().is_none());
        assert!(wait_until(Duration::from_secs(3), || {
            pool.snapshot().pool_size_peak >= 1
        }));
        let mut server_conn = server.recv_timeout(Duration::from_secs(2)).unwrap();
        pool.shutdown();
        server_conn
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0_u8; 1];
        assert_eq!(server_conn.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn replenish_failures_back_off() {
        // Bind then drop a listener so the port actively refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let pool =
            WarmSessionPool::start(socks5_config(&addr, false), Duration::from_secs(2)).unwrap();

        assert!(pool.lease().is_none());
        assert!(wait_until(Duration::from_secs(3), || {
            pool.snapshot().replenish_failures >= 1
        }));
        // The initial 500 ms backoff must keep the failure count bounded.
        thread::sleep(Duration::from_millis(200));
        let snapshot = pool.snapshot();
        assert!(snapshot.replenish_failures <= 2);
        assert_eq!(snapshot.hits, 0);
        pool.shutdown();
    }

    #[test]
    fn completion_reports_nothing_sent_on_dead_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let _server = listener.accept().unwrap();
        // A local write shutdown makes the first request write fail with
        // zero bytes handed to the kernel.
        client.shutdown(Shutdown::Write).unwrap();

        let mut timings = DialTimings::default();
        let result = complete_warm_lease(
            &socks5_config(&addr, false),
            client,
            TEST_DEST,
            Duration::from_secs(1),
            &mut timings,
        );
        match result {
            Err(WarmCompletionError::NothingSent(_)) => {}
            Err(WarmCompletionError::Fatal(err)) => {
                panic!("expected NothingSent, got Fatal: {err:#}")
            }
            Ok(_) => panic!("expected NothingSent, got success"),
        }
    }
}
