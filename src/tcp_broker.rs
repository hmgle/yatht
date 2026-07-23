use std::io;
use std::net::{Shutdown, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crossbeam_channel as channel;

use crate::observability::Observability;

const REGISTRATION_QUEUE_CAPACITY: usize = 128;
const RELAY_BUFFER_CAPACITY: usize = 64 * 1024;
const READ_CHUNK_SIZE: usize = 16 * 1024;
const DEFAULT_MAX_ACTIVE_FLOWS: usize = 16_384;
const DEFAULT_MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;
const SETUP_EXTRA_FDS_PER_WORKER: usize = 3;
const BROKER_FDS_PER_FLOW: usize = 2;

#[derive(Clone)]
pub struct TcpBroker {
    tx: channel::Sender<BrokerCommand>,
    wake_fd: Arc<OwnedFd>,
    resources: Arc<BrokerResources>,
}

pub struct TcpBrokerReactor {
    rx: channel::Receiver<BrokerCommand>,
    wake_fd: Arc<OwnedFd>,
    relays: Vec<TcpRelay>,
    resources: Arc<BrokerResources>,
}

struct BrokerResources {
    limits: TcpBrokerLimits,
    flow_limit_reason: FlowLimitReason,
    active_flows: AtomicUsize,
    pending_bytes: AtomicUsize,
    registration_queue_depth: AtomicUsize,
    observability: Observability,
}

#[derive(Clone, Copy)]
struct TcpBrokerLimits {
    max_active_flows: usize,
    max_pending_bytes: usize,
    rlimit_nofile: u64,
    baseline_fds: usize,
    reserved_fds: usize,
}

#[derive(Clone, Copy)]
enum FlowLimitReason {
    ActiveFlow,
    FdHeadroom,
}

pub struct TcpFlowPermit {
    resources: Arc<BrokerResources>,
}

enum BrokerCommand {
    Register(TcpRelay),
    #[cfg(test)]
    Shutdown,
}

struct TcpRelay {
    target: TcpStream,
    upstream: TcpStream,
    target_to_upstream: PendingBuffer,
    upstream_to_target: PendingBuffer,
    target_read_eof: bool,
    upstream_read_eof: bool,
    target_write_shutdown: bool,
    upstream_write_shutdown: bool,
    permit: TcpFlowPermit,
    accepted_by_reactor: bool,
    outcome_recorded: bool,
    registration_cancelled: Arc<AtomicBool>,
}

#[derive(Default)]
struct PendingBuffer {
    bytes: Vec<u8>,
    offset: usize,
}

impl TcpBroker {
    pub fn new(
        observability: Observability,
        setup_concurrency: usize,
    ) -> io::Result<(Self, TcpBrokerReactor)> {
        let (limits, flow_limit_reason) = TcpBrokerLimits::detect(setup_concurrency)?;
        Self::new_with_limits(observability, limits, flow_limit_reason)
    }

    fn new_with_limits(
        observability: Observability,
        limits: TcpBrokerLimits,
        flow_limit_reason: FlowLimitReason,
    ) -> io::Result<(Self, TcpBrokerReactor)> {
        let wake_fd = Arc::new(create_eventfd()?);
        let (tx, rx) = channel::bounded(REGISTRATION_QUEUE_CAPACITY);
        let resources = Arc::new(BrokerResources {
            limits,
            flow_limit_reason,
            active_flows: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            registration_queue_depth: AtomicUsize::new(0),
            observability,
        });
        resources.observability.record_tcp_broker_limits(
            limits.max_active_flows,
            limits.max_pending_bytes,
            REGISTRATION_QUEUE_CAPACITY,
            limits.rlimit_nofile,
            limits.baseline_fds,
            limits.reserved_fds,
        );
        Ok((
            Self {
                tx,
                wake_fd: Arc::clone(&wake_fd),
                resources: Arc::clone(&resources),
            },
            TcpBrokerReactor {
                rx,
                wake_fd,
                relays: Vec::new(),
                resources,
            },
        ))
    }

    pub fn reserve_flow(&self) -> io::Result<TcpFlowPermit> {
        self.resources.reserve_flow()
    }

    pub fn register(
        &self,
        target: TcpStream,
        upstream: TcpStream,
        permit: TcpFlowPermit,
    ) -> io::Result<()> {
        self.register_with_wake(target, upstream, permit, || {
            wake_eventfd(self.wake_fd.as_raw_fd())
        })
    }

    fn register_with_wake(
        &self,
        target: TcpStream,
        upstream: TcpStream,
        permit: TcpFlowPermit,
        wake: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.resources.pending_is_saturated() {
            self.resources
                .observability
                .tcp_resource_rejection("pending_bytes");
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TCP broker pending-byte limit is saturated",
            ));
        }
        if !self.resources.reserve_registration_slot() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP broker registration queue is full",
            ));
        }

        let registration_cancelled = Arc::new(AtomicBool::new(false));
        let relay = TcpRelay::new(
            target,
            upstream,
            permit,
            Arc::clone(&registration_cancelled),
        );
        match relay.and_then(|relay| {
            self.tx
                .try_send(BrokerCommand::Register(relay))
                .map_err(|err| match err {
                    channel::TrySendError::Full(_) => io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "TCP broker registration queue is full",
                    ),
                    channel::TrySendError::Disconnected(_) => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "TCP broker reactor stopped")
                    }
                })
        }) {
            Ok(()) => {}
            Err(err) => {
                self.resources.release_registration_slot();
                let reason = if err.kind() == io::ErrorKind::BrokenPipe {
                    "reactor_stopped"
                } else {
                    "registration_queue"
                };
                self.resources.observability.tcp_resource_rejection(reason);
                return Err(err);
            }
        }
        if let Err(err) = wake() {
            registration_cancelled.store(true, Ordering::Release);
            self.resources
                .observability
                .tcp_resource_rejection("reactor_stopped");
            return Err(err);
        }
        Ok(())
    }

    #[cfg(test)]
    fn shutdown(&self) -> io::Result<()> {
        self.tx
            .send(BrokerCommand::Shutdown)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP broker stopped"))?;
        wake_eventfd(self.wake_fd.as_raw_fd())
    }
}

impl TcpBrokerLimits {
    fn detect(setup_concurrency: usize) -> io::Result<(Self, FlowLimitReason)> {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let rlimit_nofile = if limit.rlim_cur == libc::RLIM_INFINITY {
            u64::MAX
        } else {
            limit.rlim_cur as u64
        };
        let soft_limit = usize::try_from(rlimit_nofile).unwrap_or(usize::MAX);
        let baseline_fds = open_fd_count()?;
        let policy_headroom = (soft_limit / 5).max(256);
        let setup_headroom = setup_concurrency.saturating_mul(SETUP_EXTRA_FDS_PER_WORKER);
        let reserved_fds = policy_headroom.saturating_add(setup_headroom);
        let fd_flow_limit = soft_limit
            .saturating_sub(baseline_fds)
            .saturating_sub(reserved_fds)
            / BROKER_FDS_PER_FLOW;
        let max_active_flows = DEFAULT_MAX_ACTIVE_FLOWS.min(fd_flow_limit);
        if max_active_flows == 0 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "RLIMIT_NOFILE leaves no TCP broker flow capacity",
            ));
        }
        let reason = if fd_flow_limit < DEFAULT_MAX_ACTIVE_FLOWS {
            FlowLimitReason::FdHeadroom
        } else {
            FlowLimitReason::ActiveFlow
        };
        Ok((
            Self {
                max_active_flows,
                max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
                rlimit_nofile,
                baseline_fds,
                reserved_fds,
            },
            reason,
        ))
    }
}

impl BrokerResources {
    fn reserve_flow(self: &Arc<Self>) -> io::Result<TcpFlowPermit> {
        if self.pending_is_saturated() {
            self.observability.tcp_resource_rejection("pending_bytes");
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TCP broker pending-byte limit is saturated",
            ));
        }
        let acquired =
            self.active_flows
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < self.limits.max_active_flows).then_some(current.saturating_add(1))
                });
        if acquired.is_err() {
            let reason = match self.flow_limit_reason {
                FlowLimitReason::ActiveFlow => "active_flow",
                FlowLimitReason::FdHeadroom => "fd_headroom",
            };
            self.observability.tcp_resource_rejection(reason);
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("TCP broker {reason} limit reached"),
            ));
        }
        self.observability.tcp_flow_acquired();
        Ok(TcpFlowPermit {
            resources: Arc::clone(self),
        })
    }

    fn pending_is_saturated(&self) -> bool {
        self.pending_bytes.load(Ordering::Acquire) >= self.limits.max_pending_bytes
    }

    fn reserve_pending(&self, requested: usize) -> usize {
        loop {
            let current = self.pending_bytes.load(Ordering::Acquire);
            let available = self.limits.max_pending_bytes.saturating_sub(current);
            let reserved = requested.min(available);
            if reserved == 0 {
                return 0;
            }
            let next = current + reserved;
            if self
                .pending_bytes
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.observability.tcp_pending_budget_reserved(reserved);
                return reserved;
            }
        }
    }

    fn release_pending(&self, released: usize) {
        if released == 0 {
            return;
        }
        let previous = self.pending_bytes.fetch_sub(released, Ordering::AcqRel);
        debug_assert!(previous >= released);
        self.observability.tcp_pending_budget_released(released);
    }

    fn reserve_registration_slot(&self) -> bool {
        let reserved = self.registration_queue_depth.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| (current < REGISTRATION_QUEUE_CAPACITY).then_some(current.saturating_add(1)),
        );
        match reserved {
            Ok(_) => {
                self.observability.tcp_registration_queued();
                true
            }
            Err(_) => {
                self.observability
                    .tcp_resource_rejection("registration_queue");
                false
            }
        }
    }

    fn release_registration_slot(&self) {
        let previous = self.registration_queue_depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        self.observability.tcp_registration_dequeued();
    }
}

impl Drop for TcpFlowPermit {
    fn drop(&mut self) {
        let previous = self.resources.active_flows.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        self.resources.observability.tcp_flow_released();
    }
}

fn open_fd_count() -> io::Result<usize> {
    let count = std::fs::read_dir("/proc/self/fd")?.count();
    Ok(count.saturating_sub(1))
}

impl TcpBrokerReactor {
    pub fn run(mut self) -> io::Result<()> {
        loop {
            if self.drain_commands()? {
                return Ok(());
            }

            let mut pollfds = Vec::with_capacity(1 + self.relays.len() * 2);
            pollfds.push(libc::pollfd {
                fd: self.wake_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            for relay in &self.relays {
                pollfds.push(libc::pollfd {
                    fd: relay.target.as_raw_fd(),
                    events: relay.target_events(&self.resources),
                    revents: 0,
                });
                pollfds.push(libc::pollfd {
                    fd: relay.upstream.as_raw_fd(),
                    events: relay.upstream_events(&self.resources),
                    revents: 0,
                });
            }

            let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, -1) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }

            if pollfds[0].revents & libc::POLLIN != 0 {
                drain_eventfd(self.wake_fd.as_raw_fd())?;
                self.resources.observability.tcp_reactor_wakeup();
                if self.drain_commands()? {
                    return Ok(());
                }
            }

            let polled_relays = (pollfds.len() - 1) / 2;
            for index in (0..polled_relays).rev() {
                let target_events = pollfds[1 + index * 2].revents;
                let upstream_events = pollfds[2 + index * 2].revents;
                let relay = &mut self.relays[index];
                let result = relay.process(target_events, upstream_events);
                let finished = result.is_ok() && relay.is_finished();
                if let Err(err) = &result {
                    relay.record_outcome(Some(err));
                } else if finished {
                    relay.record_outcome(None);
                }
                if result.is_err() || finished {
                    self.relays.swap_remove(index);
                }
            }
        }
    }

    fn drain_commands(&mut self) -> io::Result<bool> {
        loop {
            match self.rx.try_recv() {
                Ok(BrokerCommand::Register(mut relay)) => {
                    self.resources.release_registration_slot();
                    if relay.registration_cancelled.load(Ordering::Acquire) {
                        continue;
                    }
                    relay.accepted_by_reactor = true;
                    self.relays.push(relay);
                }
                #[cfg(test)]
                Ok(BrokerCommand::Shutdown) => return Ok(true),
                Err(channel::TryRecvError::Empty) => return Ok(false),
                Err(channel::TryRecvError::Disconnected) => return Ok(true),
            }
        }
    }
}

impl TcpRelay {
    fn new(
        target: TcpStream,
        upstream: TcpStream,
        permit: TcpFlowPermit,
        registration_cancelled: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        target.set_nonblocking(true)?;
        upstream.set_nonblocking(true)?;
        target.set_nodelay(true)?;
        upstream.set_nodelay(true)?;
        Ok(Self {
            target,
            upstream,
            target_to_upstream: PendingBuffer::default(),
            upstream_to_target: PendingBuffer::default(),
            target_read_eof: false,
            upstream_read_eof: false,
            target_write_shutdown: false,
            upstream_write_shutdown: false,
            permit,
            accepted_by_reactor: false,
            outcome_recorded: false,
            registration_cancelled,
        })
    }

    fn target_events(&self, resources: &BrokerResources) -> libc::c_short {
        let mut events = libc::POLLRDHUP;
        if !self.target_read_eof
            && !self.target_to_upstream.is_full()
            && !resources.pending_is_saturated()
        {
            events |= libc::POLLIN;
        }
        if !self.target_write_shutdown && !self.upstream_to_target.is_empty() {
            events |= libc::POLLOUT;
        }
        events
    }

    fn upstream_events(&self, resources: &BrokerResources) -> libc::c_short {
        let mut events = libc::POLLRDHUP;
        if !self.upstream_read_eof
            && !self.upstream_to_target.is_full()
            && !resources.pending_is_saturated()
        {
            events |= libc::POLLIN;
        }
        if !self.upstream_write_shutdown && !self.target_to_upstream.is_empty() {
            events |= libc::POLLOUT;
        }
        events
    }

    fn process(
        &mut self,
        target_events: libc::c_short,
        upstream_events: libc::c_short,
    ) -> io::Result<()> {
        if target_events & libc::POLLNVAL != 0 || upstream_events & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        if target_events & libc::POLLOUT != 0 {
            flush_socket(
                &self.target,
                &mut self.upstream_to_target,
                &self.permit.resources,
            )?;
        }
        if upstream_events & libc::POLLOUT != 0 {
            flush_socket(
                &self.upstream,
                &mut self.target_to_upstream,
                &self.permit.resources,
            )?;
        }
        let target_read = if target_events
            & (libc::POLLIN | libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR)
            != 0
        {
            read_socket(
                &self.target,
                &mut self.target_to_upstream,
                &self.permit.resources,
                true,
            )?
        } else {
            ReadOutcome::Idle
        };
        if target_read == ReadOutcome::Eof {
            self.target_read_eof = true;
        }
        let upstream_read = if upstream_events
            & (libc::POLLIN | libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR)
            != 0
        {
            read_socket(
                &self.upstream,
                &mut self.upstream_to_target,
                &self.permit.resources,
                false,
            )?
        } else {
            ReadOutcome::Idle
        };
        if upstream_read == ReadOutcome::Eof {
            self.upstream_read_eof = true;
        }

        if target_events & libc::POLLERR != 0 && target_read != ReadOutcome::Progress {
            return Err(socket_error(self.target.as_raw_fd()));
        }
        if upstream_events & libc::POLLERR != 0 && upstream_read != ReadOutcome::Progress {
            return Err(socket_error(self.upstream.as_raw_fd()));
        }

        self.propagate_half_closes();
        Ok(())
    }

    fn propagate_half_closes(&mut self) {
        if self.target_read_eof
            && self.target_to_upstream.is_empty()
            && !self.upstream_write_shutdown
        {
            let _ = self.upstream.shutdown(Shutdown::Write);
            self.upstream_write_shutdown = true;
            self.permit.resources.observability.tcp_half_close();
        }
        if self.upstream_read_eof
            && self.upstream_to_target.is_empty()
            && !self.target_write_shutdown
        {
            let _ = self.target.shutdown(Shutdown::Write);
            self.target_write_shutdown = true;
            self.permit.resources.observability.tcp_half_close();
        }
    }

    fn is_finished(&self) -> bool {
        self.target_read_eof
            && self.upstream_read_eof
            && self.target_to_upstream.is_empty()
            && self.upstream_to_target.is_empty()
    }

    fn record_outcome(&mut self, error: Option<&io::Error>) {
        if !self.outcome_recorded {
            self.permit.resources.observability.tcp_flow_finished(error);
            self.outcome_recorded = true;
        }
    }
}

impl Drop for TcpRelay {
    fn drop(&mut self) {
        let pending = self
            .target_to_upstream
            .len()
            .saturating_add(self.upstream_to_target.len());
        self.permit.resources.release_pending(pending);
        self.permit
            .resources
            .observability
            .tcp_pending_removed(pending);
        if self.accepted_by_reactor && !self.outcome_recorded {
            self.permit.resources.observability.tcp_flow_cancelled();
            self.outcome_recorded = true;
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadOutcome {
    Idle,
    Progress,
    Eof,
}

impl PendingBuffer {
    fn pending(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn len(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn is_full(&self) -> bool {
        self.len() >= RELAY_BUFFER_CAPACITY
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.offset > 0 && self.bytes.len() + bytes.len() > RELAY_BUFFER_CAPACITY {
            self.bytes.copy_within(self.offset.., 0);
            self.bytes.truncate(self.len());
            self.offset = 0;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn consume(&mut self, length: usize) {
        self.offset += length;
        if self.offset == self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
    }
}

fn read_socket(
    stream: &TcpStream,
    pending: &mut PendingBuffer,
    resources: &BrokerResources,
    target_to_upstream: bool,
) -> io::Result<ReadOutcome> {
    if pending.is_full() {
        return Ok(ReadOutcome::Idle);
    }
    let mut chunk = [0_u8; READ_CHUNK_SIZE];
    let available = RELAY_BUFFER_CAPACITY - pending.len();
    let reserved = resources.reserve_pending(chunk.len().min(available));
    if reserved == 0 {
        return Ok(ReadOutcome::Idle);
    }
    loop {
        let rc = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                reserved,
                libc::MSG_DONTWAIT,
            )
        };
        resources
            .observability
            .tcp_recv(rc.max(0) as usize, target_to_upstream);
        if rc > 0 {
            resources.release_pending(reserved - rc as usize);
            pending.append(&chunk[..rc as usize]);
            resources.observability.tcp_pending_added(rc as usize);
            return Ok(ReadOutcome::Progress);
        }
        if rc == 0 {
            resources.release_pending(reserved);
            return Ok(ReadOutcome::Eof);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        resources.release_pending(reserved);
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(ReadOutcome::Idle);
        }
        return Err(err);
    }
}

fn flush_socket(
    stream: &TcpStream,
    pending: &mut PendingBuffer,
    resources: &BrokerResources,
) -> io::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    loop {
        let rc = unsafe {
            libc::send(
                stream.as_raw_fd(),
                pending.pending().as_ptr().cast(),
                pending.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        resources.observability.tcp_send();
        if rc > 0 {
            pending.consume(rc as usize);
            resources.release_pending(rc as usize);
            resources.observability.tcp_pending_removed(rc as usize);
            return Ok(());
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TCP broker write returned zero",
            ));
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

fn socket_error(fd: RawFd) -> io::Error {
    let mut error = 0;
    let mut length = std::mem::size_of_val(&error) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if rc < 0 {
        io::Error::last_os_error()
    } else if error == 0 {
        io::Error::from_raw_os_error(libc::ECONNRESET)
    } else {
        io::Error::from_raw_os_error(error)
    }
}

fn create_eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn wake_eventfd(fd: RawFd) -> io::Result<()> {
    let value = 1_u64;
    loop {
        let rc = unsafe {
            libc::write(
                fd,
                (&value as *const u64).cast(),
                std::mem::size_of_val(&value),
            )
        };
        if rc >= 0 {
            return Ok(());
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

fn drain_eventfd(fd: RawFd) -> io::Result<()> {
    let mut value = 0_u64;
    loop {
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
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn relays_data_and_propagates_half_closes() {
        let (broker, reactor) = test_broker(32, DEFAULT_MAX_PENDING_BYTES);
        let reactor_thread = thread::spawn(move || reactor.run().unwrap());
        let (mut target, broker_target) = tcp_pair();
        let (broker_upstream, mut remote) = tcp_pair();
        set_timeout(&target);
        set_timeout(&remote);
        let permit = broker.reserve_flow().unwrap();
        broker
            .register(broker_target, broker_upstream, permit)
            .unwrap();

        target.write_all(b"request").unwrap();
        target.shutdown(Shutdown::Write).unwrap();
        let mut request = Vec::new();
        remote.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"request");

        remote.write_all(b"response").unwrap();
        remote.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        target.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");

        broker.shutdown().unwrap();
        reactor_thread.join().unwrap();
    }

    #[test]
    fn stalled_relay_does_not_block_other_flows() {
        let (broker, reactor) = test_broker(32, DEFAULT_MAX_PENDING_BYTES);
        let reactor_thread = thread::spawn(move || reactor.run().unwrap());
        let (mut stalled_target, stalled_broker_target) = tcp_pair();
        let (stalled_broker_upstream, _stalled_remote) = tcp_pair();
        let permit = broker.reserve_flow().unwrap();
        broker
            .register(stalled_broker_target, stalled_broker_upstream, permit)
            .unwrap();

        let payload = vec![0x5a; RELAY_BUFFER_CAPACITY * 4];
        thread::spawn(move || {
            let _ = stalled_target.write_all(&payload);
        });

        let (mut active_target, active_broker_target) = tcp_pair();
        let (active_broker_upstream, mut active_remote) = tcp_pair();
        set_timeout(&active_target);
        set_timeout(&active_remote);
        let permit = broker.reserve_flow().unwrap();
        broker
            .register(active_broker_target, active_broker_upstream, permit)
            .unwrap();
        active_target.write_all(b"ping").unwrap();
        let mut received = [0_u8; 4];
        active_remote.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ping");

        broker.shutdown().unwrap();
        reactor_thread.join().unwrap();
    }

    #[test]
    fn releases_active_flow_permits() {
        let (broker, _reactor) = test_broker(1, DEFAULT_MAX_PENDING_BYTES);
        let permit = broker.reserve_flow().unwrap();
        let err = match broker.reserve_flow() {
            Ok(_) => panic!("active flow limit was not enforced"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);

        drop(permit);
        assert!(broker.reserve_flow().is_ok());
    }

    #[test]
    fn pending_byte_cap_allows_progress_in_chunks() {
        let (broker, reactor) = test_broker(2, 4);
        let resources = Arc::clone(&broker.resources);
        let reactor_thread = thread::spawn(move || reactor.run().unwrap());
        let (mut target, broker_target) = tcp_pair();
        let (broker_upstream, mut remote) = tcp_pair();
        set_timeout(&target);
        set_timeout(&remote);
        let permit = broker.reserve_flow().unwrap();
        broker
            .register(broker_target, broker_upstream, permit)
            .unwrap();

        target.write_all(b"12345678").unwrap();
        let mut received = [0_u8; 8];
        remote.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"12345678");
        assert!(resources.pending_bytes.load(Ordering::Acquire) <= 4);

        drop(target);
        drop(remote);
        broker.shutdown().unwrap();
        reactor_thread.join().unwrap();
        assert_eq!(resources.pending_bytes.load(Ordering::Acquire), 0);
        assert_eq!(resources.active_flows.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounds_registration_slots() {
        let (broker, _reactor) = test_broker(256, DEFAULT_MAX_PENDING_BYTES);
        for _ in 0..REGISTRATION_QUEUE_CAPACITY {
            assert!(broker.resources.reserve_registration_slot());
        }
        assert!(!broker.resources.reserve_registration_slot());
        for _ in 0..REGISTRATION_QUEUE_CAPACITY {
            broker.resources.release_registration_slot();
        }
        assert_eq!(
            broker
                .resources
                .registration_queue_depth
                .load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn drops_queued_relay_when_wakeup_fails() {
        let (broker, mut reactor) = test_broker(2, DEFAULT_MAX_PENDING_BYTES);
        let (broker_target, _target) = tcp_pair();
        let (broker_upstream, _remote) = tcp_pair();
        let permit = broker.reserve_flow().unwrap();
        let err = broker
            .register_with_wake(broker_target, broker_upstream, permit, || {
                Err(io::Error::from_raw_os_error(libc::EBADF))
            })
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
        assert_eq!(broker.resources.active_flows.load(Ordering::Acquire), 1);

        assert!(!reactor.drain_commands().unwrap());
        assert!(reactor.relays.is_empty());
        assert_eq!(broker.resources.active_flows.load(Ordering::Acquire), 0);
        assert_eq!(
            broker
                .resources
                .registration_queue_depth
                .load(Ordering::Acquire),
            0
        );
    }

    fn test_broker(
        max_active_flows: usize,
        max_pending_bytes: usize,
    ) -> (TcpBroker, TcpBrokerReactor) {
        TcpBroker::new_with_limits(
            Observability::default(),
            TcpBrokerLimits {
                max_active_flows,
                max_pending_bytes,
                rlimit_nofile: 4096,
                baseline_fds: 0,
                reserved_fds: 256,
            },
            FlowLimitReason::ActiveFlow,
        )
        .unwrap()
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn set_timeout(stream: &TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
}
