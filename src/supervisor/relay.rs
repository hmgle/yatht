use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpRouteKind {
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
pub(super) struct RelayKey {
    pub(super) tgid: u32,
    pub(super) fd: RawFd,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FdIdentity {
    pub(super) dev: libc::dev_t,
    pub(super) ino: libc::ino_t,
}

pub(super) struct UdpTargetSnapshot {
    pub(super) identity: FdIdentity,
    pub(super) domain: i32,
    pub(super) protocol: i32,
    pub(super) flags: TargetFdFlags,
    pub(super) rcvtimeo: Option<Duration>,
}

/// Relay slot state. `Creating` is a single-flight marker published under the
/// lock while a relay's sockets/fd are built outside it; concurrent lookups for
/// the same key wait for it to resolve rather than missing the (still empty)
/// map and continuing a recv on the original fd -- which would then block
/// forever once ADDFD swaps in the relay socket.
pub(super) enum RelayState {
    Creating,
    Ready(UdpRelayHandle),
}

pub(super) enum RelayLookup {
    Ready(UdpRelayHandle, OwnedFd),
    Creating,
    Missing,
}

pub(super) enum StableSocketCreation {
    Injected,
    Unsupported,
}

#[derive(Default)]
pub(super) struct UdpRelayRegistry {
    pub(super) observability: Observability,
    pub(super) inner: Mutex<HashMap<RelayKey, RelayState>>,
    pub(super) by_cookie: Mutex<HashMap<u64, UdpRelayHandle>>,
    pub(super) created: Condvar,
    pub(super) active: AtomicUsize,
    pub(super) stable_addfd_unsupported: AtomicBool,
    pub(super) reap_warning_reported: AtomicBool,
    pub(super) reaper: RelayReaper,
}

#[derive(Default)]
pub(super) struct RelayReaper {
    pub(super) state: Mutex<RelayReaperState>,
    pub(super) signal: Condvar,
}

#[derive(Default)]
pub(super) struct RelayReaperState {
    pub(super) stop: bool,
    pub(super) published: bool,
}

/// Sweep cadence for the relay reaper. Consecutive sweeps that reclaim
/// nothing extend the wait geometrically once the grace window passes, so a
/// quiet supervisor stops re-reading the host-wide `/proc/net/unix`. Capacity
/// is never lost to a long interval: exhausted admission sweeps on demand.
#[derive(Clone, Copy, Default)]
pub(super) struct StableSweepCadence {
    pub(super) idle_sweeps: u32,
}

impl StableSweepCadence {
    pub(super) fn interval(self) -> Duration {
        let steps = self
            .idle_sweeps
            .saturating_sub(STABLE_RELAY_SWEEP_IDLE_GRACE);
        let factor = 1_u32.checked_shl(steps).unwrap_or(u32::MAX);
        STABLE_RELAY_SWEEP_INTERVAL
            .saturating_mul(factor)
            .min(STABLE_RELAY_SWEEP_MAX_INTERVAL)
    }

    pub(super) fn record_sweep(&mut self, reclaimed: usize) {
        if reclaimed > 0 {
            self.restart();
        } else {
            self.idle_sweeps = self.idle_sweeps.saturating_add(1);
        }
    }

    pub(super) fn restart(&mut self) {
        self.idle_sweeps = 0;
    }
}

#[derive(Clone)]
pub(super) struct UdpRelayHandle {
    pub(super) tx: channel::Sender<UdpJob>,
    pub(super) default_dest: Arc<Mutex<Option<(Destination, UdpRouteKind)>>>,
    /// Retains the actual local port reservation, including bind(port=0).
    pub(super) local_bind: Arc<Mutex<Option<UdpLocalSocket>>>,
    pub(super) pending_sources: Arc<Mutex<VecDeque<Destination>>>,
    pub(super) relay_fd: Arc<OwnedFd>,
    pub(super) target_identity: FdIdentity,
    pub(super) target_cookie: u64,
    pub(super) domain: i32,
    /// Protocol recorded at relay creation (UDP today) so `SO_PROTOCOL`
    /// answers from the handle rather than from a creation-time invariant.
    pub(super) protocol: i32,
    pub(super) stable: bool,
    pub(super) shutdown: Arc<AtomicBool>,
}

pub(super) struct UdpJob {
    pub(super) dest: Destination,
    pub(super) payload: Vec<u8>,
    pub(super) route: UdpRouteKind,
}

pub(super) struct UdpRelayResponse {
    pub(super) source: Destination,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct UdpRelayConfig {
    pub(super) observability: Observability,
    pub(super) proxy: crate::config::ProxyConfig,
    pub(super) dns_server: Destination,
    pub(super) timeout: Duration,
    pub(super) debug: bool,
}

pub(super) struct DirectUdpSocket {
    pub(super) sock: UdpSocket,
    pub(super) recv_buf: Vec<u8>,
    pub(super) cookie: u64,
}

pub(super) struct UdpLocalSocket {
    pub(super) socket: UdpSocket,
    pub(super) port_locked: bool,
}

pub(super) fn relay_key(pid: u32, fd: RawFd) -> RelayKey {
    RelayKey {
        tgid: cached_thread_group_id(pid).unwrap_or(pid),
        fd,
    }
}

pub(super) struct CachedThreadPidfd {
    pub(super) tgid: Option<u32>,
    pub(super) pidfd: OwnedFd,
}

pub(super) static THREAD_PIDFD_CACHE: OnceLock<Mutex<HashMap<u32, CachedThreadPidfd>>> =
    OnceLock::new();

pub(super) fn cached_thread_group_id(pid: u32) -> io::Result<u32> {
    let cache = THREAD_PIDFD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();
    if cache
        .get(&pid)
        .is_some_and(|entry| !pidfd_is_alive(entry.pidfd.as_raw_fd()))
    {
        cache.remove(&pid);
    }
    ensure_cached_thread_pidfd(&mut cache, pid)?;
    if let Some(tgid) = cache.get(&pid).and_then(|entry| entry.tgid) {
        return Ok(tgid);
    }
    let tgid = thread_group_id(pid)?;
    cache.get_mut(&pid).unwrap().tgid = Some(tgid);
    Ok(tgid)
}

pub(super) fn ensure_cached_thread_pidfd(
    cache: &mut HashMap<u32, CachedThreadPidfd>,
    pid: u32,
) -> io::Result<()> {
    if cache.contains_key(&pid) {
        return Ok(());
    }
    if cache.len() >= THREAD_PIDFD_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    let pidfd = pidfd_open(pid, libc::PIDFD_THREAD)?;
    cache.insert(pid, CachedThreadPidfd { tgid: None, pidfd });
    Ok(())
}

pub(super) fn pidfd_is_alive(pidfd: RawFd) -> bool {
    loop {
        let mut pollfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if rc == 0 {
            return true;
        }
        if rc > 0 {
            return pollfd.revents
                & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                == 0;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return false;
        }
    }
}

pub(super) fn valid_relay_locked(
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
        // The cookie index owns the relay until its final target alias closes.
        relays.remove(&key);
        None
    }
}

pub(super) fn build_udp_relay_config(
    cfg: &EffectiveConfig,
    observability: Observability,
) -> UdpRelayConfig {
    let dns_server = cfg
        .dns_server
        .map(|addr| Destination {
            ip: addr.ip(),
            port: addr.port(),
        })
        .unwrap_or(Destination {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0,
        });

    UdpRelayConfig {
        observability,
        proxy: cfg.proxy.clone(),
        dns_server,
        timeout: cfg.connect_timeout,
        debug: cfg.debug,
    }
}

impl UdpRelayRegistry {
    pub(super) fn with_observability(observability: Observability) -> Self {
        Self {
            observability,
            ..Self::default()
        }
    }

    /// Closes relays whose target socket is gone. Only relays that were
    /// already published when the sweep started are eligible: `/proc/net/unix`
    /// is generated as it is read, so a socket that a concurrent
    /// `create_stable` opens while the read is in flight can be missing from
    /// the snapshot even though it is alive. Taking the candidate list before
    /// the read keeps such a relay from being shut down at birth and from
    /// releasing an admission slot its creator still holds.
    pub(super) fn reap_closed_relays(&self) -> io::Result<usize> {
        let candidates = self
            .by_cookie
            .lock()
            .unwrap()
            .iter()
            .map(|(cookie, handle)| (*cookie, handle.target_identity))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(0);
        }

        let live_inodes = unix_socket_inodes()?;
        let removed = {
            let mut stable = self.by_cookie.lock().unwrap();
            let mut closed = Vec::new();
            for (cookie, identity) in &candidates {
                if live_inodes.contains(&identity.ino) {
                    continue;
                }
                // Reap only the handle the candidate list saw. A replacement
                // published under the same cookie since then has its own
                // socket and must not inherit this verdict.
                match stable.get(cookie) {
                    Some(handle) if handle.target_identity == *identity => {
                        closed.push((*cookie, handle.clone()));
                    }
                    _ => continue,
                }
            }
            for (cookie, _) in &closed {
                stable.remove(cookie);
            }
            closed
        };
        if removed.is_empty() {
            return Ok(0);
        }

        let identities = removed
            .iter()
            .map(|(_, handle)| handle.target_identity)
            .collect::<HashSet<_>>();
        self.inner.lock().unwrap().retain(|_, state| {
            !matches!(state, RelayState::Ready(handle) if identities.contains(&handle.target_identity))
        });
        self.created.notify_all();
        for (_, handle) in &removed {
            handle.shutdown();
            self.release_relay_slot();
        }
        Ok(removed.len())
    }

    pub(super) fn reserve_relay_slot(&self) -> Result<RelaySlotGuard<'_>> {
        let reserved = self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_UDP_RELAYS).then_some(active + 1)
            });
        if reserved.is_err() {
            bail!("active UDP relay limit of {MAX_UDP_RELAYS} reached");
        }
        Ok(RelaySlotGuard {
            registry: self,
            committed: false,
        })
    }

    pub(super) fn reap_closed_relays_best_effort(&self, debug: bool) -> usize {
        match self.reap_closed_relays() {
            Ok(reclaimed) => {
                self.reap_warning_reported.store(false, Ordering::Release);
                reclaimed
            }
            Err(err) => {
                let first = !self.reap_warning_reported.swap(true, Ordering::AcqRel);
                if debug && first {
                    eprintln!("yatht: UDP relay cleanup skipped: {err}");
                }
                0
            }
        }
    }

    /// Restores the base sweep cadence. A newly published relay is the
    /// only event the supervisor can observe that makes a quiet process worth
    /// sweeping often again; the target-side close the sweep looks for happens
    /// entirely outside its view.
    pub(super) fn notify_relay_published(&self) {
        self.reaper.state.lock().unwrap().published = true;
        self.reaper.signal.notify_all();
    }

    pub(super) fn stop_relay_reaper(&self) {
        self.reaper.state.lock().unwrap().stop = true;
        self.reaper.signal.notify_all();
    }

    /// Sleeps until the next sweep is due, returning false once shutdown has
    /// been requested. The remaining wait is always measured from the same
    /// start, so a steady stream of newly published relays can only shorten
    /// it and can never postpone a sweep indefinitely.
    pub(super) fn wait_for_next_relay_sweep(&self, cadence: &mut StableSweepCadence) -> bool {
        let start = Instant::now();
        let mut state = self.reaper.state.lock().unwrap();
        loop {
            if state.stop {
                return false;
            }
            if state.published {
                state.published = false;
                cadence.restart();
            }
            let Some(remaining) = cadence.interval().checked_sub(start.elapsed()) else {
                return true;
            };
            state = self.reaper.signal.wait_timeout(state, remaining).unwrap().0;
        }
    }

    /// Reserves an admission slot for a relay. The common path never
    /// scans procfs; only an exhausted budget sweeps, and it then retries
    /// briefly because `/proc/net/unix` can lag the final close of a
    /// target-side alias performed by another thread. The wait sits entirely
    /// on the already-slow path.
    pub(super) fn reserve_reaped_relay_slot(&self, debug: bool) -> Result<RelaySlotGuard<'_>> {
        let mut last = match self.reserve_relay_slot() {
            Ok(slot) => return Ok(slot),
            Err(err) => err,
        };
        for attempt in 0..STABLE_RELAY_REAP_ATTEMPTS {
            if attempt > 0 {
                thread::sleep(STABLE_RELAY_REAP_INTERVAL);
            }
            self.reap_closed_relays_best_effort(debug);
            match self.reserve_relay_slot() {
                Ok(slot) => return Ok(slot),
                Err(err) => last = err,
            }
        }
        Err(last)
    }

    pub(super) fn release_relay_slot(&self) {
        let _ = self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_sub(1)
            });
    }

    pub(super) fn remove_cookie_if_current(&self, cookie: u64, target_identity: FdIdentity) {
        let mut stable = self.by_cookie.lock().unwrap();
        if matches!(stable.get(&cookie), Some(current) if current.target_identity == target_identity)
        {
            stable.remove(&cookie);
        }
    }

    pub(super) fn create_stable(
        &self,
        listener_fd: RawFd,
        cfg: &EffectiveConfig,
        notif: &SeccompNotif,
        socket_type: i32,
        protocol: i32,
    ) -> Result<StableSocketCreation> {
        if self.stable_addfd_unsupported.load(Ordering::Acquire) {
            return Ok(StableSocketCreation::Unsupported);
        }

        let mut slot = self.reserve_reaped_relay_slot(cfg.debug)?;
        let (relay_socket, target_fd) =
            make_relay_pair().context("create stable UDP relay datagram socketpair")?;
        if socket_type & libc::SOCK_NONBLOCK != 0 {
            set_nonblocking(target_fd.as_raw_fd())
                .context("set stable UDP relay target nonblocking")?;
        }
        let target = RelayTargetInfo {
            identity: fd_identity(target_fd.as_raw_fd())
                .context("stat stable UDP relay target socket")?,
            cookie: socket_cookie(target_fd.as_raw_fd())
                .context("read stable UDP relay target SO_COOKIE")?,
            domain: notif.data.args[0] as i32,
            protocol,
        };
        let target_cookie = target.cookie;
        let target_identity = target.identity;
        let handle = start_udp_relay(
            build_udp_relay_config(cfg, self.observability.clone()),
            relay_socket,
            None,
            target,
            true,
        )
        .context("start stable UDP relay workers")?;

        // Publish the primary identity before ADDFD+SEND wakes the target. If
        // the target immediately uses a dup/fork alias before the fd cache is
        // populated, lookup can still recover the relay by SO_COOKIE.
        self.by_cookie
            .lock()
            .unwrap()
            .insert(target_cookie, handle.clone());
        self.notify_relay_published();
        let mut addfd = SeccompNotifAddfd {
            id: notif.id,
            flags: seccomp::ADDFD_FLAG_SEND,
            srcfd: target_fd.as_raw_fd() as u32,
            newfd: 0,
            newfd_flags: if socket_type & libc::SOCK_CLOEXEC != 0 {
                libc::O_CLOEXEC as u32
            } else {
                0
            },
        };
        let target_fd_number = match seccomp::notif_addfd(listener_fd, &mut addfd) {
            Ok(fd) => fd,
            Err(err) => {
                self.remove_cookie_if_current(target_cookie, target_identity);
                handle.shutdown();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    self.stable_addfd_unsupported.store(true, Ordering::Release);
                    return Ok(StableSocketCreation::Unsupported);
                }
                return Err(err).context("atomically inject stable UDP socket");
            }
        };

        self.inner.lock().unwrap().insert(
            relay_key(notif.pid, target_fd_number),
            RelayState::Ready(handle),
        );
        slot.commit();
        Ok(StableSocketCreation::Injected)
    }

    pub(super) fn ensure(
        &self,
        listener_fd: RawFd,
        cfg: &EffectiveConfig,
        notif_id: u64,
        pid: u32,
        fd: RawFd,
        default_dest: Option<(Destination, UdpRouteKind)>,
    ) -> Result<Option<UdpRelayHandle>> {
        // Fast path: reuse an existing relay. This still validates the target
        // fd identity, but it no longer returns an unused duplicate to ensure().
        if let Some(handle) = self.lookup_handle(pid, fd, true) {
            if let Some((dest, route)) = default_dest {
                handle.set_default_dest(dest, route)?;
            }
            return Ok(Some(handle));
        }

        let key = relay_key(pid, fd);

        // Claim the key under the lock before building anything. Publishing a
        // Creating marker keeps the expensive setup (datagram socketpair,
        // reading the target fd flags via pidfd + /proc, fstat) outside the lock
        // -- so it never blocks lookups for unrelated keys -- while still making a
        // concurrent lookup for THIS key wait for the relay instead of missing
        // the empty map and continuing its recv on the original fd.
        let mut slot = {
            let mut relays = self.inner.lock().unwrap();
            loop {
                if let Some(handle) = valid_relay_locked(&mut relays, key, pid, fd) {
                    if let Some((dest, route)) = default_dest {
                        handle.set_default_dest(dest, route)?;
                    }
                    return Ok(Some(handle));
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
                        // Admission may reap, which also locks the alias map.
                        drop(relays);
                        let slot = self.reserve_reaped_relay_slot(cfg.debug)?;
                        relays = self.inner.lock().unwrap();
                        if relays.contains_key(&key) {
                            drop(slot);
                            continue;
                        }
                        relays.insert(key, RelayState::Creating);
                        break slot;
                    }
                }
            }
        };

        // We own the Creating marker for `key`. The guard clears it and wakes
        // waiters on every early return (build error, injection failure) so a
        // failed attempt never strands lookups waiting forever.
        let mut guard = CreatingGuard::new(self, key);

        // Inspect only after publishing Creating. Trapped close/close_range and
        // dup2/dup3 operations targeting this fd now wait until injection has
        // either committed or failed, so they cannot replace the descriptor
        // between this snapshot and ADDFD.
        let target_snapshot = match inspect_udp_target(pid, fd)? {
            Some(snapshot) => snapshot,
            None => return Ok(None),
        };

        let relay_cfg = build_udp_relay_config(cfg, self.observability.clone());
        let (relay_socket, target_fd) =
            make_relay_pair().context("create UDP relay datagram socketpair")?;
        if target_snapshot.flags.status_flags & libc::O_NONBLOCK != 0 {
            let _ = set_nonblocking(target_fd.as_raw_fd());
        }
        if let Some(timeout) = target_snapshot.rcvtimeo {
            set_socket_recv_timeout(target_fd.as_raw_fd(), timeout)
                .context("preserve UDP SO_RCVTIMEO across lazy relay replacement")?;
        }
        let target_identity =
            fd_identity(target_fd.as_raw_fd()).context("stat UDP relay target socket")?;

        let mut addfd = SeccompNotifAddfd {
            id: notif_id,
            flags: seccomp::ADDFD_FLAG_SETFD,
            srcfd: target_fd.as_raw_fd() as u32,
            newfd: fd as u32,
            newfd_flags: target_snapshot.flags.newfd_flags,
        };

        let current_target = duplicate_remote_fd(pid, fd)
            .context("duplicate UDP target fd immediately before injection")?;
        if fd_identity(current_target.as_raw_fd()).context("stat current UDP target fd")?
            != target_snapshot.identity
        {
            bail!("UDP target fd changed before relay injection");
        }
        let target = RelayTargetInfo {
            identity: target_identity,
            cookie: socket_cookie(target_fd.as_raw_fd())
                .context("read UDP relay target SO_COOKIE")?,
            domain: target_snapshot.domain,
            protocol: target_snapshot.protocol,
        };
        let handle = start_udp_relay(relay_cfg, relay_socket, default_dest, target, false)
            .context("start bounded UDP relay workers")?;
        if let Err(err) = seccomp::notif_addfd(listener_fd, &mut addfd) {
            handle.shutdown();
            return Err(err).context("inject UDP relay fd");
        }
        // Publish while our target duplicate still pins the inode and before
        // waking waiters on the alias cache. A sweep cannot reap this socket.
        self.by_cookie
            .lock()
            .unwrap()
            .insert(handle.target_cookie, handle.clone());
        self.notify_relay_published();
        drop(target_fd);

        // Publish the ready relay and hand the marker off to Ready in one
        // critical section so waiters wake to a usable handle.
        guard.commit(RelayState::Ready(handle.clone()));
        slot.commit();
        Ok(Some(handle))
    }

    /// Fast relay lookup. Probes the map under the lock first, so the common
    /// case -- a recvfrom/recvmsg on a plain fd with no relay -- costs a single
    /// cheap map miss with no fd duplication. Only on a hit is the target fd
    /// duplicated (once, outside the lock) and its identity verified; the
    /// duplicated fd is handed back so the caller can recv on it without
    /// duplicating again. A stale entry (fd reused for a different socket) is
    /// removed, but only if the entry we saw is still the current one, so a
    /// concurrent insert of a fresh relay is never clobbered.
    pub(super) fn lookup(&self, pid: u32, fd: RawFd, wait_creating: bool) -> RelayLookup {
        let key = relay_key(pid, fd);
        let cached = {
            let mut relays = self.inner.lock().unwrap();
            loop {
                match relays.get(&key) {
                    Some(RelayState::Ready(handle)) => break Some(handle.clone()),
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
                    None => break None,
                }
            }
        };

        if let Some(handle) = cached {
            let duplicated = match handle.duplicate_target_fd(pid, fd) {
                Ok(duplicated) => duplicated,
                Err(_) => {
                    self.remove_ready_if_current(key, handle.target_identity);
                    return RelayLookup::Missing;
                }
            };
            if handle.matches_target_fd(duplicated.as_raw_fd()) {
                return RelayLookup::Ready(handle, duplicated);
            }
            self.remove_ready_if_current(key, handle.target_identity);
        }

        // `(tgid, fd)` is only a cache. A dup or fork alias
        // misses that cache, so duplicate the notifying fd and recover the
        // primary relay by the kernel socket cookie.
        if self.by_cookie.lock().unwrap().is_empty() {
            return RelayLookup::Missing;
        }
        let duplicated = match duplicate_remote_fd(pid, fd) {
            Ok(duplicated) => duplicated,
            Err(_) => return RelayLookup::Missing,
        };
        let Some(cookie) = socket_cookie(duplicated.as_raw_fd()) else {
            return RelayLookup::Missing;
        };
        let handle = self.by_cookie.lock().unwrap().get(&cookie).cloned();
        let Some(handle) = handle else {
            return RelayLookup::Missing;
        };
        if !handle.matches_target_fd(duplicated.as_raw_fd()) {
            return RelayLookup::Missing;
        }
        self.inner
            .lock()
            .unwrap()
            .insert(key, RelayState::Ready(handle.clone()));
        RelayLookup::Ready(handle, duplicated)
    }

    pub(super) fn lookup_handle(
        &self,
        pid: u32,
        fd: RawFd,
        wait_creating: bool,
    ) -> Option<UdpRelayHandle> {
        match self.lookup(pid, fd, wait_creating) {
            RelayLookup::Ready(handle, _) => Some(handle),
            RelayLookup::Creating | RelayLookup::Missing => None,
        }
    }

    pub(super) fn remove_for_close(&self, pid: u32, fd: RawFd) {
        let key = relay_key(pid, fd);
        let handle = {
            let mut relays = self.inner.lock().unwrap();
            loop {
                match relays.get(&key) {
                    Some(RelayState::Ready(handle)) => break handle.clone(),
                    Some(RelayState::Creating) => {
                        relays = self.created.wait(relays).unwrap();
                    }
                    None => return,
                }
            }
        };
        if handle.target_fd_matches(pid, fd) {
            self.remove_ready_if_current(key, handle.target_identity);
        }
    }

    pub(super) fn remove_for_close_range(&self, pid: u32, first: u32, last: u32) {
        let tgid = cached_thread_group_id(pid).unwrap_or(pid);
        let candidates = {
            let mut relays = self.inner.lock().unwrap();
            while relays.iter().any(|(key, state)| {
                key.tgid == tgid
                    && fd_in_close_range(key.fd, first, last)
                    && matches!(state, RelayState::Creating)
            }) {
                relays = self.created.wait(relays).unwrap();
            }
            relays
                .iter()
                .filter_map(|(key, state)| {
                    if key.tgid != tgid || !fd_in_close_range(key.fd, first, last) {
                        return None;
                    }
                    match state {
                        RelayState::Ready(handle) => Some((*key, handle.clone())),
                        RelayState::Creating => None,
                    }
                })
                .collect::<Vec<_>>()
        };

        for (key, handle) in candidates {
            if handle.target_fd_matches(pid, key.fd) {
                self.remove_ready_if_current(key, handle.target_identity);
            }
        }
    }

    pub(super) fn wait_for_creation(&self, pid: u32, fd: RawFd) {
        let key = relay_key(pid, fd);
        let mut relays = self.inner.lock().unwrap();
        while matches!(relays.get(&key), Some(RelayState::Creating)) {
            relays = self.created.wait(relays).unwrap();
        }
    }

    pub(super) fn remove_alias(&self, pid: u32, fd: RawFd) {
        let key = relay_key(pid, fd);
        self.inner.lock().unwrap().remove(&key);
        self.created.notify_all();
    }

    pub(super) fn remove_ready_if_current(&self, key: RelayKey, target_identity: FdIdentity) {
        {
            let mut relays = self.inner.lock().unwrap();
            if matches!(relays.get(&key), Some(RelayState::Ready(current)) if current.target_identity == target_identity)
            {
                relays.remove(&key);
            }
        }
    }
}

/// Reclaims relays whose target socket is gone. The scan reads the
/// host-wide `/proc/net/unix`, whose size and parse cost track the machine
/// rather than the relays this supervisor owns, so it runs on its own thread
/// instead of on the blocking-receive reactor where a multi-millisecond stall
/// would delay already-ready receives and armed `SO_RCVTIMEO`/`recvmmsg`
/// deadlines.
pub(super) fn udp_relay_reaper(relays: Arc<UdpRelayRegistry>, debug: bool) {
    lower_current_thread_priority(STABLE_RELAY_REAPER_NICE);
    let mut cadence = StableSweepCadence::default();
    while relays.wait_for_next_relay_sweep(&mut cadence) {
        cadence.record_sweep(relays.reap_closed_relays_best_effort(debug));
    }
}

/// Best-effort `nice` for the calling thread only. Linux scopes `PRIO_PROCESS`
/// to a single task when given a tid, so the notification workers and the
/// receive reactor keep their original priority. Failure only means the sweep
/// competes for CPU on equal terms.
pub(super) fn lower_current_thread_priority(nice: libc::c_int) {
    let tid = unsafe { libc::gettid() };
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS as _, tid as libc::id_t, nice);
    }
}

// `/proc/net/unix`'s Num column is rendered through `%pK` and can be zeroed by
// kptr_restrict, so it is not a portable identity component. Inode reuse can
// conservatively delay cleanup while the reused inode remains present, but it
// cannot reclaim a live relay.
pub(super) fn unix_socket_inodes() -> io::Result<HashSet<libc::ino_t>> {
    let raw = fs::read_to_string("/proc/net/unix")?;
    let mut inodes = HashSet::new();
    for line in raw.lines().skip(1) {
        let Some(raw_inode) = line.split_whitespace().nth(6) else {
            continue;
        };
        if let Ok(inode) = raw_inode.parse::<libc::ino_t>() {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

pub(super) struct RelaySlotGuard<'a> {
    pub(super) registry: &'a UdpRelayRegistry,
    pub(super) committed: bool,
}

impl RelaySlotGuard<'_> {
    pub(super) fn commit(&mut self) {
        self.committed = true;
    }
}

/// Owns the single-flight `Creating` marker for one relay key. On drop it clears
/// the marker (unless committed) and always wakes threads waiting in `lookup`/
/// `ensure`, so a failed creation attempt can never strand a waiter.
pub(super) struct CreatingGuard<'a> {
    pub(super) registry: &'a UdpRelayRegistry,
    pub(super) key: RelayKey,
    pub(super) committed: bool,
}

impl<'a> CreatingGuard<'a> {
    pub(super) fn new(registry: &'a UdpRelayRegistry, key: RelayKey) -> Self {
        CreatingGuard {
            registry,
            key,
            committed: false,
        }
    }

    pub(super) fn commit(&mut self, state: RelayState) {
        let mut relays = self.registry.inner.lock().unwrap();
        relays.insert(self.key, state);
        self.committed = true;
        drop(relays);
        self.registry.created.notify_all();
    }
}

impl UdpRelayHandle {
    pub(super) fn local_bind(&self) -> Option<Destination> {
        self.local_bind
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|local| local.socket.local_addr().ok())
            .map(|addr| Destination {
                ip: addr.ip(),
                port: addr.port(),
            })
    }

    pub(super) fn default_destination(&self) -> Option<(Destination, UdpRouteKind)> {
        *self.default_dest.lock().unwrap()
    }

    pub(super) fn unspecified_destination(&self) -> Destination {
        Destination {
            ip: if self.domain == libc::AF_INET6 {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            port: 0,
        }
    }

    pub(super) fn set_default_dest(
        &self,
        dest: Destination,
        route: UdpRouteKind,
    ) -> io::Result<()> {
        self.autobind()?;
        *self.default_dest.lock().unwrap() = Some((dest, route));
        Ok(())
    }

    pub(super) fn clear_default_dest(&self) {
        *self.default_dest.lock().unwrap() = None;
        // Linux disconnect releases an automatically selected local port, but
        // retains one explicitly locked by bind(nonzero_port). bind(0) does
        // not set SOCK_BINDPORT_LOCK, even though it reserves a port eagerly.
        let mut local = self.local_bind.lock().unwrap();
        if local.as_ref().is_some_and(|bound| !bound.port_locked) {
            *local = None;
        }
    }

    pub(super) fn accepts_destination(&self, dest: Destination) -> bool {
        udp_domain_accepts_destination(self.domain, dest)
    }

    pub(super) fn set_local_bind(&self, bind: Destination) -> io::Result<()> {
        let mut current = self.local_bind.lock().unwrap();
        if current.is_some() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        *current = Some(UdpLocalSocket {
            socket: UdpSocket::bind(SocketAddr::new(bind.ip, bind.port))?,
            port_locked: bind.port != 0,
        });
        Ok(())
    }

    pub(super) fn autobind(&self) -> io::Result<()> {
        if self.stable {
            let mut local = self.local_bind.lock().unwrap();
            if local.is_none() {
                *local = Some(UdpLocalSocket {
                    socket: UdpSocket::bind(SocketAddr::new(self.unspecified_destination().ip, 0))?,
                    port_locked: false,
                });
            }
        }
        Ok(())
    }

    pub(super) fn send(
        &self,
        dest: Destination,
        payload: Vec<u8>,
        route: UdpRouteKind,
        nonblocking: bool,
    ) -> io::Result<()> {
        // Reserve synchronously, before acknowledging a send or queueing work.
        // A following bind must already observe the socket as bound.
        self.autobind()?;
        let job = UdpJob {
            dest,
            payload,
            route,
        };
        if nonblocking {
            return self.tx.try_send(job).map_err(|err| match err {
                channel::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
                channel::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "UDP relay worker exited")
                }
            });
        }
        self.tx
            .send(job)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP relay worker exited"))
    }

    /// Duplicates the target fd from the *currently notifying* thread rather than
    /// a cached thread-group-leader pidfd. The leader can exit (becoming a zombie
    /// with no accessible fd table) while worker threads keep using the relay, and
    /// a thread may not share the leader's fd table at all; the notifying thread is
    /// guaranteed alive for the duration of the seccomp stop, so its fd table is the
    /// reliable source for the duplicate.
    pub(super) fn duplicate_target_fd(&self, pid: u32, fd: RawFd) -> io::Result<OwnedFd> {
        duplicate_remote_fd(pid, fd)
    }

    pub(super) fn matches_target_fd(&self, fd: RawFd) -> bool {
        socket_cookie(fd) == Some(self.target_cookie)
            && matches!(fd_identity(fd), Ok(identity) if identity == self.target_identity)
    }

    pub(super) fn target_fd_matches(&self, pid: u32, fd: RawFd) -> bool {
        self.duplicate_target_fd(pid, fd)
            .map(|duplicated| self.matches_target_fd(duplicated.as_raw_fd()))
            .unwrap_or(false)
    }

    pub(super) fn shutdown(&self) {
        if !self.shutdown.swap(true, Ordering::SeqCst) {
            let _ = unsafe { libc::shutdown(self.relay_fd.as_raw_fd(), libc::SHUT_RDWR) };
        }
    }
}

pub(super) fn udp_domain_accepts_destination(domain: i32, dest: Destination) -> bool {
    matches!(
        (domain, dest.ip),
        (libc::AF_INET, IpAddr::V4(_)) | (libc::AF_INET6, _)
    )
}

/// Renders `dest` in the socket's logical address family. A dual-stack AF_INET6
/// socket reaches IPv4 peers, and Linux reports those peers as v4-mapped IPv6
/// addresses, so `getpeername(2)` and every receive source must do the same.
pub(super) fn udp_domain_logical_address(domain: i32, dest: Destination) -> Destination {
    match (domain, dest.ip) {
        (libc::AF_INET6, IpAddr::V4(ip)) => Destination {
            ip: IpAddr::V6(ip.to_ipv6_mapped()),
            port: dest.port,
        },
        _ => dest,
    }
}

/// What a relay needs to know about the injected endpoint it publishes:
/// descriptor identity for staleness checks, `SO_COOKIE` for alias recovery,
/// and the logical domain/protocol the target socket reports.
pub(super) struct RelayTargetInfo {
    pub(super) identity: FdIdentity,
    pub(super) cookie: u64,
    pub(super) domain: i32,
    pub(super) protocol: i32,
}

pub(super) fn start_udp_relay(
    cfg: UdpRelayConfig,
    relay_socket: OwnedFd,
    default_dest: Option<(Destination, UdpRouteKind)>,
    target: RelayTargetInfo,
    stable: bool,
) -> io::Result<UdpRelayHandle> {
    let RelayTargetInfo {
        identity: target_identity,
        cookie: target_cookie,
        domain,
        protocol,
    } = target;
    let relay_fd = Arc::new(relay_socket);
    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel::bounded::<UdpJob>(UDP_JOB_QUEUE_CAPACITY);
    let default_dest = Arc::new(Mutex::new(default_dest));
    let local_bind = Arc::new(Mutex::new(None));
    let pending_sources = Arc::new(Mutex::new(VecDeque::new()));

    let read_fd = Arc::clone(&relay_fd);
    let read_tx = tx.clone();
    let read_default_dest = Arc::clone(&default_dest);
    let read_shutdown = Arc::clone(&shutdown);
    let reader = thread::Builder::new()
        .name("yatht-udp-relay-read".to_string())
        .stack_size(UDP_RELAY_THREAD_STACK_SIZE)
        .spawn(move || {
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
        })?;

    let write_pending_sources = Arc::clone(&pending_sources);
    let write_local_bind = Arc::clone(&local_bind);
    let write_fd = Arc::clone(&relay_fd);
    let write_shutdown = Arc::clone(&shutdown);
    let writer = thread::Builder::new()
        .name("yatht-udp-relay-write".to_string())
        .stack_size(UDP_RELAY_THREAD_STACK_SIZE)
        .spawn(move || {
            let mut dns_tcp = None;
            let mut socks_udp = None;
            let mut direct_udp = None;
            for job in rx {
                if write_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                match forward_udp_job(
                    &cfg,
                    &mut dns_tcp,
                    &mut socks_udp,
                    &mut direct_udp,
                    &write_local_bind,
                    job,
                ) {
                    Ok(Some(response)) => {
                        let mut pending = write_pending_sources.lock().unwrap();
                        // Drop the response if the target is not draining fast
                        // enough. The socketpair send below uses MSG_DONTWAIT, so a
                        // successful send means the datagram is actually queued.
                        if pending.len() >= MAX_PENDING_SOURCES {
                            if cfg.debug {
                                eprintln!("yatht: UDP relay pending queue full, dropping response");
                            }
                            cfg.observability.record_udp_pending_response_dropped();
                            continue;
                        }
                        pending.push_back(response.source);
                        if !send_relay_response(write_fd.as_raw_fd(), &response.payload) {
                            let _ = pending.pop_back();
                            if write_shutdown.load(Ordering::SeqCst) {
                                break;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if cfg.debug {
                            eprintln!("yatht: UDP relay forward failed: {err:#}");
                        }
                    }
                }
            }
        });
    if let Err(err) = writer {
        shutdown.store(true, Ordering::SeqCst);
        let _ = unsafe { libc::shutdown(relay_fd.as_raw_fd(), libc::SHUT_RDWR) };
        drop(reader);
        return Err(err);
    }
    drop(reader);
    drop(writer);

    Ok(UdpRelayHandle {
        tx,
        default_dest,
        local_bind,
        pending_sources,
        relay_fd,
        target_identity,
        target_cookie,
        domain,
        // socket(AF_INET*, SOCK_DGRAM, 0) reports IPPROTO_UDP; normalize the
        // default so the recorded protocol always matches SO_PROTOCOL.
        protocol: if protocol == 0 {
            libc::IPPROTO_UDP
        } else {
            protocol
        },
        stable,
        shutdown,
    })
}

pub(super) fn recv_relay_socket(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
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
pub(super) fn send_relay_response(fd: RawFd, response: &[u8]) -> bool {
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

pub(super) fn forward_udp_job(
    cfg: &UdpRelayConfig,
    dns_tcp: &mut Option<proxy::DnsTcpConnection>,
    socks_udp: &mut Option<proxy::Socks5UdpAssociation>,
    direct_udp: &mut Option<DirectUdpSocket>,
    local_bind: &Mutex<Option<UdpLocalSocket>>,
    job: UdpJob,
) -> Result<Option<UdpRelayResponse>> {
    let deadline = proxy::Deadline::after(cfg.timeout);
    // The route was decided by the notification handler, which has the full
    // routing table. Honour it verbatim so a datagram bound for a direct route
    // is never accidentally tunnelled through the proxy (and vice versa).
    match job.route {
        UdpRouteKind::Dns => forward_dns_tcp(cfg, dns_tcp, &job.payload, deadline).map(|payload| {
            Some(UdpRelayResponse {
                source: job.dest,
                payload,
            })
        }),
        UdpRouteKind::Generic => {
            if socks_udp.is_none() {
                *socks_udp = Some(proxy::Socks5UdpAssociation::connect(&cfg.proxy, deadline)?);
            }
            socks_udp
                .as_mut()
                .expect("SOCKS5 UDP association initialized")
                .send_datagram(job.dest, &job.payload, deadline)
                .map(|response| {
                    response.map(|response| UdpRelayResponse {
                        source: response.source,
                        payload: response.payload,
                    })
                })
        }
        UdpRouteKind::Direct => {
            forward_direct_udp(direct_udp, local_bind, job.dest, &job.payload, cfg.timeout)
        }
    }
}

pub(super) fn forward_dns_tcp(
    cfg: &UdpRelayConfig,
    dns_tcp: &mut Option<proxy::DnsTcpConnection>,
    payload: &[u8],
    deadline: proxy::Deadline,
) -> Result<Vec<u8>> {
    if dns_tcp.is_none() {
        *dns_tcp = Some(proxy::DnsTcpConnection::connect(
            &cfg.proxy,
            cfg.dns_server,
            deadline,
        )?);
    }

    match dns_tcp
        .as_mut()
        .expect("DNS-over-TCP connection initialized")
        .query(payload, deadline)
    {
        Ok(response) => Ok(response),
        Err(first_err) => {
            *dns_tcp = None;
            let mut fresh = proxy::DnsTcpConnection::connect(&cfg.proxy, cfg.dns_server, deadline)
                .with_context(|| format!("reconnect DNS-over-TCP after {first_err:#}"))?;
            let response = fresh.query(payload, deadline)?;
            *dns_tcp = Some(fresh);
            Ok(response)
        }
    }
}

/// Sends a datagram straight to its destination on a plain UDP socket, reusing a
/// cached duplicate of the socket that reserves the relay's local port.
/// Mirrors the single request/response model of the proxy paths: one datagram is
/// read back (within the timeout) so the connected-UDP return path stays fed.
pub(super) fn forward_direct_udp(
    direct_udp: &mut Option<DirectUdpSocket>,
    local_bind: &Mutex<Option<UdpLocalSocket>>,
    dest: Destination,
    payload: &[u8],
    timeout: Duration,
) -> Result<Option<UdpRelayResponse>> {
    let default_bind = Destination {
        ip: if dest.ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        port: 0,
    };
    let (cookie, socket) = {
        let mut bound = local_bind.lock().unwrap();
        if bound.is_none() {
            *bound = Some(UdpLocalSocket {
                socket: UdpSocket::bind(SocketAddr::new(default_bind.ip, 0))?,
                port_locked: false,
            });
        }
        let sock = &bound.as_ref().expect("local port reserved above").socket;
        let cookie = socket_cookie(sock.as_raw_fd()).context("read bound UDP socket cookie")?;
        let socket = if direct_udp
            .as_ref()
            .is_some_and(|state| state.cookie == cookie)
        {
            None
        } else {
            Some(sock.try_clone()?)
        };
        (cookie, socket)
    };
    if let Some(sock) = socket {
        // Clone the reserved socket rather than binding again: it must retain
        // the port reported immediately after bind(0), including dual stack.
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        *direct_udp = Some(DirectUdpSocket {
            sock,
            recv_buf: vec![0_u8; MAX_UDP_PAYLOAD],
            cookie,
        });
    }
    let state = direct_udp
        .as_mut()
        .expect("direct UDP socket initialized above");
    state
        .sock
        .send_to(payload, SocketAddr::new(dest.ip, dest.port))?;

    match state.sock.recv_from(&mut state.recv_buf) {
        Ok((n, source)) => Ok(Some(UdpRelayResponse {
            source: Destination {
                ip: source.ip(),
                port: source.port(),
            },
            payload: state.recv_buf[..n].to_vec(),
        })),
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

pub(super) fn make_relay_pair() -> io::Result<(OwnedFd, OwnedFd)> {
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

pub(super) fn socket_type_and_protocol(pid: u32, fd: RawFd) -> Option<(i32, i32)> {
    let file = duplicate_remote_fd(pid, fd).ok()?;
    Some((
        socket_type_from_fd(file.as_raw_fd())?,
        socket_protocol_from_fd(file.as_raw_fd())?,
    ))
}

pub(super) fn socket_type_from_fd(fd: RawFd) -> Option<i32> {
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

pub(super) fn socket_domain_from_fd(fd: RawFd) -> Option<i32> {
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&domain) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        None
    } else {
        Some(domain)
    }
}

pub(super) fn socket_protocol_from_fd(fd: RawFd) -> Option<i32> {
    let mut protocol: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&protocol) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PROTOCOL,
            (&mut protocol as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        None
    } else {
        Some(protocol)
    }
}

pub(super) fn socket_cookie(fd: RawFd) -> Option<u64> {
    let mut cookie = 0_u64;
    let mut len = std::mem::size_of_val(&cookie) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of_val(&cookie)).then_some(cookie)
}

pub(super) fn inspect_udp_target(pid: u32, fd: RawFd) -> Result<Option<UdpTargetSnapshot>> {
    let target = match duplicate_remote_fd(pid, fd) {
        Ok(target) => target,
        Err(err) if matches!(err.raw_os_error(), Some(libc::EBADF | libc::ENOTSOCK)) => {
            return Ok(None);
        }
        Err(err) => return Err(err).context("duplicate UDP target fd"),
    };
    let Some(protocol) = socket_protocol_from_fd(target.as_raw_fd()) else {
        return Ok(None);
    };
    if protocol != libc::IPPROTO_UDP
        || socket_type_from_fd(target.as_raw_fd()) != Some(libc::SOCK_DGRAM)
    {
        return Ok(None);
    }
    let Some(domain) = socket_domain_from_fd(target.as_raw_fd()) else {
        return Ok(None);
    };
    if !matches!(domain, libc::AF_INET | libc::AF_INET6) {
        return Ok(None);
    }

    let mut flags = read_target_fd_flags(pid, fd);
    flags.status_flags = fd_status_flags(target.as_raw_fd()).unwrap_or(flags.status_flags);
    Ok(Some(UdpTargetSnapshot {
        identity: fd_identity(target.as_raw_fd()).context("stat UDP target fd")?,
        domain,
        protocol,
        flags,
        rcvtimeo: socket_recv_timeout(target.as_raw_fd()),
    }))
}

pub(super) fn fd_identity(fd: RawFd) -> io::Result<FdIdentity> {
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

pub(super) fn fd_status_flags(fd: RawFd) -> io::Result<i32> {
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

#[derive(Default)]
pub(super) struct TargetFdFlags {
    pub(super) status_flags: i32,
    pub(super) newfd_flags: u32,
}

pub(super) fn read_target_fd_flags(pid: u32, fd: RawFd) -> TargetFdFlags {
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
