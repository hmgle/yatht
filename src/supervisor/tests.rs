use std::cell::Cell;
use std::io::{BufRead, BufReader};
use std::process::Stdio;

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
fn remote_fd_duplication_reuses_thread_pidfd() {
    let pid = std::process::id();
    let (_relay, target) = make_relay_pair().unwrap();
    let cache = THREAD_PIDFD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    cache.lock().unwrap().remove(&pid);

    let first = duplicate_remote_fd(pid, target.as_raw_fd()).unwrap();
    let cached_pidfd = cache.lock().unwrap()[&pid].pidfd.as_raw_fd();
    let second = duplicate_remote_fd(pid, target.as_raw_fd()).unwrap();

    assert_eq!(
        fd_identity(first.as_raw_fd()).unwrap(),
        fd_identity(second.as_raw_fd()).unwrap()
    );
    assert_eq!(cache.lock().unwrap()[&pid].pidfd.as_raw_fd(), cached_pidfd);
}

#[test]
fn termination_poll_returns_before_deadline() {
    let attempts = Cell::new(0);
    let value = poll_until_termination(
        Instant::now() + Duration::from_secs(1),
        || {
            let next = attempts.get() + 1;
            attempts.set(next);
            Ok((next == 2).then_some(7_u8))
        },
        "test process",
    )
    .unwrap();

    assert_eq!(value, 7);
    assert_eq!(attempts.get(), 2);
}

#[test]
fn termination_poll_reports_expired_deadline() {
    let attempts = Cell::new(0);
    let result = poll_until_termination::<()>(
        Instant::now(),
        || {
            attempts.set(attempts.get() + 1);
            Ok(None)
        },
        "test process",
    );

    assert_eq!(attempts.get(), 1);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn terminates_adopted_descendant_outside_process_group() {
    set_child_subreaper().unwrap();
    let mut parent = Command::new("sh")
        .arg("-c")
        .arg("setsid sleep 30 & echo $!")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(parent.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let descendant_pid = line.trim().parse::<u32>().unwrap();
    assert!(parent.wait().unwrap().success());

    let adopted = direct_child_pids(std::process::id())
        .unwrap()
        .contains(&descendant_pid);
    // The shell reports the descendant pid before that process execs
    // setsid(1), so poll for the new session instead of sampling the
    // process group once.
    let session_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pgid = unsafe { libc::getpgid(descendant_pid as libc::pid_t) };
        assert!(
            pgid >= 0,
            "descendant {descendant_pid} exited before setsid"
        );
        if pgid == descendant_pid as libc::pid_t {
            break;
        }
        assert!(
            Instant::now() < session_deadline,
            "descendant {descendant_pid} never became a session leader"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let result = terminate_adopted_descendants();

    assert!(adopted, "descendant {descendant_pid} was not adopted");
    result.unwrap();
    assert_eq!(unsafe { libc::kill(descendant_pid as libc::pid_t, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
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
fn udp_relay_capacity_is_globally_bounded() {
    let registry = UdpRelayRegistry::default();
    let mut slots = Vec::new();
    for _ in 0..MAX_UDP_RELAYS {
        slots.push(registry.reserve_relay_slot().unwrap());
    }

    let err = match registry.reserve_relay_slot() {
        Ok(_) => panic!("relay reservation unexpectedly exceeded the limit"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("active UDP relay limit"), "{err}");
    let cause = err.downcast_ref::<io::Error>().unwrap();
    assert_eq!(cause.raw_os_error(), Some(libc::ENOBUFS));
    assert_eq!(udp_send_errno(cause), libc::ENOBUFS);
    assert_eq!(errno_from_io(cause), libc::ENOBUFS);

    drop(slots.pop());
    registry.reserve_relay_slot().unwrap();
}

#[test]
fn stable_relay_reaping_waits_for_the_last_target_alias() {
    relay_reaping_waits_for_the_last_target_alias(true);
}

#[test]
fn lazy_relay_reaping_waits_for_the_last_target_alias() {
    relay_reaping_waits_for_the_last_target_alias(false);
}

fn relay_reaping_waits_for_the_last_target_alias(stable: bool) {
    let registry = UdpRelayRegistry::default();
    let (relay, target) = make_relay_pair().unwrap();
    let alias_fd = unsafe { libc::dup(target.as_raw_fd()) };
    assert!(alias_fd >= 0);
    let alias = unsafe { OwnedFd::from_raw_fd(alias_fd) };
    let (tx, _rx) = udp_job_queues(1);
    let target_identity = fd_identity(target.as_raw_fd()).unwrap();
    let handle = UdpRelayHandle {
        tx,
        state: UdpRelayState::new(relay).unwrap(),
        original_local: None,
        target_identity,
        target_cookie: socket_cookie(target.as_raw_fd()).unwrap(),
        domain: libc::AF_INET,
        protocol: libc::IPPROTO_UDP,
        stable,
    };
    let shutdown = Arc::clone(&handle.shutdown);
    registry.active.store(1, Ordering::Release);
    registry
        .by_cookie
        .lock()
        .unwrap()
        .insert(handle.target_cookie, handle);

    drop(target);
    assert_eq!(registry.reap_closed_relays().unwrap(), 0);
    assert_eq!(registry.active.load(Ordering::Acquire), 1);

    drop(alias);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if registry.reap_closed_relays().unwrap() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "closed AF_UNIX socket remained visible in /proc/net/unix"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(registry.active.load(Ordering::Acquire), 0);
    assert!(shutdown.load(Ordering::SeqCst));
}

#[test]
fn stable_relay_reaping_spares_relays_published_during_a_sweep() {
    // Mirrors `create_stable`'s publish order against a sweep running in
    // parallel. Every target socket stays open for its whole batch, so a
    // relay that gets shut down or loses its admission slot was reaped
    // purely because the sweep's snapshot predates it.
    let registry = Arc::new(UdpRelayRegistry::default());
    let stop = Arc::new(AtomicBool::new(false));
    let reaper_registry = Arc::clone(&registry);
    let reaper_stop = Arc::clone(&stop);
    let reaper = thread::spawn(move || {
        while !reaper_stop.load(Ordering::Relaxed) {
            reaper_registry.reap_closed_relays().unwrap();
        }
    });

    for batch in 0..20_usize {
        let mut live = Vec::new();
        for index in 0..32_usize {
            let mut slot = registry.reserve_relay_slot().unwrap();
            let (relay, target) = make_relay_pair().unwrap();
            let (tx, _rx) = udp_job_queues(1);
            let target_cookie = socket_cookie(target.as_raw_fd()).unwrap();
            let key = relay_key(1, (batch * 32 + index) as RawFd);
            let handle = UdpRelayHandle {
                tx,
                state: UdpRelayState::new(relay).unwrap(),
                original_local: None,
                target_identity: fd_identity(target.as_raw_fd()).unwrap(),
                target_cookie,
                domain: libc::AF_INET,
                protocol: libc::IPPROTO_UDP,
                stable: true,
            };
            let shutdown = Arc::clone(&handle.shutdown);
            registry
                .by_cookie
                .lock()
                .unwrap()
                .insert(target_cookie, handle.clone());
            // Stands in for the ADDFD round trip inside `create_stable`.
            thread::yield_now();
            registry
                .inner
                .lock()
                .unwrap()
                .insert(key, RelayState::Ready(handle));
            slot.commit();
            live.push((target, shutdown, target_cookie, key));
        }

        thread::sleep(Duration::from_millis(5));
        for (_, shutdown, cookie, _) in &live {
            assert!(
                !shutdown.load(Ordering::SeqCst),
                "sweep closed a live stable relay"
            );
            assert!(
                registry.by_cookie.lock().unwrap().contains_key(cookie),
                "sweep dropped a live stable relay"
            );
        }
        assert_eq!(registry.active.load(Ordering::Acquire), live.len());

        for (_, _, cookie, key) in &live {
            registry.by_cookie.lock().unwrap().remove(cookie);
            registry.inner.lock().unwrap().remove(key);
            registry.release_relay_slot();
        }
    }

    stop.store(true, Ordering::Relaxed);
    reaper.join().unwrap();
}

#[test]
fn stable_sweep_cadence_backs_off_only_after_the_grace_window() {
    let mut cadence = StableSweepCadence::default();
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL);

    for _ in 0..STABLE_RELAY_SWEEP_IDLE_GRACE {
        cadence.record_sweep(0);
        assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL);
    }

    cadence.record_sweep(0);
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL * 2);
    cadence.record_sweep(0);
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL * 4);
}

#[test]
fn stable_sweep_cadence_caps_and_restarts() {
    let mut cadence = StableSweepCadence::default();
    for _ in 0..64 {
        cadence.record_sweep(0);
    }
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_MAX_INTERVAL);

    cadence.record_sweep(1);
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL);
}

#[test]
fn udp_relay_reaper_stops_without_waiting_out_its_interval() {
    let registry = Arc::new(UdpRelayRegistry::default());
    let reaper_registry = Arc::clone(&registry);
    let reaper = thread::spawn(move || udp_relay_reaper(reaper_registry, false));

    registry.stop_relay_reaper();
    let start = Instant::now();
    reaper.join().unwrap();

    assert!(
        start.elapsed() < STABLE_RELAY_SWEEP_INTERVAL,
        "reaper did not observe the stop request: {:?}",
        start.elapsed()
    );
}

#[test]
fn publishing_a_relay_shortens_a_backed_off_sweep_wait() {
    let registry = Arc::new(UdpRelayRegistry::default());
    let mut cadence = StableSweepCadence::default();
    for _ in 0..64 {
        cadence.record_sweep(0);
    }
    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_MAX_INTERVAL);

    let publisher_registry = Arc::clone(&registry);
    let publisher = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        publisher_registry.notify_relay_published();
    });

    let start = Instant::now();
    assert!(registry.wait_for_next_relay_sweep(&mut cadence));
    let waited = start.elapsed();
    publisher.join().unwrap();

    assert_eq!(cadence.interval(), STABLE_RELAY_SWEEP_INTERVAL);
    assert!(
        waited < STABLE_RELAY_SWEEP_INTERVAL * 2,
        "a published relay did not shorten the backed-off wait: {waited:?}"
    );
}

#[test]
fn a_steady_publish_rate_cannot_postpone_a_sweep() {
    let registry = Arc::new(UdpRelayRegistry::default());
    let stop = Arc::new(AtomicBool::new(false));
    let publisher_registry = Arc::clone(&registry);
    let publisher_stop = Arc::clone(&stop);
    let publisher = thread::spawn(move || {
        while !publisher_stop.load(Ordering::Relaxed) {
            publisher_registry.notify_relay_published();
            thread::sleep(Duration::from_millis(10));
        }
    });

    let mut cadence = StableSweepCadence::default();
    let start = Instant::now();
    assert!(registry.wait_for_next_relay_sweep(&mut cadence));
    let waited = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    publisher.join().unwrap();

    assert!(
        waited < STABLE_RELAY_SWEEP_INTERVAL * 2,
        "a steady publish rate postponed the sweep: {waited:?}"
    );
}

#[test]
fn fd_replacement_waits_for_relay_creation() {
    let registry = Arc::new(UdpRelayRegistry::default());
    let pid = std::process::id();
    let fd = 9;
    let key = relay_key(pid, fd);
    registry
        .inner
        .lock()
        .unwrap()
        .insert(key, RelayState::Creating);
    let waiter_registry = Arc::clone(&registry);
    let (done_tx, done_rx) = channel::bounded(1);
    thread::spawn(move || {
        waiter_registry.wait_for_creation(pid, fd);
        done_tx.send(()).unwrap();
    });

    assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
    registry.inner.lock().unwrap().remove(&key);
    registry.created.notify_all();
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
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
    assert!(!handle.shutdown.load(Ordering::SeqCst));
}

#[test]
fn close_removes_matching_relay() {
    let registry = UdpRelayRegistry::default();
    let (relay, target) = make_relay_pair().unwrap();
    let (tx, _rx) = udp_job_queues(1);
    let target_cookie = socket_cookie(target.as_raw_fd()).unwrap();
    let handle = UdpRelayHandle {
        tx,
        state: UdpRelayState::new(relay).unwrap(),
        original_local: None,
        target_identity: fd_identity(target.as_raw_fd()).unwrap(),
        target_cookie,
        domain: libc::AF_INET,
        protocol: libc::IPPROTO_UDP,
        stable: false,
    };
    let shutdown = Arc::clone(&handle.shutdown);
    // Production relays remain owned by the cookie index after an fd cache
    // entry is removed, until the last target alias closes.
    registry
        .by_cookie
        .lock()
        .unwrap()
        .insert(target_cookie, handle.clone());
    let key = relay_key(std::process::id(), target.as_raw_fd());
    registry
        .inner
        .lock()
        .unwrap()
        .insert(key, RelayState::Ready(handle));

    registry.remove_for_close(std::process::id(), target.as_raw_fd());

    assert!(!registry.inner.lock().unwrap().contains_key(&key));
    assert!(!shutdown.load(Ordering::SeqCst));
}

#[test]
fn close_range_only_removes_when_fds_are_closed() {
    assert!(close_range_closes_fds(3, 9, 0));
    assert!(!close_range_closes_fds(3, 9, CLOSE_RANGE_UNSHARE));
    assert!(!close_range_closes_fds(9, 3, 0));
    assert!(!close_range_closes_fds(3, 9, CLOSE_RANGE_CLOEXEC));
    assert!(!close_range_closes_fds(3, 9, 1 << 30));
}

#[test]
fn reads_iovec_targets_in_one_batch() {
    let first = [1_u8, 2, 3];
    let second = [4_u8, 5];
    let raw = [
        libc::iovec {
            iov_base: first.as_ptr() as *mut libc::c_void,
            iov_len: first.len(),
        },
        libc::iovec {
            iov_base: second.as_ptr() as *mut libc::c_void,
            iov_len: second.len(),
        },
    ];

    let got =
        read_iovec_targets(std::process::id(), raw.as_ptr() as u64, raw.len() as u64).unwrap();

    assert_eq!(got.len(), 2);
    assert_eq!(got[0].base, first.as_ptr() as u64);
    assert_eq!(got[0].len, first.len());
    assert_eq!(got[1].base, second.as_ptr() as u64);
    assert_eq!(got[1].len, second.len());
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
fn nonblocking_udp_send_reports_full_job_queue() {
    let (relay, target) = make_relay_pair().unwrap();
    let (tx, _rx) = udp_job_queues(1);
    let target_cookie = socket_cookie(target.as_raw_fd()).unwrap();
    let handle = UdpRelayHandle {
        tx,
        state: UdpRelayState::new(relay).unwrap(),
        original_local: None,
        target_identity: fd_identity(target.as_raw_fd()).unwrap(),
        target_cookie,
        domain: libc::AF_INET,
        protocol: libc::IPPROTO_UDP,
        stable: false,
    };
    let dest = Destination {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
    };

    handle
        .send(dest, b"first".to_vec(), UdpRouteKind::Dns, true)
        .unwrap();
    let err = handle
        .send(dest, b"second".to_vec(), UdpRouteKind::Dns, true)
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    // A saturated DNS route must not consume another route's admission slot.
    for route in [UdpRouteKind::Direct, UdpRouteKind::Generic] {
        handle.send(dest, vec![1], route, true).unwrap();
        assert_eq!(
            handle.send(dest, vec![2], route, true).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn blocking_receive_dispatch_wakes_reactor() {
    let (tx, rx) = channel::unbounded();
    let wake_fd = Arc::new(create_eventfd().unwrap());
    let queue = BlockingRecvQueue {
        tx,
        wake_fd: Arc::clone(&wake_fd),
    };

    assert!(queue_blocking_notification(
        &queue,
        -1,
        SeccompNotif::default(),
        Instant::now(),
        false,
    ));
    assert!(rx.try_recv().is_ok());

    let mut pollfd = libc::pollfd {
        fd: wake_fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
    assert_ne!(pollfd.revents & libc::POLLIN, 0);
}

#[test]
fn ready_blocking_receives_run_once_per_relay() {
    let first_relay = FdIdentity { dev: 1, ino: 1 };
    let second_relay = FdIdentity { dev: 1, ino: 2 };
    let first_notif = SeccompNotif {
        id: 1,
        ..SeccompNotif::default()
    };
    let second_notif = SeccompNotif {
        id: 2,
        ..SeccompNotif::default()
    };
    let third_notif = SeccompNotif {
        id: 3,
        ..SeccompNotif::default()
    };
    let mut pending = vec![
        PendingBlockingRecv {
            notif: first_notif,
            relay_fd: create_eventfd().unwrap(),
            relay: first_relay,
            state: BlockingRecvState::default(),
        },
        PendingBlockingRecv {
            notif: second_notif,
            relay_fd: create_eventfd().unwrap(),
            relay: first_relay,
            state: BlockingRecvState::default(),
        },
        PendingBlockingRecv {
            notif: third_notif,
            relay_fd: create_eventfd().unwrap(),
            relay: second_relay,
            state: BlockingRecvState::default(),
        },
    ];
    let pollfds = std::iter::once(libc::pollfd {
        fd: -1,
        events: libc::POLLIN,
        revents: 0,
    })
    .chain(pending.iter().map(|recv| libc::pollfd {
        fd: recv.relay_fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: libc::POLLIN,
    }))
    .collect::<Vec<_>>();
    let mut in_flight = HashSet::new();
    let mut work_backlog = VecDeque::new();

    queue_ready_blocking_recvs(&mut pending, &pollfds, &mut in_flight, &mut work_backlog);

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].notif.id, first_notif.id);
    assert_eq!(in_flight.len(), 2);
    assert_eq!(work_backlog.len(), 2);
    assert_eq!(
        work_backlog
            .iter()
            .filter(|work| work.relay == Some(first_relay))
            .count(),
        1
    );
    assert!(work_backlog
        .iter()
        .any(|work| work.relay == Some(second_relay)));
}

#[test]
fn expired_recvmmsg_receive_reenters_worker_queue() {
    let expired_relay = FdIdentity { dev: 1, ino: 1 };
    let future_relay = FdIdentity { dev: 1, ino: 2 };
    let mut pending = vec![
        PendingBlockingRecv {
            notif: SeccompNotif {
                id: 1,
                ..SeccompNotif::default()
            },
            relay_fd: create_eventfd().unwrap(),
            relay: expired_relay,
            state: BlockingRecvState {
                completed: 0,
                timeout_initialized: true,
                deadline: Some(Instant::now() - Duration::from_millis(1)),
                ..BlockingRecvState::default()
            },
        },
        PendingBlockingRecv {
            notif: SeccompNotif {
                id: 2,
                ..SeccompNotif::default()
            },
            relay_fd: create_eventfd().unwrap(),
            relay: future_relay,
            state: BlockingRecvState {
                completed: 0,
                timeout_initialized: true,
                deadline: Some(Instant::now() + Duration::from_secs(1)),
                ..BlockingRecvState::default()
            },
        },
    ];
    let mut in_flight = HashSet::new();
    let mut work_backlog = VecDeque::new();

    queue_expired_blocking_recvs(&mut pending, &mut in_flight, &mut work_backlog);

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].relay, future_relay);
    assert_eq!(work_backlog.len(), 1);
    assert_eq!(work_backlog[0].relay, Some(expired_relay));
    assert!(in_flight.contains(&expired_relay));
}

#[test]
fn recvmmsg_timeout_controls_reactor_poll_deadline() {
    let relay = FdIdentity { dev: 1, ino: 1 };
    let pending = vec![PendingBlockingRecv {
        notif: SeccompNotif::default(),
        relay_fd: create_eventfd().unwrap(),
        relay,
        state: BlockingRecvState {
            completed: 0,
            timeout_initialized: true,
            deadline: Some(Instant::now() + Duration::from_secs(10)),
            ..BlockingRecvState::default()
        },
    }];

    let timeout = blocking_recv_poll_timeout(&pending, &HashSet::new(), false);

    assert_eq!(timeout, BLOCKING_RECV_POLL_INTERVAL_MS);
    assert_eq!(
        blocking_recv_poll_timeout(&pending, &HashSet::new(), true),
        0
    );
}

#[test]
fn socket_recv_timeout_reads_target_configured_value() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(socket_recv_timeout(socket.as_raw_fd()), None);

    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let timeout = socket_recv_timeout(socket.as_raw_fd()).unwrap();
    assert!(timeout >= Duration::from_millis(500));
    assert!(timeout <= Duration::from_millis(600));

    socket.set_read_timeout(None).unwrap();
    assert_eq!(socket_recv_timeout(socket.as_raw_fd()), None);
}

#[test]
fn next_deadline_prefers_earliest_pending_timer() {
    let now = Instant::now();
    let earlier = now + Duration::from_millis(100);
    let later = now + Duration::from_millis(200);
    let mut state = BlockingRecvState::default();
    assert_eq!(state.next_deadline(), None);

    state.deadline = Some(later);
    assert_eq!(state.next_deadline(), Some(later));

    state.rcvtimeo_deadline = Some(earlier);
    assert_eq!(state.next_deadline(), Some(earlier));

    state.deadline = None;
    assert_eq!(state.next_deadline(), Some(earlier));
}

#[test]
fn reset_rcvtimeo_deadline_rearms_only_with_a_timeout() {
    let mut state = BlockingRecvState::default();
    state.reset_rcvtimeo_deadline();
    assert_eq!(state.rcvtimeo_deadline, None);

    state.rcvtimeo = Some(Duration::from_millis(250));
    let before = Instant::now();
    state.reset_rcvtimeo_deadline();
    assert!(state.rcvtimeo_deadline.unwrap() >= before + Duration::from_millis(250));
}

#[test]
fn arm_rcvtimeo_uses_notification_received_at() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let received_at = Instant::now() - Duration::from_secs(2);
    let mut state = BlockingRecvState {
        received_at: Some(received_at),
        ..BlockingRecvState::default()
    };

    state.arm_rcvtimeo(socket.as_raw_fd());

    assert!(state
        .rcvtimeo_deadline
        .is_some_and(|deadline| deadline < Instant::now() - Duration::from_secs(1)));
}

#[test]
fn parses_x86_64_recvmmsg_timeout() {
    let mut raw = [0_u8; X86_64_TIMESPEC_SIZE];
    raw[0..8].copy_from_slice(&2_i64.to_ne_bytes());
    raw[8..16].copy_from_slice(&3_i64.to_ne_bytes());

    assert_eq!(parse_recvmmsg_timeout(&raw).unwrap(), Duration::new(2, 3));

    raw[0..8].copy_from_slice(&(-1_i64).to_ne_bytes());
    assert_eq!(
        parse_recvmmsg_timeout(&raw).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    raw[0..8].copy_from_slice(&0_i64.to_ne_bytes());
    raw[8..16].copy_from_slice(&1_000_000_000_i64.to_ne_bytes());
    assert_eq!(
        parse_recvmmsg_timeout(&raw).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn explicit_nonblocking_receives_skip_blocking_reactor() {
    let mut recvfrom = SeccompNotif::default();
    recvfrom.data.nr = libc::SYS_recvfrom as i32;
    assert!(is_blocking_recv_notification(&recvfrom));
    recvfrom.data.args[3] = libc::MSG_DONTWAIT as u64;
    assert!(!is_blocking_recv_notification(&recvfrom));

    let mut recvmsg = SeccompNotif::default();
    recvmsg.data.nr = libc::SYS_recvmsg as i32;
    assert!(is_blocking_recv_notification(&recvmsg));
    recvmsg.data.args[2] = libc::MSG_DONTWAIT as u64;
    assert!(!is_blocking_recv_notification(&recvmsg));

    let mut recvmmsg = SeccompNotif::default();
    recvmmsg.data.nr = libc::SYS_recvmmsg as i32;
    assert!(is_blocking_recv_notification(&recvmmsg));
    recvmmsg.data.args[3] = libc::MSG_DONTWAIT as u64;
    assert!(!is_blocking_recv_notification(&recvmmsg));

    let mut sendmsg = SeccompNotif::default();
    sendmsg.data.nr = libc::SYS_sendmsg as i32;
    assert!(!is_blocking_recv_notification(&sendmsg));
}

#[test]
fn blocking_receive_attempt_can_defer_without_polling() {
    let (_relay, target) = make_relay_pair().unwrap();
    let pending = Mutex::new(VecDeque::new());

    let err = match recv_from_relay_fd(-1, 0, target.as_raw_fd(), 1, 0, &pending, false) {
        Ok(_) => panic!("quiet relay unexpectedly received a datagram"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
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
    let (tx, _rx) = udp_job_queues(1);
    let target_cookie = socket_cookie(target.as_raw_fd()).unwrap();
    UdpRelayHandle {
        tx,
        state: UdpRelayState::new(relay).unwrap(),
        original_local: None,
        target_identity: fd_identity(target.as_raw_fd()).unwrap(),
        target_cookie,
        domain: libc::AF_INET,
        protocol: libc::IPPROTO_UDP,
        stable: false,
    }
}

fn test_config(enable_dns: bool) -> EffectiveConfig {
    EffectiveConfig {
        proxy: crate::config::ProxyConfig::Socks5 {
            endpoint: crate::config::ProxyEndpoint::new("127.0.0.1:1080".to_string()),
            username: None,
            password: None,
        },
        bypass_local: true,
        bypass_cidrs: Vec::new(),
        proxy_cidrs: Vec::new(),
        connect_timeout: Duration::from_secs(10),
        enable_dns,
        enable_udp: false,
        dns_server: enable_dns.then(|| SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53))),
        udp_socket_mode: UdpSocketMode::Lazy,
        debug: false,
        metrics_file: None,
        command: Vec::new(),
    }
}

#[test]
fn udp_send_errors_preserve_local_failures() {
    for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::EADDRINUSE,
        libc::ENOMEM,
        libc::ENOBUFS,
        libc::EPIPE,
    ] {
        assert_eq!(udp_send_errno(&io::Error::from_raw_os_error(errno)), errno);
    }
    assert_eq!(
        udp_send_errno(&io::Error::from(io::ErrorKind::WouldBlock)),
        libc::EAGAIN
    );
    assert_eq!(
        udp_send_errno(&io::Error::new(io::ErrorKind::BrokenPipe, "worker exited")),
        libc::ECONNREFUSED
    );
}

#[test]
fn idle_udp_workers_retire_when_last_handle_is_dropped() {
    udp_workers_retire_when_last_handle_is_dropped(false);
}

#[test]
fn active_udp_workers_retire_when_last_handle_is_dropped() {
    udp_workers_retire_when_last_handle_is_dropped(true);
}

fn udp_workers_retire_when_last_handle_is_dropped(send_datagram: bool) {
    let (relay, target) = make_relay_pair().unwrap();
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    set_socket_recv_timeout(target.as_raw_fd(), Duration::from_secs(3)).unwrap();
    let dest = Destination {
        ip: echo.local_addr().unwrap().ip(),
        port: echo.local_addr().unwrap().port(),
    };
    let handle = start_udp_relay(
        build_udp_relay_config(&test_config(false), Observability::default()),
        relay,
        Some((dest, UdpRouteKind::Direct)),
        RelayTargetInfo {
            identity: fd_identity(target.as_raw_fd()).unwrap(),
            cookie: socket_cookie(target.as_raw_fd()).unwrap(),
            domain: libc::AF_INET,
            protocol: libc::IPPROTO_UDP,
        },
        false,
    )
    .unwrap();
    let shutdown = Arc::clone(&handle.shutdown);
    let relay_fd = Arc::downgrade(&handle.relay_fd);
    let remaining = handle.clone();
    drop(handle);
    assert!(!shutdown.load(Ordering::SeqCst));

    if send_datagram {
        // Exercise both workers through the connected socket, then leave
        // them waiting for more input with a live target-side endpoint.
        assert!(send_relay_response(target.as_raw_fd(), b"ping"));
        let mut payload = [0; 4];
        let (n, peer) = echo.recv_from(&mut payload).unwrap();
        assert_eq!(&payload[..n], b"ping");
        echo.send_to(b"pong", peer).unwrap();
        assert_eq!(
            recv_relay_socket(target.as_raw_fd(), &mut payload).unwrap(),
            4
        );
        assert_eq!(&payload, b"pong");
    }

    // No explicit shutdown and no target-side close: dropping the final
    // owner must wake poll and recv and release both workers' fd references.
    drop(remaining);
    assert!(shutdown.load(Ordering::SeqCst));
    let deadline = Instant::now() + Duration::from_secs(3);
    while relay_fd.upgrade().is_some() {
        assert!(
            Instant::now() < deadline,
            "UDP workers retained the relay fd"
        );
        thread::sleep(Duration::from_millis(1));
    }
    drop(target);
}

#[test]
fn udp_worker_counts_failed_jobs_without_debug_logging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metrics.jsonl");
    let metrics = ObservabilityRuntime::start(Some(&path)).unwrap();
    let mut cfg = build_udp_relay_config(&test_config(false), metrics.observability());
    // Generic UDP cannot use HTTP, so this deterministically fails setup.
    cfg.proxy = crate::config::ProxyConfig::Http {
        endpoint: crate::config::ProxyEndpoint::new("127.0.0.1:9".into()),
    };
    let (relay, target) = make_relay_pair().unwrap();
    set_socket_recv_timeout(target.as_raw_fd(), Duration::from_secs(3)).unwrap();
    let mut handle = test_relay_handle();
    handle.state = UdpRelayState::new(relay).unwrap();
    let (tx, rx) = udp_job_queues(16);
    handle.tx = tx;
    let worker_handle = handle.state.io.clone();
    let worker = thread::spawn(move || relay_io::udp_relay_io(cfg, worker_handle, rx));
    let dest = Destination {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 9,
    };
    handle
        .send(dest, vec![1], UdpRouteKind::Generic, false)
        .unwrap();
    handle
        .send(
            Destination { port: 0, ..dest },
            vec![2],
            UdpRouteKind::Direct,
            false,
        )
        .unwrap();
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    handle
        .send(
            Destination {
                port: echo.local_addr().unwrap().port(),
                ..dest
            },
            vec![3],
            UdpRouteKind::Direct,
            false,
        )
        .unwrap();
    let mut payload = [0; 1];
    let (_, peer) = echo.recv_from(&mut payload).unwrap();
    assert_eq!(payload, [3]);
    echo.send_to(&payload, peer).unwrap();
    assert_eq!(
        recv_relay_socket(target.as_raw_fd(), &mut payload).unwrap(),
        1
    );
    handle.shutdown();
    worker.join().unwrap();
    metrics.finish().unwrap();
    let contents = fs::read_to_string(path).unwrap();
    let summary: serde_json::Value =
        serde_json::from_str(contents.lines().last().unwrap()).unwrap();
    assert_eq!(summary["udp_dropped_jobs"], 2);
    assert_eq!(summary["udp_dropped_pending_responses"], 0);
}
