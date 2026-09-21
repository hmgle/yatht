use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn notification_loop(
    listener_fd: Arc<OwnedFd>,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
    tcp_broker: TcpBroker,
    warm_pool: Option<Arc<WarmSessionPool>>,
    failure: Arc<NotificationFailure>,
    observability: Observability,
    worker_count: usize,
) {
    let (tx, rx) = channel::bounded::<QueuedNotification>(
        worker_count.saturating_mul(NOTIFICATION_QUEUE_PER_WORKER),
    );
    let mut worker_threads = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let worker_rx = rx.clone();
        let worker_listener_fd = Arc::clone(&listener_fd);
        let worker_cfg = Arc::clone(&cfg);
        let worker_relays = Arc::clone(&relays);
        let worker_tcp_broker = tcp_broker.clone();
        let worker_warm_pool = warm_pool.clone();
        let worker_failure = Arc::clone(&failure);
        let worker_observability = observability.clone();
        worker_threads.push(thread::spawn(move || {
            notification_worker(
                worker_listener_fd,
                worker_rx,
                worker_cfg,
                worker_relays,
                worker_tcp_broker,
                worker_warm_pool,
                worker_failure,
                worker_observability,
            )
        }));
    }
    let mut reaper_thread = None;
    if cfg.enable_udp || cfg.enable_dns {
        let reaper_relays = Arc::clone(&relays);
        let reaper_debug = cfg.debug;
        match thread::Builder::new()
            .name("yatht-udp-reap".to_string())
            .spawn(move || udp_relay_reaper(reaper_relays, reaper_debug))
        {
            Ok(thread) => reaper_thread = Some(thread),
            Err(err) => {
                failure.report("spawn stable UDP relay reaper", err);
                drop(tx);
                join_notification_workers(worker_threads, &failure);
                return;
            }
        }
    }

    let mut blocking_thread = None;
    let blocking_queue = if cfg.enable_dns || cfg.enable_udp {
        let (blocking_tx, blocking_rx) = channel::unbounded::<BlockingRecvNotification>();
        let wake_fd = match create_eventfd() {
            Ok(fd) => Arc::new(fd),
            Err(err) => {
                failure.report("create blocking receive wake fd", err);
                drop(tx);
                relays.stop_relay_reaper();
                join_notification_workers(worker_threads, &failure);
                join_udp_relay_reaper(reaper_thread, &failure);
                return;
            }
        };
        let reactor_listener_fd = Arc::clone(&listener_fd);
        let reactor_relays = Arc::clone(&relays);
        let reactor_failure = Arc::clone(&failure);
        let loop_failure = Arc::clone(&failure);
        let reactor_wake_fd = Arc::clone(&wake_fd);
        blocking_thread = Some(thread::spawn(move || {
            if std::panic::catch_unwind(|| {
                blocking_recv_reactor(
                    reactor_listener_fd,
                    blocking_rx,
                    reactor_wake_fd,
                    reactor_relays,
                    reactor_failure,
                    worker_count,
                )
            })
            .is_err()
            {
                loop_failure.report(
                    "blocking receive reactor panicked",
                    io::Error::other("blocking receive reactor panicked"),
                );
            }
        }));
        Some(BlockingRecvQueue {
            tx: blocking_tx,
            wake_fd,
        })
    } else {
        None
    };

    'notifications: loop {
        let listener_raw_fd = listener_fd.as_raw_fd();
        match seccomp::notif_recv(listener_raw_fd) {
            Ok(notif) => {
                if is_blocking_recv_notification(&notif) {
                    if let Some(blocking_queue) = &blocking_queue {
                        if !queue_blocking_notification(
                            blocking_queue,
                            listener_raw_fd,
                            notif,
                            Instant::now(),
                            cfg.debug,
                        ) {
                            if !report_thread_notification_error(
                                &failure,
                                "respond to notification",
                            ) {
                                failure.report(
                                    "blocking receive reactor stopped",
                                    io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "blocking receive queue disconnected",
                                    ),
                                );
                            }
                            break 'notifications;
                        }
                        if report_thread_notification_error(&failure, "respond to notification") {
                            break 'notifications;
                        }
                        continue;
                    }
                }
                let queued = QueuedNotification {
                    notif,
                    received_at: Instant::now(),
                    observability: observability.clone(),
                };
                if !try_queue_notification(&tx, listener_raw_fd, queued, cfg.debug, "notification")
                {
                    if !report_thread_notification_error(&failure, "respond to notification") {
                        failure.report(
                            "notification workers stopped",
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "notification queue disconnected",
                            ),
                        );
                    }
                    break 'notifications;
                }
                if report_thread_notification_error(&failure, "respond to notification") {
                    break 'notifications;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                if failure.shutting_down.load(Ordering::Acquire) {
                    break 'notifications;
                }
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(err) => {
                if cfg.debug {
                    eprintln!("yatht: notification loop stopped: {err}");
                }
                failure.report("receive seccomp notification", err);
                break 'notifications;
            }
        }
    }
    drop(tx);
    drop(blocking_queue);
    relays.stop_relay_reaper();
    join_notification_workers(worker_threads, &failure);
    if blocking_thread.is_some_and(|thread| thread.join().is_err()) {
        failure.report(
            "blocking receive reactor panicked",
            io::Error::other("blocking receive reactor panicked"),
        );
    }
    join_udp_relay_reaper(reaper_thread, &failure);
}

pub(super) fn join_udp_relay_reaper(
    reaper_thread: Option<thread::JoinHandle<()>>,
    failure: &NotificationFailure,
) {
    if reaper_thread.is_some_and(|thread| thread.join().is_err()) {
        failure.report(
            "stable UDP relay reaper panicked",
            io::Error::other("stable UDP relay reaper panicked"),
        );
    }
}

pub(super) fn join_notification_workers(
    worker_threads: Vec<thread::JoinHandle<()>>,
    failure: &NotificationFailure,
) {
    for worker in worker_threads {
        if worker.join().is_err() {
            failure.report(
                "seccomp notification worker panicked",
                io::Error::other("notification worker panicked"),
            );
        }
    }
}

pub(super) fn try_queue_notification(
    tx: &channel::Sender<QueuedNotification>,
    listener_fd: RawFd,
    queued: QueuedNotification,
    debug: bool,
    queue_name: &str,
) -> bool {
    queued.observability.notification_queued();
    match tx.try_send(queued) {
        Ok(()) => true,
        Err(channel::TrySendError::Full(queued)) => {
            queued.observability.notification_queue_full();
            if should_block_when_queue_full(&queued.notif) {
                return queue_notification_blocking(tx, listener_fd, queued, debug, queue_name);
            }
            queued.observability.notification_dequeued();
            if debug {
                eprintln!("yatht: {queue_name} queue full");
            }
            seccomp::send_errno(listener_fd, queued.notif.id, libc::EAGAIN);
            true
        }
        Err(channel::TrySendError::Disconnected(queued)) => {
            queued.observability.notification_dequeued();
            if debug {
                eprintln!("yatht: {queue_name} workers stopped");
            }
            seccomp::send_errno(listener_fd, queued.notif.id, libc::EIO);
            false
        }
    }
}

pub(super) fn should_block_when_queue_full(notif: &SeccompNotif) -> bool {
    matches!(
        notif.data.nr as libc::c_long,
        libc::SYS_connect
            | libc::SYS_close
            | libc::SYS_close_range
            | libc::SYS_dup2
            | libc::SYS_dup3
    )
}

pub(super) fn queue_notification_blocking(
    tx: &channel::Sender<QueuedNotification>,
    listener_fd: RawFd,
    queued: QueuedNotification,
    debug: bool,
    queue_name: &str,
) -> bool {
    match tx.send(queued) {
        Ok(()) => true,
        Err(channel::SendError(queued)) => {
            queued.observability.notification_dequeued();
            if debug {
                eprintln!("yatht: {queue_name} workers stopped");
            }
            seccomp::send_errno(listener_fd, queued.notif.id, libc::EIO);
            false
        }
    }
}

pub(super) fn queue_blocking_notification(
    queue: &BlockingRecvQueue,
    listener_fd: RawFd,
    notif: SeccompNotif,
    received_at: Instant,
    debug: bool,
) -> bool {
    let queued = BlockingRecvNotification { notif, received_at };
    match queue.tx.send(queued) {
        Ok(()) => {
            wake_eventfd(queue.wake_fd.as_raw_fd());
            true
        }
        Err(channel::SendError(notif)) => {
            if debug {
                eprintln!("yatht: blocking recv reactor stopped");
            }
            seccomp::send_errno(listener_fd, notif.notif.id, libc::EIO);
            false
        }
    }
}

pub(super) fn create_eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub(super) fn wake_eventfd(fd: RawFd) {
    let value = 1_u64;
    let rc = unsafe {
        libc::write(
            fd,
            (&value as *const u64).cast(),
            std::mem::size_of_val(&value),
        )
    };
    // A failed or saturated write is harmless: the reactor also wakes on its
    // bounded validity-check interval and drains the notification channel.
    let _ = rc;
}

pub(super) fn drain_eventfd(fd: RawFd) -> io::Result<()> {
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

#[allow(clippy::too_many_arguments)]
pub(super) fn notification_worker(
    listener_fd: Arc<OwnedFd>,
    rx: channel::Receiver<QueuedNotification>,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
    tcp_broker: TcpBroker,
    warm_pool: Option<Arc<WarmSessionPool>>,
    failure: Arc<NotificationFailure>,
    observability: Observability,
) {
    loop {
        let queued = rx.recv();
        let Ok(queued) = queued else {
            return;
        };
        queued.observability.notification_dequeued();
        let queue_wait = queued.received_at.elapsed();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_notification(
                listener_fd.as_raw_fd(),
                queued.notif,
                Arc::clone(&cfg),
                Arc::clone(&relays),
                tcp_broker.clone(),
                warm_pool.clone(),
                observability.clone(),
                queue_wait,
            );
        }))
        .is_err()
        {
            failure.report(
                "seccomp notification worker panicked",
                io::Error::other("notification worker panicked"),
            );
            return;
        }
        if report_thread_notification_error(&failure, "respond to seccomp notification") {
            return;
        }
    }
}

pub(super) fn report_thread_notification_error(
    failure: &NotificationFailure,
    context: &str,
) -> bool {
    let Some(err) = seccomp::take_notification_error() else {
        return false;
    };
    failure.report(context, err);
    true
}

pub(super) fn notification_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get().saturating_mul(2))
        .unwrap_or(4)
        .clamp(4, MAX_NOTIFICATION_WORKERS)
}

pub(super) fn is_blocking_recv_notification(notif: &SeccompNotif) -> bool {
    let flags = match notif.data.nr as libc::c_long {
        libc::SYS_recvfrom => notif.data.args[3] as i32,
        libc::SYS_recvmsg => notif.data.args[2] as i32,
        libc::SYS_recvmmsg => notif.data.args[3] as i32,
        _ => return false,
    };
    flags & libc::MSG_DONTWAIT == 0
}

pub(super) fn blocking_recv_worker(
    listener_fd: Arc<OwnedFd>,
    rx: channel::Receiver<BlockingRecvWork>,
    completion_tx: channel::Sender<BlockingRecvCompletion>,
    wake_fd: Arc<OwnedFd>,
    relays: Arc<UdpRelayRegistry>,
    failure: Arc<NotificationFailure>,
) {
    while let Ok(work) = rx.recv() {
        let handling = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_recv_notification_once(
                listener_fd.as_raw_fd(),
                work.notif,
                Arc::clone(&relays),
                false,
                work.state,
            )
        })) {
            Ok(handling) => handling,
            Err(_) => {
                failure.report(
                    "blocking receive worker panicked",
                    io::Error::other("blocking receive worker panicked"),
                );
                return;
            }
        };
        if report_thread_notification_error(&failure, "respond to blocking UDP receive") {
            return;
        }
        if completion_tx
            .send(BlockingRecvCompletion { work, handling })
            .is_err()
        {
            return;
        }
        wake_eventfd(wake_fd.as_raw_fd());
    }
}

pub(super) fn send_blocking_recv_poll_error(
    listener_fd: RawFd,
    notif_id: u64,
    relay_fd: RawFd,
    revents: libc::c_short,
) {
    let err = if revents & libc::POLLNVAL != 0 {
        io::Error::from_raw_os_error(libc::EBADF)
    } else {
        socket_error(relay_fd).unwrap_or_else(|| io::Error::from_raw_os_error(libc::ECONNRESET))
    };
    send_recv_error(listener_fd, notif_id, &err);
}

pub(super) fn queue_ready_blocking_recvs(
    pending: &mut Vec<PendingBlockingRecv>,
    pollfds: &[libc::pollfd],
    in_flight: &mut HashSet<FdIdentity>,
    work_backlog: &mut VecDeque<BlockingRecvWork>,
) {
    let terminal_events = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
    let mut index = pending.len();
    while index > 0 {
        index -= 1;
        let revents = pollfds[index + 1].revents;
        if revents == 0 || in_flight.contains(&pending[index].relay) {
            continue;
        }

        let pending_recv = pending.swap_remove(index);
        in_flight.insert(pending_recv.relay);
        work_backlog.push_back(BlockingRecvWork {
            notif: pending_recv.notif,
            relay: Some(pending_recv.relay),
            terminal_revents: revents & terminal_events,
            state: pending_recv.state,
        });
    }
}

pub(super) fn queue_expired_blocking_recvs(
    pending: &mut Vec<PendingBlockingRecv>,
    in_flight: &mut HashSet<FdIdentity>,
    work_backlog: &mut VecDeque<BlockingRecvWork>,
) {
    let now = Instant::now();
    let mut index = pending.len();
    while index > 0 {
        index -= 1;
        let recv = &pending[index];
        if in_flight.contains(&recv.relay)
            || recv
                .state
                .next_deadline()
                .is_none_or(|deadline| deadline > now)
        {
            continue;
        }
        let pending_recv = pending.swap_remove(index);
        in_flight.insert(pending_recv.relay);
        work_backlog.push_back(BlockingRecvWork {
            notif: pending_recv.notif,
            relay: Some(pending_recv.relay),
            terminal_revents: 0,
            state: pending_recv.state,
        });
    }
}

pub(super) fn blocking_recv_poll_timeout(
    pending: &[PendingBlockingRecv],
    in_flight: &HashSet<FdIdentity>,
    channels_may_have_more: bool,
) -> libc::c_int {
    if channels_may_have_more {
        return 0;
    }
    let now = Instant::now();
    let Some(until_deadline) = pending
        .iter()
        .filter(|recv| !in_flight.contains(&recv.relay))
        .filter_map(|recv| recv.state.next_deadline())
        .map(|deadline| deadline.saturating_duration_since(now))
        .min()
    else {
        return BLOCKING_RECV_POLL_INTERVAL_MS;
    };
    if until_deadline.is_zero() {
        return 0;
    }
    until_deadline
        .as_millis()
        .clamp(1, BLOCKING_RECV_POLL_INTERVAL_MS as u128) as libc::c_int
}

/// Owns readiness and pending-notification state without performing payload
/// copies. Quiet sockets stay in the poll set while ready receives complete in
/// a bounded worker pool, preserving liveness and parallelism across relays.
pub(super) fn blocking_recv_reactor(
    listener_fd: Arc<OwnedFd>,
    rx: channel::Receiver<BlockingRecvNotification>,
    wake_fd: Arc<OwnedFd>,
    relays: Arc<UdpRelayRegistry>,
    failure: Arc<NotificationFailure>,
    worker_count: usize,
) {
    let (work_tx, work_rx) = channel::bounded::<BlockingRecvWork>(
        worker_count.saturating_mul(NOTIFICATION_QUEUE_PER_WORKER),
    );
    let (completion_tx, completion_rx) = channel::unbounded::<BlockingRecvCompletion>();
    let mut worker_threads = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let worker_listener_fd = Arc::clone(&listener_fd);
        let worker_rx = work_rx.clone();
        let worker_completion_tx = completion_tx.clone();
        let worker_wake_fd = Arc::clone(&wake_fd);
        let worker_relays = Arc::clone(&relays);
        let worker_failure = Arc::clone(&failure);
        worker_threads.push(thread::spawn(move || {
            blocking_recv_worker(
                worker_listener_fd,
                worker_rx,
                worker_completion_tx,
                worker_wake_fd,
                worker_relays,
                worker_failure,
            )
        }));
    }
    drop(completion_tx);

    let mut pending = Vec::<PendingBlockingRecv>::new();
    let mut work_backlog = VecDeque::<BlockingRecvWork>::new();
    let mut in_flight = HashSet::<FdIdentity>::new();
    let validity_interval = Duration::from_millis(BLOCKING_RECV_POLL_INTERVAL_MS as u64);
    let mut last_validity_sweep = Instant::now();
    let mut channels_may_have_more = false;
    let mut pollfds = Vec::<libc::pollfd>::new();

    'reactor: loop {
        pollfds.clear();
        pollfds.reserve(pending.len() + 1);
        pollfds.push(libc::pollfd {
            fd: wake_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        pollfds.extend(pending.iter().map(|recv| libc::pollfd {
            fd: if in_flight.contains(&recv.relay) {
                -1
            } else {
                recv.relay_fd.as_raw_fd()
            },
            events: libc::POLLIN,
            revents: 0,
        }));

        let timeout = blocking_recv_poll_timeout(&pending, &in_flight, channels_may_have_more);
        let rc =
            unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            failure.report("poll blocking UDP receives", err);
            break 'reactor;
        }

        if pollfds[0].revents & libc::POLLIN != 0 {
            if let Err(err) = drain_eventfd(wake_fd.as_raw_fd()) {
                failure.report("drain blocking receive wake fd", err);
                break 'reactor;
            }
        }

        queue_ready_blocking_recvs(&mut pending, &pollfds, &mut in_flight, &mut work_backlog);
        queue_expired_blocking_recvs(&mut pending, &mut in_flight, &mut work_backlog);

        if last_validity_sweep.elapsed() >= validity_interval {
            let mut index = pending.len();
            while index > 0 {
                index -= 1;
                match seccomp::notif_id_valid_result(
                    listener_fd.as_raw_fd(),
                    pending[index].notif.id,
                ) {
                    Ok(true) => continue,
                    Ok(false) => {
                        pending.swap_remove(index);
                        continue;
                    }
                    Err(err) => {
                        failure.report("validate blocking UDP receive", err);
                        break 'reactor;
                    }
                }
            }
            last_validity_sweep = Instant::now();
        }

        let mut completed = 0;
        while completed < BLOCKING_RECV_CHANNEL_BUDGET {
            let completion = match completion_rx.try_recv() {
                Ok(completion) => completion,
                Err(channel::TryRecvError::Empty) => break,
                Err(channel::TryRecvError::Disconnected) => {
                    failure.report(
                        "blocking receive workers stopped",
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "blocking receive completion queue disconnected",
                        ),
                    );
                    break 'reactor;
                }
            };
            completed += 1;
            if let Some(relay) = completion.work.relay {
                in_flight.remove(&relay);
            }
            match completion.handling {
                RecvHandling::Completed => {}
                RecvHandling::Deferred {
                    relay_fd,
                    relay,
                    state,
                } => {
                    if completion.work.terminal_revents != 0 {
                        if state.completed == 0 {
                            send_blocking_recv_poll_error(
                                listener_fd.as_raw_fd(),
                                completion.work.notif.id,
                                relay_fd.as_raw_fd(),
                                completion.work.terminal_revents,
                            );
                        } else {
                            if completion.work.notif.data.nr as libc::c_long == libc::SYS_recvmmsg {
                                send_recvmmsg_result_or_errno(
                                    listener_fd.as_raw_fd(),
                                    &completion.work.notif,
                                    &state,
                                    None,
                                    false,
                                );
                            } else {
                                seccomp::send_value(
                                    listener_fd.as_raw_fd(),
                                    completion.work.notif.id,
                                    state.completed as i64,
                                );
                            }
                        }
                    } else {
                        pending.push(PendingBlockingRecv {
                            notif: completion.work.notif,
                            relay_fd,
                            relay,
                            state,
                        });
                    }
                }
            }
            if report_thread_notification_error(&failure, "respond to blocking UDP receive") {
                break 'reactor;
            }
        }

        let mut received = 0;
        while received < BLOCKING_RECV_CHANNEL_BUDGET {
            match rx.try_recv() {
                Ok(queued) => work_backlog.push_back(BlockingRecvWork {
                    notif: queued.notif,
                    relay: None,
                    terminal_revents: 0,
                    state: BlockingRecvState {
                        received_at: Some(queued.received_at),
                        ..BlockingRecvState::default()
                    },
                }),
                Err(channel::TryRecvError::Empty) => break,
                Err(channel::TryRecvError::Disconnected) => break 'reactor,
            }
            received += 1;
        }

        let mut dispatched = 0;
        while dispatched < BLOCKING_RECV_CHANNEL_BUDGET {
            let Some(work) = work_backlog.pop_front() else {
                break;
            };
            match work_tx.try_send(work) {
                Ok(()) => dispatched += 1,
                Err(channel::TrySendError::Full(work)) => {
                    work_backlog.push_front(work);
                    break;
                }
                Err(channel::TrySendError::Disconnected(_)) => {
                    failure.report(
                        "blocking receive workers stopped",
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "blocking receive work queue disconnected",
                        ),
                    );
                    break 'reactor;
                }
            }
        }

        channels_may_have_more =
            completed == BLOCKING_RECV_CHANNEL_BUDGET || received == BLOCKING_RECV_CHANNEL_BUDGET;
    }
    drop(work_tx);
    for worker in worker_threads {
        if worker.join().is_err() {
            failure.report(
                "blocking receive worker panicked",
                io::Error::other("blocking receive worker panicked"),
            );
        }
    }
}

pub(super) fn handle_recv_notification_once(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
    wait_for_readable: bool,
    state: BlockingRecvState,
) -> RecvHandling {
    match notif.data.nr as libc::c_long {
        libc::SYS_recvfrom => {
            handle_recvfrom_once(listener_fd, notif, relays, wait_for_readable, state)
        }
        libc::SYS_recvmsg => {
            handle_recvmsg_once(listener_fd, notif, relays, wait_for_readable, state)
        }
        libc::SYS_recvmmsg => handle_recvmmsg_once(listener_fd, notif, relays, state),
        _ => {
            seccomp::send_continue(listener_fd, notif.id);
            RecvHandling::Completed
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_notification(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
    tcp_broker: TcpBroker,
    warm_pool: Option<Arc<WarmSessionPool>>,
    observability: Observability,
    queue_wait: Duration,
) {
    match notif.data.nr as libc::c_long {
        libc::SYS_socket => handle_socket(listener_fd, notif, cfg, relays),
        libc::SYS_bind => handle_bind(listener_fd, notif, relays),
        libc::SYS_getsockname => handle_getsockname(listener_fd, notif, relays),
        libc::SYS_getpeername => handle_getpeername(listener_fd, notif, relays),
        libc::SYS_getsockopt => handle_getsockopt(listener_fd, notif, relays),
        libc::SYS_connect => handle_connect(
            listener_fd,
            notif,
            cfg,
            relays,
            tcp_broker,
            warm_pool,
            observability,
            queue_wait,
        ),
        libc::SYS_sendto => handle_sendto(listener_fd, notif, cfg, relays),
        libc::SYS_sendmsg => handle_sendmsg(listener_fd, notif, cfg, relays),
        libc::SYS_sendmmsg => handle_sendmmsg(listener_fd, notif, cfg, relays),
        libc::SYS_recvfrom => handle_recvfrom(listener_fd, notif, relays),
        libc::SYS_recvmsg => handle_recvmsg(listener_fd, notif, relays),
        libc::SYS_recvmmsg => handle_recvmmsg(listener_fd, notif, relays),
        libc::SYS_close => handle_close(listener_fd, notif, relays),
        libc::SYS_close_range => handle_close_range(listener_fd, notif, relays),
        libc::SYS_dup2 | libc::SYS_dup3 => handle_fd_replacement(listener_fd, notif, relays),
        _ => seccomp::send_continue(listener_fd, notif.id),
    }
}

pub(super) fn handle_fd_replacement(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let old_fd = notif.data.args[0] as RawFd;
    let new_fd = notif.data.args[1] as RawFd;
    if old_fd != new_fd {
        relays.wait_for_creation(notif.pid, new_fd);
        relays.remove_alias(notif.pid, new_fd);
    }
    seccomp::send_continue(listener_fd, notif.id);
}

pub(super) fn handle_socket(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let domain = notif.data.args[0] as i32;
    let socket_type = notif.data.args[1] as i32;
    let protocol = notif.data.args[2] as i32;
    if !is_udp_socket_request(domain, socket_type, protocol) {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    match relays.create_stable(listener_fd, &cfg, &notif, socket_type, protocol) {
        Ok(StableSocketCreation::Injected) => {}
        Ok(StableSocketCreation::Unsupported) => {
            if cfg.debug {
                eprintln!(
                    "yatht: kernel does not support atomic seccomp ADDFD+SEND; using lazy UDP mode"
                );
            }
            seccomp::send_continue(listener_fd, notif.id);
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("yatht: stable UDP socket setup failed: {err:#}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::EMFILE);
        }
    }
}

pub(super) fn is_udp_socket_request(domain: i32, socket_type: i32, protocol: i32) -> bool {
    let allowed_flags = libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    matches!(domain, libc::AF_INET | libc::AF_INET6)
        && socket_type & !allowed_flags == libc::SOCK_DGRAM
        && matches!(protocol, 0 | libc::IPPROTO_UDP)
}

pub(super) fn handle_bind(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let fd = notif.data.args[0] as RawFd;
    let addr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;
    let Some(handle) = relays.lookup_handle(notif.pid, fd, true) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if !handle.stable {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    if addr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let destination = match read_bind_destination(notif.pid, addr, addr_len, handle.domain) {
        Ok(destination) => destination,
        Err(errno) => {
            seccomp::send_errno(listener_fd, notif.id, errno);
            return;
        }
    };
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    if let Err(err) = handle.set_local_bind(destination) {
        seccomp::send_errno(listener_fd, notif.id, errno_from_io(&err));
        return;
    }
    seccomp::send_success(listener_fd, notif.id);
}

pub(super) fn handle_getsockname(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let fd = notif.data.args[0] as RawFd;
    let addr = notif.data.args[1];
    let addr_len_ptr = notif.data.args[2];
    let Some(handle) = relays.lookup_handle(notif.pid, fd, true) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if addr_len_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let addr_len = match read_signed_socklen(notif.pid, addr_len_ptr) {
        Ok(addr_len) if addr_len >= 0 => addr_len as u32,
        Ok(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EINVAL);
            return;
        }
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    if addr_len > 0 && addr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let local = handle
        .local_bind()
        .unwrap_or_else(|| handle.unspecified_destination());
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    if write_sockaddr_result(
        notif.pid,
        addr,
        addr_len_ptr,
        addr_len,
        handle.domain,
        local,
    )
    .is_err()
    {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    seccomp::send_success(listener_fd, notif.id);
}

pub(super) fn handle_getpeername(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let fd = notif.data.args[0] as RawFd;
    let addr = notif.data.args[1];
    let addr_len_ptr = notif.data.args[2];
    let Some(handle) = relays.lookup_handle(notif.pid, fd, true) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    let Some(peer) = handle.default_destination().map(|(dest, _)| dest) else {
        seccomp::send_errno(listener_fd, notif.id, libc::ENOTCONN);
        return;
    };
    if addr_len_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let addr_len = match read_signed_socklen(notif.pid, addr_len_ptr) {
        Ok(addr_len) if addr_len >= 0 => addr_len as u32,
        Ok(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EINVAL);
            return;
        }
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    if addr_len > 0 && addr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    if write_sockaddr_result(notif.pid, addr, addr_len_ptr, addr_len, handle.domain, peer).is_err()
    {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    seccomp::send_success(listener_fd, notif.id);
}

pub(super) fn handle_getsockopt(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let fd = notif.data.args[0] as RawFd;
    let level = notif.data.args[1] as i32;
    let option = notif.data.args[2] as i32;
    let optval = notif.data.args[3];
    let optlen_ptr = notif.data.args[4];
    let Some(handle) = relays.lookup_handle(notif.pid, fd, true) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if level != libc::SOL_SOCKET
        || !matches!(
            option,
            libc::SO_DOMAIN | libc::SO_TYPE | libc::SO_PROTOCOL | libc::SO_ERROR
        )
    {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    if optlen_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let optlen = match read_signed_socklen(notif.pid, optlen_ptr) {
        Ok(optlen) => optlen,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return;
        }
    };
    if optlen < 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EINVAL);
        return;
    }
    let value_len = std::mem::size_of::<libc::c_int>() as u32;
    let write_len = (optlen as u32).min(value_len);
    if write_len > 0 && optval == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let value = match option {
        libc::SO_DOMAIN => handle.domain,
        libc::SO_TYPE => libc::SOCK_DGRAM,
        libc::SO_PROTOCOL => handle.protocol,
        libc::SO_ERROR => 0,
        _ => unreachable!("getsockopt option filtered above"),
    };
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }
    if (write_len > 0
        && write_proc_bytes(
            notif.pid,
            optval,
            &value.to_ne_bytes()[..write_len as usize],
        )
        .is_err())
        || write_proc_bytes(notif.pid, optlen_ptr, &write_len.to_ne_bytes()).is_err()
    {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    seccomp::send_success(listener_fd, notif.id);
}

pub(super) fn handle_close(listener_fd: RawFd, notif: SeccompNotif, relays: Arc<UdpRelayRegistry>) {
    let fd = notif.data.args[0] as RawFd;
    relays.remove_for_close(notif.pid, fd);
    seccomp::send_continue(listener_fd, notif.id);
}

pub(super) fn handle_close_range(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let first = notif.data.args[0] as u32;
    let last = notif.data.args[1] as u32;
    let flags = notif.data.args[2] as u32;
    if close_range_closes_fds(first, last, flags) {
        relays.remove_for_close_range(notif.pid, first, last);
    }
    seccomp::send_continue(listener_fd, notif.id);
}

pub(super) fn close_range_closes_fds(first: u32, last: u32, flags: u32) -> bool {
    first <= last
        && flags & !CLOSE_RANGE_KNOWN_FLAGS == 0
        && flags & (CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE) == 0
}

pub(super) fn fd_in_close_range(fd: RawFd, first: u32, last: u32) -> bool {
    u32::try_from(fd)
        .map(|fd| (first..=last).contains(&fd))
        .unwrap_or(false)
}
