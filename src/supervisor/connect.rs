use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_connect(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
    tcp_broker: TcpBroker,
    warm_pool: Option<Arc<WarmSessionPool>>,
    observability: Observability,
    queue_wait: Duration,
) {
    let handler_started = Instant::now();
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

    let existing = relays.lookup_handle(notif.pid, target_fd, true);
    let family = u16::from_ne_bytes(raw[0..2].try_into().unwrap()) as i32;
    if family == libc::AF_UNSPEC {
        if let Some(handle) = existing {
            handle.clear_default_dest();
            seccomp::send_success(listener_fd, notif.id);
        } else {
            seccomp::send_continue(listener_fd, notif.id);
        }
        return;
    }

    let dest = match parse_sockaddr(&raw) {
        Ok(dest) => dest,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };
    if let Some(handle) = existing.as_ref() {
        if !handle.accepts_destination(dest) {
            seccomp::send_errno(listener_fd, notif.id, libc::EAFNOSUPPORT);
            return;
        }
    }

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
                "yatht: direct {} for pid={} fd={}",
                dest.authority(),
                notif.pid,
                target_fd
            );
        }
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

    let fd_inspection_started = Instant::now();
    match socket_type_and_protocol(notif.pid, target_fd) {
        Some((libc::SOCK_DGRAM, protocol))
            if protocol == libc::IPPROTO_UDP || existing.is_some() =>
        {
            if let Some(kind) = udp_route_for(&cfg, dest) {
                if !seccomp::notif_id_valid(listener_fd, notif.id) {
                    return;
                }
                if cfg.debug {
                    eprintln!(
                        "yatht: UDP connect relay {} for pid={} fd={}",
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
                    Ok(Some(_)) => {
                        seccomp::send_success(listener_fd, notif.id);
                    }
                    Ok(None) => seccomp::send_continue(listener_fd, notif.id),
                    Err(err) => {
                        if cfg.debug {
                            eprintln!("yatht: UDP relay setup failed: {err:#}");
                        }
                        let errno = err
                            .downcast_ref::<io::Error>()
                            .map(udp_send_errno)
                            .unwrap_or(libc::ECONNREFUSED);
                        seccomp::send_errno(listener_fd, notif.id, errno);
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
        Some((libc::SOCK_DGRAM, protocol)) => {
            if cfg.debug {
                eprintln!(
                    "yatht: unsupported datagram protocol {} for pid={} fd={}",
                    protocol, notif.pid, target_fd
                );
            }
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        Some((libc::SOCK_STREAM, _)) => {}
        Some((other, _)) => {
            if cfg.debug {
                eprintln!(
                    "yatht: unsupported socket type {} for pid={} fd={}",
                    other, notif.pid, target_fd
                );
            }
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        None => {
            if cfg.debug {
                eprintln!(
                    "yatht: cannot inspect socket type for pid={} fd={}",
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
                "yatht: direct {} for pid={} fd={}",
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
            "yatht: proxy {} for pid={} fd={}",
            dest.authority(),
            notif.pid,
            target_fd
        );
    }

    let mut setup = observability.begin_tcp_setup(
        notif.pid,
        target_fd,
        dest.authority(),
        handler_started,
        queue_wait,
    );

    let flow_permit = match tcp_broker.reserve_flow() {
        Ok(permit) => permit,
        Err(err) => {
            if cfg.debug {
                eprintln!("yatht: TCP broker admission rejected flow: {err}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            setup.failed("resource_admission", err);
            return;
        }
    };

    let (target, target_domain) = match duplicate_remote_fd(notif.pid, target_fd) {
        Ok(target) => {
            let socket_type = socket_type_from_fd(target.as_raw_fd());
            let domain = socket_domain_from_fd(target.as_raw_fd());
            if socket_type == Some(libc::SOCK_STREAM)
                && matches!(domain, Some(libc::AF_INET | libc::AF_INET6))
            {
                (target, domain.unwrap())
            } else {
                seccomp::send_continue(listener_fd, notif.id);
                setup.cancelled("fd_changed");
                return;
            }
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("yatht: duplicate TCP target fd failed: {err}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            setup.failed("fd_inspection", err);
            return;
        }
    };
    setup.set_fd_inspection(
        fd_inspection_started.elapsed(),
        socket_cookie(target.as_raw_fd()),
    );

    let mut dial_timings = proxy::DialTimings::default();
    let stream = match dial_proxy_session(
        &cfg,
        warm_pool.as_deref(),
        dest,
        handler_started,
        &mut dial_timings,
        &mut setup,
    ) {
        Ok(stream) => stream,
        Err(failure) => {
            setup.set_proxy_timings(dial_timings.connect, dial_timings.handshake);
            disconnect_tcp_socket(target.as_raw_fd());
            if cfg.debug {
                eprintln!(
                    "yatht: proxy dial {} failed: {:#}",
                    dest.authority(),
                    failure.error
                );
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            setup.failed(failure.stage, format!("{:#}", failure.error));
            return;
        }
    };
    setup.set_proxy_timings(dial_timings.connect, dial_timings.handshake);
    setup.set_proxy_cookie(socket_cookie(stream.as_raw_fd()));

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        setup.cancelled("notification_validation_after_proxy");
        return;
    }

    let loopback_started = Instant::now();
    let broker_target = match connect_target_to_broker(target.as_raw_fd(), target_domain) {
        Ok(stream) => {
            setup.set_loopback(loopback_started.elapsed());
            stream
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("yatht: connect target socket to local broker failed: {err}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            setup.set_loopback(loopback_started.elapsed());
            setup.failed("loopback_connect_accept", err);
            return;
        }
    };

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        disconnect_tcp_socket(target.as_raw_fd());
        setup.cancelled("notification_validation_after_loopback");
        return;
    }
    let register_started = Instant::now();
    if let Err(err) = tcp_broker.register(broker_target, stream, flow_permit) {
        setup.set_broker_register(register_started.elapsed());
        disconnect_tcp_socket(target.as_raw_fd());
        if cfg.debug {
            eprintln!("yatht: register TCP broker relay failed: {err}");
        }
        seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
        setup.failed("broker_register", err);
        return;
    }
    setup.set_broker_register(register_started.elapsed());
    let reply_started = Instant::now();
    seccomp::send_success(listener_fd, notif.id);
    setup.set_notification_reply(reply_started.elapsed());
    setup.completed();
}

/// A failed proxy dial with the setup stage it should be attributed to.
pub(super) struct ProxyDialFailure {
    pub(super) error: anyhow::Error,
    pub(super) stage: &'static str,
}

pub(super) fn cold_dial_failure(
    timings: &proxy::DialTimings,
    error: anyhow::Error,
) -> ProxyDialFailure {
    ProxyDialFailure {
        error,
        stage: if timings.handshake.is_some() {
            "proxy_handshake"
        } else {
            "proxy_connect"
        },
    }
}

/// Obtains the proxy-side connection for one flow: a warm lease when the
/// pool is enabled and can serve one, otherwise a cold dial. All warm-path
/// fallbacks stay inside the flow's original connect budget.
pub(super) fn dial_proxy_session(
    cfg: &EffectiveConfig,
    warm_pool: Option<&WarmSessionPool>,
    dest: Destination,
    handler_started: Instant,
    timings: &mut proxy::DialTimings,
    setup: &mut TcpSetupTrace,
) -> std::result::Result<TcpStream, ProxyDialFailure> {
    let deadline = proxy::Deadline::from_start(handler_started, cfg.connect_timeout);
    let Some(pool) = warm_pool else {
        setup.set_proxy_session("cold", None);
        return proxy::dial_with_deadline(&cfg.proxy, dest, deadline, timings)
            .map_err(|err| cold_dial_failure(timings, err));
    };
    let lease_started = Instant::now();
    let leased = pool.lease();
    let lease_elapsed = lease_started.elapsed();
    let Some(warm) = leased else {
        setup.set_proxy_session("warm_miss", Some(lease_elapsed));
        return proxy::dial_with_deadline(&cfg.proxy, dest, deadline, timings)
            .map_err(|err| cold_dial_failure(timings, err));
    };
    setup.set_proxy_session("warm_hit", Some(lease_elapsed));
    match proxy::warm::complete_warm_lease(&cfg.proxy, warm, dest, deadline, timings) {
        Ok(stream) => Ok(stream),
        Err(WarmCompletionError::NothingSent(err)) => {
            // No request byte reached the kernel, so the proxy cannot have
            // observed a request; one cold retry inside the original budget.
            // The lease turned out dead: reclassify it so pool counters
            // stay consistent with the flow's warm_miss label.
            if cfg.debug {
                eprintln!("yatht: warm session dead before request, retrying cold: {err:#}");
            }
            pool.reclassify_dead_lease();
            setup.set_proxy_session("warm_miss", Some(lease_elapsed));
            proxy::dial_with_deadline(&cfg.proxy, dest, deadline, timings)
                .map_err(|err| cold_dial_failure(timings, err))
        }
        Err(WarmCompletionError::SessionDied(err)) => Err(ProxyDialFailure {
            error: err,
            // Bytes may have reached the proxy, so the pre-registered rule
            // forbids a retry; attribute the loss to the warm session
            // instead of a generic handshake failure.
            stage: "warm_session_died",
        }),
        Err(WarmCompletionError::Rejected(err)) => Err(ProxyDialFailure {
            error: err,
            stage: "proxy_handshake",
        }),
    }
}

/// If `fd` already has a relay, records `dest` as the relay's default direct
/// peer and emulates a successful connect (the injected AF_UNIX fd cannot accept
/// an AF_INET connect itself). Returns `true` when it handled the notification.
/// Returns `false` for a plain fd so the caller can continue the syscall.
pub(super) fn direct_connect_through_relay(
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
    if let Err(err) = handle.set_default_dest(dest, UdpRouteKind::Direct) {
        seccomp::send_errno(listener_fd, notif.id, errno_from_io(&err));
        return true;
    }
    seccomp::send_success(listener_fd, notif.id);
    true
}

pub(super) fn direct_connect_can_continue_before_socket_type(
    cfg: &EffectiveConfig,
    dest: Destination,
) -> bool {
    cfg.route_for(dest.ip) == Route::Direct && !(cfg.enable_dns && dest.port == 53)
}

pub(super) fn connect_target_to_broker(target_fd: RawFd, domain: i32) -> io::Result<TcpStream> {
    let bind_addr = match domain {
        libc::AF_INET => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        libc::AF_INET6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        _ => return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
    };
    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?;
    let destination = Destination {
        ip: local_addr.ip(),
        port: local_addr.port(),
    };
    let (raw_addr, raw_len) = sockaddr_bytes(destination);

    let rc = unsafe {
        libc::connect(
            target_fd,
            raw_addr.as_ptr().cast::<libc::sockaddr>(),
            raw_len as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if !matches!(
            err.raw_os_error(),
            Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR)
        ) {
            return Err(err);
        }
    }

    let deadline = Instant::now() + LOCAL_BROKER_CONNECT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(err) = socket_error(target_fd) {
                    return Err(err);
                }
                return Ok(stream);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local TCP broker connect timed out",
            ));
        }
        let timeout_ms = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut pollfds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: target_fd,
                events: libc::POLLOUT,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if pollfds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(socket_error(target_fd)
                .unwrap_or_else(|| io::Error::from_raw_os_error(libc::ECONNRESET)));
        }
    }
}

pub(super) fn disconnect_tcp_socket(fd: RawFd) {
    let address = libc::sockaddr {
        sa_family: libc::AF_UNSPEC as libc::sa_family_t,
        sa_data: [0; 14],
    };
    let _ = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
}
