use super::*;

pub(super) fn handle_sendto(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let buf_ptr = notif.data.args[1];
    let len = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;
    let addr = notif.data.args[4];
    let addr_len = notif.data.args[5] as usize;

    let existing = relays.lookup_handle(notif.pid, target_fd, true);
    // A null address leaves `msg_name` unset, so the kernel falls back to the
    // connected peer. A zero length keeps `msg_name` set and fails the
    // destination-length check below instead. The common small null-address
    // send takes this fast path without classifying the fd.
    if addr == 0 && len <= MAX_UDP_PAYLOAD {
        send_without_destination(listener_fd, &notif, existing.as_ref(), len);
        return;
    }
    // `udp_sendmsg` refuses an oversized datagram before any destination
    // verdict, but the limit belongs to Internet datagram sockets: another
    // fd type must keep the kernel's own semantics for the same call.
    let Some(domain) = internet_udp_domain(notif.pid, target_fd, existing.as_ref()) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    if len > MAX_UDP_PAYLOAD {
        seccomp::send_errno(listener_fd, notif.id, libc::EMSGSIZE);
        return;
    }
    let (dest, route) = match resolve_send_destination(notif.pid, addr, addr_len, existing.as_ref())
    {
        SendDestination::Explicit(dest) => {
            let route = match udp_route_for(&cfg, dest) {
                Some(route) => route,
                None if existing.is_some() => UdpRouteKind::Direct,
                // Direct destination on a plain (non-relay) fd: the kernel
                // socket is a real UDP socket, so let the syscall run
                // unmodified.
                None => {
                    seccomp::send_continue(listener_fd, notif.id);
                    return;
                }
            };
            if let Err(errno) = validate_send_destination(domain, dest) {
                seccomp::send_errno(listener_fd, notif.id, errno);
                return;
            }
            (dest, route)
        }
        SendDestination::ConnectedPeer => match connected_send_peer(listener_fd, &notif, &existing)
        {
            Some(peer) => peer,
            None => return,
        },
        SendDestination::Continue => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        SendDestination::Errno(errno) => {
            seccomp::send_errno(listener_fd, notif.id, errno);
            return;
        }
    };
    // With a destination resolved, the IP layer's family-specific ceiling
    // applies before any user-buffer copy.
    if len > max_udp_payload_for(dest) {
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
    let nonblocking = recv_request_is_nonblocking(notif.pid, target_fd, flags)
        .unwrap_or(flags & libc::MSG_DONTWAIT != 0);
    match handle.send(dest, payload, route, nonblocking) {
        Ok(()) => seccomp::send_value(listener_fd, notif.id, len as i64),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            seccomp::send_errno(listener_fd, notif.id, libc::EAGAIN);
        }
        Err(_) => seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED),
    }
}

/// Imports a message's iovec array and its total length, the two checks Linux
/// performs before any destination verdict: `copy_msghdr_from_user` faults on
/// an unreadable array and rejects more than `UIO_MAXIOV` segments, and
/// `udp_sendmsg` refuses a datagram over the UDP length field ahead of
/// reporting a missing peer. Returns the errno to report on failure, so a
/// caller that runs this first cannot answer `EDESTADDRREQ` where Linux
/// answers `EFAULT` or `EMSGSIZE`. Reading the buffers themselves must stay
/// after the destination verdict, which is where the kernel copies them.
///
/// This is only the first of two length ceilings: the IP layer's tighter
/// family-specific limit (`max_udp_payload_for`) surfaces after the
/// destination verdict, so callers must apply it once `dest` is known. Both
/// limits are valid only once the fd is known to be an Internet UDP socket;
/// callers must not apply them to a TCP or AF_UNIX fd that merely tripped the
/// same syscall filter.
pub(super) fn import_send_iovecs(
    pid: u32,
    msg: &TargetMsghdr,
) -> Result<(Vec<TargetIovec>, usize), i32> {
    let iovecs = match read_iovec_targets(pid, msg.iov, msg.iov_len) {
        Ok(iovecs) => iovecs,
        // Too many segments is a length error to Linux, not a fault.
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => return Err(libc::EMSGSIZE),
        Err(_) => return Err(libc::EFAULT),
    };
    validate_iovec_segment_lengths(&iovecs)?;
    // Match the sendto path: an oversized datagram cannot be sent, so report
    // EMSGSIZE rather than EFAULT (the buffer is valid, just too large).
    let total = iovec_total_len(&iovecs).map_err(|_| libc::EMSGSIZE)?;
    Ok((iovecs, total))
}

/// Linux imports each `iov_len` as a signed length and rejects one that does
/// not fit before summing segments or waiting for socket data.
pub(super) fn validate_iovec_segment_lengths(iovecs: &[TargetIovec]) -> Result<(), i32> {
    if iovecs.iter().any(|iov| iov.len > isize::MAX as usize) {
        Err(libc::EINVAL)
    } else {
        Ok(())
    }
}

/// Answers a send whose call carries no destination pointer at all. The kernel
/// drops such a name before the injected AF_UNIX endpoint sees it, so a relayed
/// socket can simply continue and let its connected peer carry the datagram;
/// an unconnected one fails with `EDESTADDRREQ`, and a datagram over the
/// connected peer's family-specific ceiling fails with `EMSGSIZE` — the IP
/// layer checks it after resolving the peer but before copying any payload.
pub(super) fn send_without_destination(
    listener_fd: RawFd,
    notif: &SeccompNotif,
    handle: Option<&UdpRelayHandle>,
    len: usize,
) {
    match handle.map(|handle| handle.default_destination()) {
        None => seccomp::send_continue(listener_fd, notif.id),
        Some(None) => seccomp::send_errno(listener_fd, notif.id, libc::EDESTADDRREQ),
        Some(Some((dest, _))) => {
            if len > max_udp_payload_for(dest) {
                seccomp::send_errno(listener_fd, notif.id, libc::EMSGSIZE);
            } else {
                seccomp::send_continue(listener_fd, notif.id);
            }
        }
    }
}

/// Resolves the peer that carries a send whose supplied name Linux drops. The
/// relay must perform this send itself: continuing would hand the dropped name
/// to the injected AF_UNIX endpoint, which rejects any non-AF_UNIX address.
/// Answers the notification and returns `None` when the socket is unconnected.
pub(super) fn connected_send_peer(
    listener_fd: RawFd,
    notif: &SeccompNotif,
    handle: &Option<UdpRelayHandle>,
) -> Option<(Destination, UdpRouteKind)> {
    let peer = handle
        .as_ref()
        .and_then(|handle| handle.default_destination());
    if peer.is_none() {
        seccomp::send_errno(listener_fd, notif.id, libc::EDESTADDRREQ);
    }
    peer
}

/// Resolves the relay handle a send should use: an already-relay-ized fd reuses
/// its existing handle, otherwise a relay is created (injecting the socketpair).
/// Emits the seccomp error response itself on failure and returns `None`.
pub(super) fn relay_for_send(
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
        Ok(Some(handle)) => Some(handle),
        Ok(None) => {
            seccomp::send_continue(listener_fd, notif.id);
            None
        }
        Err(err) => {
            if cfg.debug {
                eprintln!("yatht: UDP relay setup failed: {err:#}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            None
        }
    }
}

pub(super) fn handle_sendmsg(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let msg_ptr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;

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
    let existing = relays.lookup_handle(notif.pid, target_fd, true);
    // The filter traps the syscall, not the socket, so TCP, AF_UNIX and stale
    // fds arrive here too. Classify an unrelayed fd before applying UDP's
    // datagram limits: an explicit, routable name does not prove the fd is
    // UDP, while a lazy UDP socket still needs the kernel's iovec-import order
    // on its first send.
    let Some(domain) = internet_udp_domain(notif.pid, target_fd, existing.as_ref()) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    let (iovecs, total) = match import_send_iovecs(notif.pid, &msg) {
        Ok(imported) => imported,
        Err(errno) => {
            seccomp::send_errno(listener_fd, notif.id, errno);
            return;
        }
    };
    // `sendmsg(2)` drops a zero-length name, so both cases leave the datagram
    // without an explicit destination.
    if msg.name == 0 || msg.name_len == 0 {
        send_without_destination(listener_fd, &notif, existing.as_ref(), total);
        return;
    }

    let (dest, route) = match resolve_send_destination(
        notif.pid,
        msg.name,
        msg.name_len as usize,
        existing.as_ref(),
    ) {
        SendDestination::Explicit(dest) => {
            let route = match udp_route_for(&cfg, dest) {
                Some(route) => route,
                None if existing.is_some() => UdpRouteKind::Direct,
                None => {
                    seccomp::send_continue(listener_fd, notif.id);
                    return;
                }
            };
            if let Err(errno) = validate_send_destination(domain, dest) {
                seccomp::send_errno(listener_fd, notif.id, errno);
                return;
            }
            (dest, route)
        }
        SendDestination::ConnectedPeer => match connected_send_peer(listener_fd, &notif, &existing)
        {
            Some(peer) => peer,
            None => return,
        },
        SendDestination::Continue => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
        SendDestination::Errno(errno) => {
            seccomp::send_errno(listener_fd, notif.id, errno);
            return;
        }
    };

    // The iovec import above already applied the pre-destination 0xFFFF
    // ceiling; with a destination resolved the IP layer's family-specific
    // limit applies before any user-buffer copy.
    if total > max_udp_payload_for(dest) {
        seccomp::send_errno(listener_fd, notif.id, libc::EMSGSIZE);
        return;
    }

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
    let nonblocking = recv_request_is_nonblocking(notif.pid, target_fd, flags)
        .unwrap_or(flags & libc::MSG_DONTWAIT != 0);
    match handle.send(dest, payload, route, nonblocking) {
        Ok(()) => seccomp::send_value(listener_fd, notif.id, written),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            seccomp::send_errno(listener_fd, notif.id, libc::EAGAIN);
        }
        Err(_) => seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED),
    }
}

pub(super) fn handle_sendmmsg(
    listener_fd: RawFd,
    notif: SeccompNotif,
    cfg: Arc<EffectiveConfig>,
    relays: Arc<UdpRelayRegistry>,
) {
    let target_fd = notif.data.args[0] as RawFd;
    let msgvec = notif.data.args[1];
    let vlen = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;

    // The kernel clamps vlen and reads no entry when it is zero, so a null
    // msgvec with an empty batch still succeeds.
    if vlen == 0 {
        seccomp::send_success(listener_fd, notif.id);
        return;
    }
    if msgvec == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    let vlen = vlen.min(UIO_MAXIOV);

    let mut existing = relays.lookup_handle(notif.pid, target_fd, true);
    let Some(domain) = internet_udp_domain(notif.pid, target_fd, existing.as_ref()) else {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    };
    // Decide before sending any entry whether this batch needs virtualization.
    // Once any entry needs a proxy, direct entries must use the same relay;
    // continuing the batch after partial emulation would resend its prefix.
    if existing.is_none() && !(0..vlen).any(|index| {
        let Some(ptr) = msgvec.checked_add((index * X86_64_MMSGHDR_SIZE) as u64) else {
            return false;
        };
        let Ok(msg) = read_msghdr(notif.pid, ptr) else {
            return false;
        };
        msg.name != 0
            && msg.name_len != 0
            && matches!(
                resolve_udp_send_destination(notif.pid, msg.name, msg.name_len as usize, domain),
                SendDestination::Explicit(dest) if udp_route_for(&cfg, dest).is_some()
            )
    }) {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }
    // A previously direct-connected lazy socket can first need a relay in a
    // named batch. Preserve its peer for unnamed entries in that same batch.
    let plain_peer = if existing.is_none() {
        duplicate_remote_fd(notif.pid, target_fd)
            .ok()
            .and_then(|fd| UdpSocket::from(fd).peer_addr().ok())
            .map(|addr| {
                let dest = Destination {
                    ip: addr.ip(),
                    port: addr.port(),
                };
                (
                    dest,
                    udp_route_for(&cfg, dest).unwrap_or(UdpRouteKind::Direct),
                )
            })
    } else {
        None
    };
    let nonblocking = recv_request_is_nonblocking(notif.pid, target_fd, flags)
        .unwrap_or(flags & libc::MSG_DONTWAIT != 0);
    let mut sent = 0_usize;

    for index in 0..vlen {
        let Some(entry_ptr) = msgvec.checked_add((index * X86_64_MMSGHDR_SIZE) as u64) else {
            send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EFAULT);
            return;
        };
        let msg = match read_msghdr(notif.pid, entry_ptr) {
            Ok(msg) => msg,
            Err(_) => {
                send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EFAULT);
                return;
            }
        };
        let (iovecs, total) = match import_send_iovecs(notif.pid, &msg) {
            Ok(imported) => imported,
            Err(errno) => {
                send_mmsg_result_or_errno(listener_fd, notif.id, sent, errno);
                return;
            }
        };
        let named = if msg.name != 0 && msg.name_len != 0 {
            match resolve_udp_send_destination(notif.pid, msg.name, msg.name_len as usize, domain) {
                SendDestination::Explicit(dest) => {
                    if let Err(errno) = validate_send_destination(domain, dest) {
                        send_mmsg_result_or_errno(listener_fd, notif.id, sent, errno);
                        return;
                    }
                    Some((
                        dest,
                        udp_route_for(&cfg, dest).unwrap_or(UdpRouteKind::Direct),
                    ))
                }
                SendDestination::ConnectedPeer => None,
                SendDestination::Continue => unreachable!("UDP domain is known"),
                SendDestination::Errno(errno) => {
                    send_mmsg_result_or_errno(listener_fd, notif.id, sent, errno);
                    return;
                }
            }
        } else {
            None
        };
        let (dest, route) = match named {
            Some(target) => target,
            None => {
                let default = existing
                    .as_ref()
                    .and_then(UdpRelayHandle::default_destination)
                    .or(plain_peer);
                let Some(default) = default else {
                    send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EDESTADDRREQ);
                    return;
                };
                default
            }
        };
        if total > max_udp_payload_for(dest) {
            send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EMSGSIZE);
            return;
        }
        let payload = match read_iovec_payload(notif.pid, &iovecs, total) {
            Ok(payload) => payload,
            Err(_) => {
                send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EFAULT);
                return;
            }
        };
        if !seccomp::notif_id_valid(listener_fd, notif.id) {
            return;
        }
        if existing.is_none() {
            existing = relay_for_send(&cfg, &relays, listener_fd, &notif, target_fd, None);
            let Some(handle) = existing.as_ref() else {
                return;
            };
            if let Some((peer, route)) = plain_peer {
                handle.set_default_dest(peer, route);
            }
        }
        let handle = existing.as_ref().expect("relay initialized above");
        if let Err(err) = handle.send(dest, payload, route, nonblocking) {
            let errno = if err.kind() == io::ErrorKind::WouldBlock {
                libc::EAGAIN
            } else {
                libc::ECONNREFUSED
            };
            send_mmsg_result_or_errno(listener_fd, notif.id, sent, errno);
            return;
        }
        if write_proc_bytes(
            notif.pid,
            entry_ptr + X86_64_MMSGHDR_LEN_OFFSET,
            &(total as u32).to_ne_bytes(),
        )
        .is_err()
        {
            send_mmsg_result_or_errno(listener_fd, notif.id, sent, libc::EFAULT);
            return;
        }
        sent += 1;
    }

    seccomp::send_value(listener_fd, notif.id, sent as i64);
}

pub(super) fn send_mmsg_result_or_errno(
    listener_fd: RawFd,
    notif_id: u64,
    sent: usize,
    errno: i32,
) {
    if sent == 0 {
        seccomp::send_errno(listener_fd, notif_id, errno);
    } else {
        seccomp::send_value(listener_fd, notif_id, sent as i64);
    }
}

pub(super) fn udp_route_for(cfg: &EffectiveConfig, dest: Destination) -> Option<UdpRouteKind> {
    if cfg.enable_dns && dest.port == 53 {
        Some(UdpRouteKind::Dns)
    } else if cfg.enable_udp && cfg.route_for(dest.ip) == Route::Proxy {
        Some(UdpRouteKind::Generic)
    } else {
        None
    }
}

/// Destination named by a send call, before the socket's own address family is
/// taken into account.
pub(super) enum SendName {
    /// A parsed AF_INET or AF_INET6 destination.
    Explicit(Destination),
    /// A family that only means something relative to the socket.
    /// [`resolve_send_name`] finishes it once the domain is known.
    SocketRelative { family: i32, raw: Vec<u8> },
}

/// Resolved destination for one send notification.
pub(super) enum SendDestination {
    /// Forward the datagram to this destination.
    Explicit(Destination),
    /// Linux drops the supplied name, so the connected peer carries the
    /// datagram and an unconnected socket fails with `EDESTADDRREQ`.
    ConnectedPeer,
    /// Nothing here depends on relay state; run the original syscall.
    Continue,
    /// Reject the call with this errno.
    Errno(i32),
}

/// Reads the destination named by `addr`/`addr_len`, applying only the checks
/// Linux performs before it looks at the socket: a truncated name is `EINVAL`,
/// and any other family is deferred to [`resolve_send_name`].
pub(super) fn read_send_name(
    pid: u32,
    addr: u64,
    addr_len: usize,
) -> std::result::Result<SendName, i32> {
    let raw =
        read_proc_bytes(pid, addr, addr_len.min(SOCKADDR_IN6_SIZE)).map_err(|_| libc::EFAULT)?;
    if raw.len() < 2 {
        return Err(libc::EINVAL);
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;
    if !matches!(family, libc::AF_INET | libc::AF_INET6) {
        return Ok(SendName::SocketRelative { family, raw });
    }
    parse_sockaddr(&raw)
        .map(SendName::Explicit)
        .map_err(|_| libc::EINVAL)
}

/// Resolves a name whose family Linux reads relative to the socket. `Ok(None)`
/// means the name is dropped and the connected peer takes over.
///
/// An AF_INET socket accepts an `AF_UNSPEC` name as AF_INET for compatibility
/// and rejects every other family with `EAFNOSUPPORT`. An AF_INET6 socket
/// treats an `AF_UNSPEC` name as no name at all and rejects every other family
/// with `EINVAL`.
pub(super) fn resolve_send_name(
    raw: &[u8],
    family: i32,
    domain: i32,
) -> std::result::Result<Option<Destination>, i32> {
    match (domain, family) {
        (libc::AF_INET, libc::AF_UNSPEC) => {
            let mut compat = raw.to_vec();
            compat[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            parse_sockaddr_in(&compat)
                .map(Some)
                .map_err(|_| libc::EINVAL)
        }
        (libc::AF_INET6, libc::AF_UNSPEC) => Ok(None),
        (libc::AF_INET6, _) => Err(libc::EINVAL),
        _ => Err(libc::EAFNOSUPPORT),
    }
}

/// Resolves the destination named by a send on a socket whose relay is
/// `handle`. Without a relay the fd is still a plain UDP socket, so anything
/// that depends on its address family is left to the kernel.
pub(super) fn resolve_send_destination(
    pid: u32,
    addr: u64,
    addr_len: usize,
    handle: Option<&UdpRelayHandle>,
) -> SendDestination {
    match read_send_name(pid, addr, addr_len) {
        Ok(SendName::Explicit(dest)) => SendDestination::Explicit(dest),
        Ok(SendName::SocketRelative { family, raw }) => {
            let Some(domain) = handle.map(|handle| handle.domain) else {
                return SendDestination::Continue;
            };
            match resolve_send_name(&raw, family, domain) {
                Ok(Some(dest)) => SendDestination::Explicit(dest),
                Ok(None) => SendDestination::ConnectedPeer,
                Err(errno) => SendDestination::Errno(errno),
            }
        }
        Err(errno) if handle.is_some() => SendDestination::Errno(errno),
        Err(_) => SendDestination::Continue,
    }
}

/// Resolve all names locally once classification has established a UDP domain.
/// In particular, a later unsupported name must not continue a proxied batch.
fn resolve_udp_send_destination(
    pid: u32,
    addr: u64,
    addr_len: usize,
    domain: i32,
) -> SendDestination {
    match read_send_name(pid, addr, addr_len) {
        Ok(SendName::Explicit(dest)) => SendDestination::Explicit(dest),
        Ok(SendName::SocketRelative { family, raw }) => {
            match resolve_send_name(&raw, family, domain) {
                Ok(Some(dest)) => SendDestination::Explicit(dest),
                Ok(None) => SendDestination::ConnectedPeer,
                Err(errno) => SendDestination::Errno(errno),
            }
        }
        Err(errno) => SendDestination::Errno(errno),
    }
}

/// Applies the checks Linux defers until it knows both the named destination
/// and the socket's address family. Only explicit names reach these: a peer
/// recorded by `connect(2)` keeps whatever that call accepted.
pub(super) fn validate_send_destination(
    domain: i32,
    dest: Destination,
) -> std::result::Result<(), i32> {
    if !udp_domain_accepts_destination(domain, dest) {
        return Err(libc::EAFNOSUPPORT);
    }
    if dest.port == 0 {
        return Err(libc::EINVAL);
    }
    Ok(())
}

pub(super) fn read_bind_destination(
    pid: u32,
    addr: u64,
    addr_len: usize,
    domain: i32,
) -> std::result::Result<Destination, i32> {
    let minimum_len = match domain {
        libc::AF_INET => SOCKADDR_IN_SIZE,
        libc::AF_INET6 => SOCKADDR_IN6_MIN_SIZE,
        _ => return Err(libc::EAFNOSUPPORT),
    };
    if addr_len < minimum_len {
        return Err(libc::EINVAL);
    }

    // The length check above guarantees at least a family and an IPv4 payload.
    let mut raw =
        read_proc_bytes(pid, addr, addr_len.min(SOCKADDR_IN6_SIZE)).map_err(|_| libc::EFAULT)?;
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;
    if family == libc::AF_UNSPEC {
        // Linux keeps an AF_UNSPEC bind working on AF_INET sockets, but only
        // for the wildcard address.
        if domain != libc::AF_INET {
            return Err(libc::EAFNOSUPPORT);
        }
        raw[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        let destination = parse_sockaddr_in(&raw).map_err(|_| libc::EINVAL)?;
        return destination
            .ip
            .is_unspecified()
            .then_some(destination)
            .ok_or(libc::EAFNOSUPPORT);
    }
    if family != domain {
        return Err(libc::EAFNOSUPPORT);
    }

    parse_sockaddr(&raw).map_err(|_| libc::EINVAL)
}

pub(super) fn remote_udp_domain(pid: u32, fd: RawFd) -> Option<i32> {
    let target = duplicate_remote_fd(pid, fd).ok()?;
    if socket_type_from_fd(target.as_raw_fd()) != Some(libc::SOCK_DGRAM)
        || socket_protocol_from_fd(target.as_raw_fd()) != Some(libc::IPPROTO_UDP)
    {
        return None;
    }
    socket_domain_from_fd(target.as_raw_fd())
}

pub(super) fn internet_udp_domain(
    pid: u32,
    fd: RawFd,
    existing: Option<&UdpRelayHandle>,
) -> Option<i32> {
    let domain = existing
        .map(|handle| handle.domain)
        .or_else(|| remote_udp_domain(pid, fd))?;
    matches!(domain, libc::AF_INET | libc::AF_INET6).then_some(domain)
}
