use super::*;

/// Imports a receive message's target segments with Linux's distinct errors
/// for an excessive segment count and an unreadable iovec array.
pub(super) fn import_recv_iovecs(pid: u32, msg: &TargetMsghdr) -> Result<Vec<TargetIovec>, i32> {
    let iovecs = match read_iovec_targets(pid, msg.iov, msg.iov_len) {
        Ok(iovecs) => iovecs,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => return Err(libc::EMSGSIZE),
        Err(_) => return Err(libc::EFAULT),
    };
    validate_iovec_segment_lengths(&iovecs)?;
    Ok(iovecs)
}

pub(super) fn lookup_relay_for_recv(
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

pub(super) fn recv_request_is_nonblocking(pid: u32, fd: RawFd, flags: i32) -> io::Result<bool> {
    if flags & libc::MSG_DONTWAIT != 0 {
        return Ok(true);
    }
    let duplicated = duplicate_remote_fd(pid, fd)?;
    Ok(fd_status_flags(duplicated.as_raw_fd())? & libc::O_NONBLOCK != 0)
}

pub(super) fn handle_recvfrom(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let _ = handle_recvfrom_once(
        listener_fd,
        notif,
        relays,
        true,
        BlockingRecvState::default(),
    );
}

pub(super) fn handle_recvfrom_once(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
    wait_for_readable: bool,
    mut state: BlockingRecvState,
) -> RecvHandling {
    let target_fd = notif.data.args[0] as RawFd;
    let buf_ptr = notif.data.args[1];
    let len = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;
    let src_addr = notif.data.args[4];
    let addr_len_ptr = notif.data.args[5];

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }
    let Some((handle, relay_fd)) =
        lookup_relay_for_recv(listener_fd, &notif, &relays, target_fd, flags)
    else {
        return RecvHandling::Completed;
    };
    if !state.timeout_initialized {
        state.arm_rcvtimeo(relay_fd.as_raw_fd());
        state.timeout_initialized = true;
    }
    // A single UDP datagram never exceeds MAX_UDP_PAYLOAD, so cap the local
    // receive buffer instead of continuing the syscall on the relay fd: a plain
    // send_continue would bypass source rewrite and leave pending_sources
    // unpopped, desyncing the source queue from the datagram stream (mirrors
    // the recvmsg capacity clamp below).
    let capacity = len.min(MAX_UDP_PAYLOAD);
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }
    let addr_len = if src_addr != 0 && addr_len_ptr != 0 {
        match read_socklen(notif.pid, addr_len_ptr) {
            Ok(addr_len) => Some(addr_len),
            Err(_) => {
                seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                return RecvHandling::Completed;
            }
        }
    } else {
        None
    };

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }

    let nonblocking = recv_is_nonblocking(relay_fd.as_raw_fd(), flags);

    match recv_from_relay_fd(
        listener_fd,
        notif.id,
        relay_fd.as_raw_fd(),
        capacity,
        flags,
        &handle.pending_sources,
        wait_for_readable,
    ) {
        Ok(received) => {
            let source = received.source;
            if let Err(err) = write_proc_bytes(notif.pid, buf_ptr, &received.payload) {
                if err.kind() == io::ErrorKind::Interrupted {
                    seccomp::send_errno(listener_fd, notif.id, libc::EINTR);
                } else {
                    seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                }
                return RecvHandling::Completed;
            }
            if let Some(addr_len) = addr_len {
                if let Some(source) = source {
                    if write_sockaddr_result(
                        notif.pid,
                        src_addr,
                        addr_len_ptr,
                        addr_len,
                        handle.domain,
                        source,
                    )
                    .is_err()
                    {
                        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                        return RecvHandling::Completed;
                    }
                }
            }
            seccomp::send_value(listener_fd, notif.id, received.result_len as i64);
            RecvHandling::Completed
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock && !nonblocking => {
            if state
                .rcvtimeo_deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                send_recv_error(listener_fd, notif.id, &err);
                RecvHandling::Completed
            } else {
                RecvHandling::Deferred {
                    relay_fd,
                    relay: handle.target_identity,
                    state,
                }
            }
        }
        Err(err) => {
            send_recv_error(listener_fd, notif.id, &err);
            RecvHandling::Completed
        }
    }
}

pub(super) fn handle_recvmsg(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let _ = handle_recvmsg_once(
        listener_fd,
        notif,
        relays,
        true,
        BlockingRecvState::default(),
    );
}

pub(super) fn handle_recvmsg_once(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
    wait_for_readable: bool,
    mut state: BlockingRecvState,
) -> RecvHandling {
    let target_fd = notif.data.args[0] as RawFd;
    let msg_ptr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }
    let Some((handle, relay_fd)) =
        lookup_relay_for_recv(listener_fd, &notif, &relays, target_fd, flags)
    else {
        return RecvHandling::Completed;
    };
    if !state.timeout_initialized {
        state.arm_rcvtimeo(relay_fd.as_raw_fd());
        state.timeout_initialized = true;
    }
    if msg_ptr == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return RecvHandling::Completed;
    }
    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }
    let msg = match read_msghdr(notif.pid, msg_ptr) {
        Ok(msg) => msg,
        Err(_) => {
            seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
            return RecvHandling::Completed;
        }
    };
    let iovecs = match import_recv_iovecs(notif.pid, &msg) {
        Ok(iovecs) => iovecs,
        Err(errno) => {
            seccomp::send_errno(listener_fd, notif.id, errno);
            return RecvHandling::Completed;
        }
    };
    let capacity = iovecs
        .iter()
        .try_fold(0_usize, |acc, iov| acc.checked_add(iov.len))
        .filter(|len| *len <= MAX_UDP_PAYLOAD)
        .unwrap_or(MAX_UDP_PAYLOAD);

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }

    let nonblocking = recv_is_nonblocking(relay_fd.as_raw_fd(), flags);

    match recv_msg_from_relay_fd(
        listener_fd,
        notif.id,
        relay_fd.as_raw_fd(),
        capacity,
        flags,
        &handle.pending_sources,
        wait_for_readable,
    ) {
        Ok(received) => {
            if write_recvmsg_result(notif.pid, msg_ptr, &msg, &iovecs, handle.domain, &received)
                .is_err()
            {
                seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
                return RecvHandling::Completed;
            }
            seccomp::send_value(listener_fd, notif.id, received.result_len as i64);
            RecvHandling::Completed
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock && !nonblocking => {
            if state
                .rcvtimeo_deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                send_recv_error(listener_fd, notif.id, &err);
                RecvHandling::Completed
            } else {
                RecvHandling::Deferred {
                    relay_fd,
                    relay: handle.target_identity,
                    state,
                }
            }
        }
        Err(err) => {
            send_recv_error(listener_fd, notif.id, &err);
            RecvHandling::Completed
        }
    }
}

pub(super) fn handle_recvmmsg(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
) {
    let _ = handle_recvmmsg_once(listener_fd, notif, relays, BlockingRecvState::default());
}

pub(super) fn handle_recvmmsg_once(
    listener_fd: RawFd,
    notif: SeccompNotif,
    relays: Arc<UdpRelayRegistry>,
    mut state: BlockingRecvState,
) -> RecvHandling {
    let target_fd = notif.data.args[0] as RawFd;
    let msgvec = notif.data.args[1];
    let vlen = notif.data.args[2] as usize;
    let flags = notif.data.args[3] as i32;
    let timeout_ptr = notif.data.args[4];

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return RecvHandling::Completed;
    }
    let Some((handle, relay_fd)) =
        lookup_relay_for_recv(listener_fd, &notif, &relays, target_fd, flags)
    else {
        return RecvHandling::Completed;
    };
    if !state.timeout_initialized {
        state.deadline = match read_recvmmsg_deadline(
            notif.pid,
            timeout_ptr,
            state.received_at.unwrap_or_else(Instant::now),
        ) {
            Ok(deadline) => deadline,
            Err(err) => {
                let errno = if err.kind() == io::ErrorKind::InvalidInput {
                    libc::EINVAL
                } else {
                    libc::EFAULT
                };
                seccomp::send_errno(listener_fd, notif.id, errno);
                return RecvHandling::Completed;
            }
        };
        state.arm_rcvtimeo(relay_fd.as_raw_fd());
        state.timeout_initialized = true;
    }
    if vlen == 0 {
        seccomp::send_success(listener_fd, notif.id);
        return RecvHandling::Completed;
    }
    let vlen = vlen.min(UIO_MAXIOV);
    if msgvec == 0 {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return RecvHandling::Completed;
    }

    let nonblocking = recv_is_nonblocking(relay_fd.as_raw_fd(), flags);
    while state.completed < vlen {
        if !seccomp::notif_id_valid(listener_fd, notif.id) {
            return RecvHandling::Completed;
        }
        let Some(entry_offset) = state.completed.checked_mul(X86_64_MMSGHDR_SIZE) else {
            send_recvmmsg_result_or_errno(listener_fd, &notif, &state, Some(libc::EFAULT), false);
            return RecvHandling::Completed;
        };
        let Some(entry_ptr) = msgvec.checked_add(entry_offset as u64) else {
            send_recvmmsg_result_or_errno(listener_fd, &notif, &state, Some(libc::EFAULT), false);
            return RecvHandling::Completed;
        };
        let msg = match read_msghdr(notif.pid, entry_ptr) {
            Ok(msg) => msg,
            Err(_) => {
                send_recvmmsg_result_or_errno(
                    listener_fd,
                    &notif,
                    &state,
                    Some(libc::EFAULT),
                    false,
                );
                return RecvHandling::Completed;
            }
        };
        let iovecs = match import_recv_iovecs(notif.pid, &msg) {
            Ok(iovecs) => iovecs,
            Err(errno) => {
                send_recvmmsg_result_or_errno(listener_fd, &notif, &state, Some(errno), false);
                return RecvHandling::Completed;
            }
        };
        let capacity = iovecs
            .iter()
            .try_fold(0_usize, |acc, iov| acc.checked_add(iov.len))
            .filter(|len| *len <= MAX_UDP_PAYLOAD)
            .unwrap_or(MAX_UDP_PAYLOAD);
        let mut recv_flags = flags & !libc::MSG_WAITFORONE;
        if state.completed > 0 && flags & libc::MSG_WAITFORONE != 0 {
            recv_flags |= libc::MSG_DONTWAIT;
        }

        match recv_msg_from_relay_fd(
            listener_fd,
            notif.id,
            relay_fd.as_raw_fd(),
            capacity,
            recv_flags,
            &handle.pending_sources,
            false,
        ) {
            Ok(received) => {
                if write_recvmsg_result(
                    notif.pid,
                    entry_ptr,
                    &msg,
                    &iovecs,
                    handle.domain,
                    &received,
                )
                .is_err()
                    || write_proc_bytes(
                        notif.pid,
                        entry_ptr + X86_64_MMSGHDR_LEN_OFFSET,
                        &(received.result_len as u32).to_ne_bytes(),
                    )
                    .is_err()
                {
                    send_recvmmsg_result_or_errno(
                        listener_fd,
                        &notif,
                        &state,
                        Some(libc::EFAULT),
                        false,
                    );
                    return RecvHandling::Completed;
                }
                state.completed += 1;
                state.reset_rcvtimeo_deadline();
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let now = Instant::now();
                let deadline_expired = state.deadline.is_some_and(|deadline| deadline <= now);
                let rcvtimeo_expired = state
                    .rcvtimeo_deadline
                    .is_some_and(|deadline| deadline <= now);
                if state.completed > 0
                    && (nonblocking
                        || flags & libc::MSG_WAITFORONE != 0
                        || deadline_expired
                        || rcvtimeo_expired)
                {
                    send_recvmmsg_result_or_errno(listener_fd, &notif, &state, None, false);
                    return RecvHandling::Completed;
                }
                // When both timers are expired the earlier one keeps its own
                // result: an explicit timespec returns the batch count (zero
                // included) instead of Linux's documented quiet-socket hang,
                // while an expired SO_RCVTIMEO matches the kernel's EAGAIN.
                let explicit_governs = deadline_expired
                    && state.deadline.is_some_and(|explicit| {
                        state
                            .rcvtimeo_deadline
                            .is_none_or(|rcvtimeo| explicit <= rcvtimeo)
                    });
                if explicit_governs {
                    send_recvmmsg_result_or_errno(listener_fd, &notif, &state, None, true);
                    return RecvHandling::Completed;
                }
                if rcvtimeo_expired {
                    send_recvmmsg_result_or_errno(
                        listener_fd,
                        &notif,
                        &state,
                        Some(libc::EAGAIN),
                        false,
                    );
                    return RecvHandling::Completed;
                }
                if nonblocking {
                    send_recvmmsg_result_or_errno(
                        listener_fd,
                        &notif,
                        &state,
                        Some(libc::EAGAIN),
                        false,
                    );
                    return RecvHandling::Completed;
                }
                return RecvHandling::Deferred {
                    relay_fd,
                    relay: handle.target_identity,
                    state,
                };
            }
            Err(err) => {
                send_recvmmsg_result_or_errno(
                    listener_fd,
                    &notif,
                    &state,
                    Some(errno_from_io(&err)),
                    false,
                );
                return RecvHandling::Completed;
            }
        }
    }

    send_recvmmsg_result_or_errno(listener_fd, &notif, &state, None, false);
    RecvHandling::Completed
}

pub(super) fn send_recvmmsg_result_or_errno(
    listener_fd: RawFd,
    notif: &SeccompNotif,
    state: &BlockingRecvState,
    errno: Option<i32>,
    explicit_timeout_expired: bool,
) {
    // Linux writes the remaining explicit timeout after both a nonempty batch
    // and an explicit expiry. A failed final write overrides any batch count.
    if (state.completed > 0 || explicit_timeout_expired)
        && write_recvmmsg_remaining_timeout(notif.pid, notif.data.args[4], state.deadline).is_err()
    {
        seccomp::send_errno(listener_fd, notif.id, libc::EFAULT);
        return;
    }
    if state.completed > 0 {
        seccomp::send_value(listener_fd, notif.id, state.completed as i64);
    } else if let Some(errno) = errno {
        seccomp::send_errno(listener_fd, notif.id, errno);
    } else {
        seccomp::send_success(listener_fd, notif.id);
    }
}

pub(super) fn recv_from_relay_fd(
    listener_fd: RawFd,
    notif_id: u64,
    relay_fd: RawFd,
    capacity: usize,
    flags: i32,
    pending: &Mutex<VecDeque<Destination>>,
    wait_for_readable: bool,
) -> io::Result<RelayRecvfrom> {
    let nonblocking = recv_is_nonblocking(relay_fd, flags);
    let mut payload = vec![0_u8; capacity];
    loop {
        if !nonblocking && wait_for_readable && !seccomp::notif_id_valid(listener_fd, notif_id) {
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
                if err.kind() == io::ErrorKind::WouldBlock && !nonblocking && wait_for_readable {
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
pub(super) fn claim_datagram(
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

pub(super) fn recv_msg_from_relay_fd(
    listener_fd: RawFd,
    notif_id: u64,
    relay_fd: RawFd,
    capacity: usize,
    flags: i32,
    pending: &Mutex<VecDeque<Destination>>,
    wait_for_readable: bool,
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
        if !nonblocking && wait_for_readable && !seccomp::notif_id_valid(listener_fd, notif_id) {
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
                if err.kind() == io::ErrorKind::WouldBlock && !nonblocking && wait_for_readable {
                    wait_for_relay_readable(listener_fd, notif_id, relay_fd)?;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

pub(super) fn recv_is_nonblocking(fd: RawFd, flags: i32) -> bool {
    flags & libc::MSG_DONTWAIT != 0
        || fd_status_flags(fd)
            .map(|status_flags| status_flags & libc::O_NONBLOCK != 0)
            .unwrap_or(false)
}

pub(super) fn wait_for_relay_readable(
    listener_fd: RawFd,
    notif_id: u64,
    fd: RawFd,
) -> io::Result<()> {
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

pub(super) fn socket_error(fd: RawFd) -> Option<io::Error> {
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

pub(super) fn notification_interrupted() -> io::Error {
    io::Error::from_raw_os_error(libc::EINTR)
}

/// Reads the target-visible `SO_RCVTIMEO`. A zero timeout means "block forever"
/// and maps to `None`, as does a read failure: an unreadable option must
/// degrade to the previous unbounded wait rather than fail the receive.
pub(super) fn socket_recv_timeout(fd: RawFd) -> Option<Duration> {
    let mut timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of_val(&timeout) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&mut timeout as *mut libc::timeval).cast(),
            &mut len,
        )
    };
    if rc != 0 || timeout.tv_sec < 0 || timeout.tv_usec < 0 {
        return None;
    }
    if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
        return None;
    }
    Some(Duration::from_secs(timeout.tv_sec as u64) + Duration::from_micros(timeout.tv_usec as u64))
}

pub(super) fn set_socket_recv_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let tv_sec = libc::time_t::try_from(timeout.as_secs()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SO_RCVTIMEO duration does not fit timeval",
        )
    })?;
    let value = libc::timeval {
        tv_sec,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&value as *const libc::timeval).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn read_recvmmsg_deadline(
    pid: u32,
    timeout_ptr: u64,
    received_at: Instant,
) -> io::Result<Option<Instant>> {
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let raw = read_proc_bytes(pid, timeout_ptr, X86_64_TIMESPEC_SIZE)?;
    let duration = parse_recvmmsg_timeout(&raw)?;
    received_at
        .checked_add(duration)
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "recvmmsg timeout overflow"))
}

pub(super) fn write_recvmmsg_remaining_timeout(
    pid: u32,
    timeout_ptr: u64,
    deadline: Option<Instant>,
) -> io::Result<()> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    debug_assert_ne!(timeout_ptr, 0);
    let remaining = deadline.saturating_duration_since(Instant::now());
    let seconds = i64::try_from(remaining.as_secs()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "recvmmsg remaining timeout does not fit timespec",
        )
    })?;
    let nanos = i64::from(remaining.subsec_nanos());
    let mut raw = [0_u8; X86_64_TIMESPEC_SIZE];
    raw[0..8].copy_from_slice(&seconds.to_ne_bytes());
    raw[8..16].copy_from_slice(&nanos.to_ne_bytes());
    write_proc_bytes(pid, timeout_ptr, &raw)
}

pub(super) fn parse_recvmmsg_timeout(raw: &[u8]) -> io::Result<Duration> {
    if raw.len() != X86_64_TIMESPEC_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid x86_64 timespec size",
        ));
    }
    let seconds = i64::from_ne_bytes(raw[0..8].try_into().unwrap());
    let nanos = i64::from_ne_bytes(raw[8..16].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recvmmsg timeout",
        ));
    }
    Ok(Duration::new(seconds as u64, nanos as u32))
}

pub(super) fn write_iovec_payload(
    pid: u32,
    iovecs: &[TargetIovec],
    payload: &[u8],
) -> io::Result<()> {
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

pub(super) fn write_recvmsg_result(
    pid: u32,
    msg_ptr: u64,
    msg: &TargetMsghdr,
    iovecs: &[TargetIovec],
    domain: i32,
    received: &RelayRecvmsg,
) -> io::Result<()> {
    write_iovec_payload(pid, iovecs, &received.payload)?;
    write_proc_bytes(
        pid,
        msg_ptr + X86_64_MSGHDR_FLAGS_OFFSET,
        &received.msg_flags.to_ne_bytes(),
    )?;
    if msg.name != 0 {
        if let Some(source) = received.source {
            write_sockaddr_to_msghdr(pid, msg_ptr, msg.name, msg.name_len, domain, source)?;
        }
    }
    Ok(())
}

pub(super) fn write_sockaddr_to_msghdr(
    pid: u32,
    msg_ptr: u64,
    addr: u64,
    addr_len: u32,
    domain: i32,
    source: Destination,
) -> io::Result<()> {
    let (raw, raw_len) = sockaddr_bytes(udp_domain_logical_address(domain, source));
    let write_len = (addr_len as usize).min(raw_len);
    write_proc_bytes(pid, addr, &raw[..write_len])?;
    write_proc_bytes(
        pid,
        msg_ptr + X86_64_MSGHDR_NAME_LEN_OFFSET as u64,
        &(raw_len as u32).to_ne_bytes(),
    )
}

pub(super) fn send_recv_error(listener_fd: RawFd, notif_id: u64, err: &io::Error) {
    if err.kind() == io::ErrorKind::Interrupted && !seccomp::notif_id_valid(listener_fd, notif_id) {
        return;
    }
    seccomp::send_errno(listener_fd, notif_id, errno_from_io(err));
}
