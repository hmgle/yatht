use super::*;

#[derive(Debug)]
pub(super) struct TargetMsghdr {
    pub(super) name: u64,
    pub(super) name_len: u32,
    pub(super) iov: u64,
    pub(super) iov_len: u64,
}

pub(super) fn read_msghdr(pid: u32, msg_ptr: u64) -> io::Result<TargetMsghdr> {
    let raw = read_proc_bytes(pid, msg_ptr, X86_64_MSGHDR_SIZE)?;
    Ok(TargetMsghdr {
        name: u64::from_ne_bytes(raw[0..8].try_into().unwrap()),
        name_len: u32::from_ne_bytes(
            raw[X86_64_MSGHDR_NAME_LEN_OFFSET..X86_64_MSGHDR_NAME_LEN_OFFSET + 4]
                .try_into()
                .unwrap(),
        ),
        iov: u64::from_ne_bytes(
            raw[X86_64_MSGHDR_IOV_OFFSET..X86_64_MSGHDR_IOV_OFFSET + 8]
                .try_into()
                .unwrap(),
        ),
        iov_len: u64::from_ne_bytes(
            raw[X86_64_MSGHDR_IOV_LEN_OFFSET..X86_64_MSGHDR_IOV_LEN_OFFSET + 8]
                .try_into()
                .unwrap(),
        ),
    })
}

#[derive(Clone, Copy)]
pub(super) struct TargetIovec {
    pub(super) base: u64,
    pub(super) len: usize,
}

pub(super) fn read_iovec_targets(
    pid: u32,
    iov_ptr: u64,
    iov_len: u64,
) -> io::Result<Vec<TargetIovec>> {
    if iov_len > UIO_MAXIOV as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many iovecs",
        ));
    }
    let raw = read_proc_bytes(
        pid,
        iov_ptr,
        (iov_len as usize).saturating_mul(X86_64_IOVEC_SIZE),
    )?;
    let mut iovecs = Vec::with_capacity(iov_len as usize);
    for index in 0..iov_len {
        let offset = index as usize * X86_64_IOVEC_SIZE;
        let base = u64::from_ne_bytes(raw[offset..offset + 8].try_into().unwrap());
        let len = u64::from_ne_bytes(
            raw[offset + 8..offset + X86_64_IOVEC_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        iovecs.push(TargetIovec { base, len });
    }
    Ok(iovecs)
}

pub(super) fn iovec_total_len(iovecs: &[TargetIovec]) -> io::Result<usize> {
    iovecs.iter().try_fold(0_usize, |acc, iov| {
        acc.checked_add(iov.len)
            .filter(|len| *len <= MAX_UDP_PAYLOAD)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UDP payload too large"))
    })
}

pub(super) fn read_iovec_payload(
    pid: u32,
    iovecs: &[TargetIovec],
    total_len: usize,
) -> io::Result<Vec<u8>> {
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

pub(super) fn read_socklen(pid: u32, addr: u64) -> io::Result<u32> {
    let raw = read_proc_bytes(pid, addr, std::mem::size_of::<libc::socklen_t>())?;
    Ok(u32::from_ne_bytes(raw.try_into().unwrap()))
}

pub(super) fn read_signed_socklen(pid: u32, addr: u64) -> io::Result<i32> {
    let raw = read_proc_bytes(pid, addr, std::mem::size_of::<libc::socklen_t>())?;
    Ok(i32::from_ne_bytes(raw.try_into().unwrap()))
}

pub(super) fn write_sockaddr_result(
    pid: u32,
    addr: u64,
    addr_len_ptr: u64,
    addr_len: u32,
    domain: i32,
    source: Destination,
) -> io::Result<()> {
    let (raw, raw_len) = sockaddr_bytes(udp_domain_logical_address(domain, source));
    let write_len = (addr_len as usize).min(raw_len);
    if write_len > 0 {
        write_proc_bytes(pid, addr, &raw[..write_len])?;
    }
    write_proc_bytes(pid, addr_len_ptr, &(raw_len as u32).to_ne_bytes())
}

pub(super) fn sockaddr_bytes(dest: Destination) -> ([u8; SOCKADDR_IN6_SIZE], usize) {
    let mut raw = [0_u8; SOCKADDR_IN6_SIZE];
    match dest.ip {
        IpAddr::V4(ip) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&dest.port.to_be_bytes());
            raw[4..8].copy_from_slice(&ip.octets());
            (raw, SOCKADDR_IN_SIZE)
        }
        IpAddr::V6(ip) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&dest.port.to_be_bytes());
            raw[8..24].copy_from_slice(&ip.octets());
            (raw, SOCKADDR_IN6_SIZE)
        }
    }
}

pub(super) fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

pub(super) fn thread_group_id(pid: u32) -> io::Result<u32> {
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

pub(super) fn read_sockaddr(pid: u32, addr: u64, addr_len: usize) -> io::Result<Vec<u8>> {
    let family_len = addr_len.min(2);
    let family_raw = read_proc_bytes(pid, addr, family_len)?;
    if family_raw.len() < 2 {
        return Ok(family_raw);
    }

    let family = u16::from_ne_bytes([family_raw[0], family_raw[1]]) as i32;
    let needed_len = match family {
        libc::AF_INET => SOCKADDR_IN_SIZE,
        libc::AF_INET6 => SOCKADDR_IN6_SIZE,
        _ => return Ok(family_raw),
    };
    read_proc_bytes(pid, addr, addr_len.min(needed_len).min(128))
}

pub(super) fn read_proc_bytes(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut raw = vec![0_u8; len];
    if len == 0 {
        return Ok(raw);
    }
    process_vm_read(pid, addr, &mut raw)?;
    Ok(raw)
}

pub(super) fn write_proc_bytes(pid: u32, mut addr: u64, mut buf: &[u8]) -> io::Result<()> {
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

pub(super) fn process_vm_read(pid: u32, mut addr: u64, mut buf: &mut [u8]) -> io::Result<()> {
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

pub(super) fn process_vm_write(pid: u32, addr: u64, buf: &[u8]) -> io::Result<usize> {
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

pub(super) fn process_vm_readv_all(
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

pub(super) fn process_vm_writev_all(
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

pub(super) fn iovecs_len(iovecs: &[libc::iovec]) -> usize {
    iovecs.iter().map(|iov| iov.iov_len).sum()
}

pub(super) fn advance_iovecs(iovecs: &mut [libc::iovec], start: &mut usize, mut bytes: usize) {
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

pub(super) fn parse_sockaddr(raw: &[u8]) -> Result<Destination> {
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

pub(super) fn parse_sockaddr_in(raw: &[u8]) -> Result<Destination> {
    if raw.len() < SOCKADDR_IN_SIZE {
        bail!("sockaddr_in too short");
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    Ok(Destination {
        ip: IpAddr::V4(ip),
        port,
    })
}

pub(super) fn parse_sockaddr_in6(raw: &[u8]) -> Result<Destination> {
    if raw.len() < SOCKADDR_IN6_MIN_SIZE {
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

pub(super) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

pub(super) fn set_child_subreaper() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn socketpair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

pub(super) fn recv_listener_fd(sock: RawFd, child_pid: u32) -> io::Result<OwnedFd> {
    let mut raw = [0_u8; std::mem::size_of::<RawFd>()];
    read_exact_fd(sock, &mut raw)?;
    let child_listener_fd = RawFd::from_ne_bytes(raw);
    duplicate_remote_fd(child_pid, child_listener_fd)
}

pub(super) fn duplicate_remote_fd(pid: u32, fd: RawFd) -> io::Result<OwnedFd> {
    let cache = THREAD_PIDFD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();
    ensure_cached_thread_pidfd(&mut cache, pid)?;
    let first = duplicate_remote_fd_from_pidfd(cache[&pid].pidfd.as_raw_fd(), fd);
    if !matches!(&first, Err(err) if err.raw_os_error() == Some(libc::ESRCH)) {
        return first;
    }

    // A dead cached pidfd can share its numeric TID with a newly created
    // thread. Refresh only on ESRCH; EBADF may describe the requested target
    // fd and must be returned unchanged.
    cache.remove(&pid);
    ensure_cached_thread_pidfd(&mut cache, pid)?;
    duplicate_remote_fd_from_pidfd(cache[&pid].pidfd.as_raw_fd(), fd)
}

pub(super) fn duplicate_remote_fd_from_pidfd(pidfd: RawFd, fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) };
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated as RawFd) })
    }
}

pub(super) fn pidfd_open(pid: u32, flags: libc::c_uint) -> io::Result<OwnedFd> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, flags) };
    if pidfd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) })
    }
}

pub(super) fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
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

pub(super) fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
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

pub(super) fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}
