use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::{EffectiveConfig, Route};
use crate::proxy;
use crate::seccomp::{self, SeccompNotif, SeccompNotifAddfd};

const CHILD_STAGE_ENV: &str = "SUP_CHILD_STAGE";
const TARGET_PATH_ENV: &str = "SUP_TARGET_PATH";
const TARGET_ARGV_ENV: &str = "SUP_TARGET_ARGV";
const CONTROL_FD: RawFd = 3;

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

pub fn run(cfg: EffectiveConfig) -> Result<i32> {
    if cfg.command.is_empty() {
        bail!("missing command");
    }

    let target_path = resolve_target(&cfg.command[0])?;
    let argv = cfg.command.clone();
    let (parent_sock, child_sock) = socketpair().context("create control socketpair")?;

    let mut command = Command::new(std::env::current_exe().context("resolve current executable")?);
    command
        .env(CHILD_STAGE_ENV, "1")
        .env(
            TARGET_PATH_ENV,
            encode_os(&target_path.as_os_str().to_os_string())?,
        )
        .env(TARGET_ARGV_ENV, encode_os_list(&argv)?);

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

    let mut child = command.spawn().context("spawn child stage")?;
    close_fd(child_sock);

    let listener_fd = recv_fd(parent_sock).context("receive seccomp listener fd")?;
    write_all_fd(parent_sock, b"G").context("ack child stage")?;
    close_fd(parent_sock);

    let cfg = Arc::new(cfg);
    let loop_cfg = Arc::clone(&cfg);
    thread::spawn(move || notification_loop(listener_fd, loop_cfg));

    let status = child.wait().context("wait for target")?;
    if let Some(code) = status.code() {
        Ok(code)
    } else if let Some(signal) = status.signal() {
        Ok(128 + signal)
    } else {
        Ok(1)
    }
}

pub fn run_child_stage() -> Result<i32> {
    let target_path = decode_os(
        std::env::var(TARGET_PATH_ENV)
            .context("child stage missing target path")?
            .as_str(),
    )?;
    let argv = decode_os_list(
        std::env::var(TARGET_ARGV_ENV)
            .context("child stage missing target argv")?
            .as_str(),
    )?;

    set_no_new_privs().context("set PR_SET_NO_NEW_PRIVS")?;
    let listener_fd = seccomp::install_listener().context("install seccomp listener")?;
    send_fd(CONTROL_FD, listener_fd).context("send seccomp listener fd")?;
    close_fd(listener_fd);

    let mut ack = [0_u8; 1];
    read_exact_fd(CONTROL_FD, &mut ack).context("wait for supervisor ack")?;
    close_fd(CONTROL_FD);

    exec_target(target_path.into(), argv)
}

fn notification_loop(listener_fd: RawFd, cfg: Arc<EffectiveConfig>) {
    loop {
        match seccomp::notif_recv(listener_fd) {
            Ok(notif) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || handle_notification(listener_fd, notif, cfg));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                if cfg.debug {
                    eprintln!("seccomp-unotify-proxy: notification loop stopped: {err}");
                }
                close_fd(listener_fd);
                return;
            }
        }
    }
}

fn handle_notification(listener_fd: RawFd, notif: SeccompNotif, cfg: Arc<EffectiveConfig>) {
    if notif.data.nr != libc::SYS_connect as i32 {
        seccomp::send_continue(listener_fd, notif.id);
        return;
    }

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

    let dest = match parse_sockaddr(&raw) {
        Ok(dest) => dest,
        Err(_) => {
            seccomp::send_continue(listener_fd, notif.id);
            return;
        }
    };

    if cfg.route_for(dest.ip) == Route::Direct {
        if cfg.debug {
            eprintln!(
                "seccomp-unotify-proxy: direct {} for pid={} fd={}",
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
            "seccomp-unotify-proxy: proxy {} for pid={} fd={}",
            dest.authority(),
            notif.pid,
            target_fd
        );
    }

    let stream = match proxy::dial(&cfg.proxy, dest, cfg.connect_timeout) {
        Ok(stream) => stream,
        Err(err) => {
            if cfg.debug {
                eprintln!(
                    "seccomp-unotify-proxy: proxy dial {} failed: {err:#}",
                    dest.authority()
                );
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
            return;
        }
    };

    if !seccomp::notif_id_valid(listener_fd, notif.id) {
        return;
    }

    let target_flags = read_target_fd_flags(notif.pid, target_fd);
    if target_flags.status_flags & libc::O_NONBLOCK != 0 {
        let _ = set_nonblocking(stream.as_raw_fd());
    }

    let mut addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: seccomp::ADDFD_FLAG_SETFD,
        srcfd: stream.as_raw_fd() as u32,
        newfd: target_fd as u32,
        newfd_flags: target_flags.newfd_flags,
    };

    match seccomp::notif_addfd(listener_fd, &mut addfd) {
        Ok(_) => seccomp::send_success(listener_fd, notif.id),
        Err(err) => {
            if cfg.debug {
                eprintln!("seccomp-unotify-proxy: ADDFD failed: {err}");
            }
            seccomp::send_errno(listener_fd, notif.id, libc::ECONNREFUSED);
        }
    }
}

fn exec_target(target_path: PathBuf, argv: Vec<OsString>) -> Result<i32> {
    if argv.is_empty() {
        bail!("target argv is empty");
    }

    let mut command = Command::new(&target_path);
    command.arg0(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }

    let env = std::env::vars_os()
        .filter(|(key, _)| {
            key != CHILD_STAGE_ENV && key != TARGET_PATH_ENV && key != TARGET_ARGV_ENV
        })
        .collect::<Vec<_>>();
    command.env_clear().envs(env);

    let err = command.exec();
    Err(anyhow!("exec {}: {err}", target_path.display()))
}

fn resolve_target(cmd: &OsStr) -> Result<PathBuf> {
    let path = PathBuf::from(cmd);
    if path.components().count() > 1 {
        return Ok(path);
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(cmd);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("cannot find command {:?}", cmd);
}

fn is_executable(path: &PathBuf) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

fn read_sockaddr(pid: u32, addr: u64, addr_len: usize) -> io::Result<Vec<u8>> {
    let len = addr_len.min(128);
    let mut raw = vec![0_u8; len];
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    mem.read_exact_at(&mut raw, addr)?;
    Ok(raw)
}

fn parse_sockaddr(raw: &[u8]) -> Result<Destination> {
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

fn parse_sockaddr_in(raw: &[u8]) -> Result<Destination> {
    if raw.len() < 8 {
        bail!("sockaddr_in too short");
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    Ok(Destination {
        ip: IpAddr::V4(ip),
        port,
    })
}

fn parse_sockaddr_in6(raw: &[u8]) -> Result<Destination> {
    if raw.len() < 28 {
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

#[derive(Default)]
struct TargetFdFlags {
    status_flags: i32,
    newfd_flags: u32,
}

fn read_target_fd_flags(pid: u32, fd: RawFd) -> TargetFdFlags {
    let mut flags = TargetFdFlags::default();

    if let Ok(file) = File::open(format!("/proc/{pid}/fd/{fd}")) {
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if rc >= 0 {
            flags.status_flags = rc;
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

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socketpair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; unsafe { libc::CMSG_SPACE(mem_size_of_raw_fd() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem_size_of_raw_fd() as u32) as usize;
        let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
        *data = fd;
        msg.msg_controllen = (*cmsg).cmsg_len;

        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = vec![0_u8; unsafe { libc::CMSG_SPACE(mem_size_of_raw_fd() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::other("missing SCM_RIGHTS fd"));
        }
        let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
        Ok(*data)
    }
}

fn mem_size_of_raw_fd() -> usize {
    std::mem::size_of::<RawFd>()
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
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

fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
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

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn encode_os(value: &OsString) -> Result<String> {
    serde_json::to_string(value.as_bytes()).context("encode os string")
}

fn decode_os(raw: &str) -> Result<OsString> {
    let bytes: Vec<u8> = serde_json::from_str(raw).context("decode os string")?;
    Ok(OsString::from_vec(bytes))
}

fn encode_os_list(values: &[OsString]) -> Result<String> {
    let bytes = values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    serde_json::to_string(&bytes).context("encode os string list")
}

fn decode_os_list(raw: &str) -> Result<Vec<OsString>> {
    let bytes: Vec<Vec<u8>> = serde_json::from_str(raw).context("decode os string list")?;
    Ok(bytes.into_iter().map(OsString::from_vec).collect())
}

#[cfg(test)]
mod tests {
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
    fn os_list_round_trips() {
        let values = vec![
            OsString::from("curl"),
            OsString::from("https://example.com"),
        ];
        let encoded = encode_os_list(&values).unwrap();
        let decoded = decode_os_list(&encoded).unwrap();
        assert_eq!(values, decoded);
    }
}
