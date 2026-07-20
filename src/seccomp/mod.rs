use std::cell::RefCell;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;

pub const USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;
pub const ADDFD_FLAG_SETFD: u32 = 1 << 0;

thread_local! {
    static NOTIFICATION_ERROR: RefCell<Option<io::Error>> = const { RefCell::new(None) };
}

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifSizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrapSet {
    pub connect: bool,
    pub sendto: bool,
    pub sendmsg: bool,
    pub recvfrom: bool,
    pub recvmsg: bool,
    pub close: bool,
    pub close_range: bool,
    pub dup2: bool,
    pub dup3: bool,
}

impl TrapSet {
    pub fn tcp_only() -> Self {
        Self {
            connect: true,
            sendto: false,
            sendmsg: false,
            recvfrom: false,
            recvmsg: false,
            close: false,
            close_range: false,
            dup2: false,
            dup3: false,
        }
    }

    pub fn with_udp() -> Self {
        Self {
            connect: true,
            sendto: true,
            sendmsg: true,
            recvfrom: true,
            recvmsg: true,
            close: true,
            close_range: true,
            dup2: true,
            dup3: true,
        }
    }

    pub fn encode(self) -> String {
        let mut bits = 0_u16;
        if self.connect {
            bits |= 1 << 0;
        }
        if self.sendto {
            bits |= 1 << 1;
        }
        if self.sendmsg {
            bits |= 1 << 2;
        }
        if self.recvfrom {
            bits |= 1 << 3;
        }
        if self.recvmsg {
            bits |= 1 << 4;
        }
        if self.close {
            bits |= 1 << 5;
        }
        if self.close_range {
            bits |= 1 << 6;
        }
        if self.dup2 {
            bits |= 1 << 7;
        }
        if self.dup3 {
            bits |= 1 << 8;
        }
        bits.to_string()
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let bits = raw.parse::<u16>().ok()?;
        if bits & !0b1_1111_1111 != 0 {
            return None;
        }
        Some(Self {
            connect: bits & (1 << 0) != 0,
            sendto: bits & (1 << 1) != 0,
            sendmsg: bits & (1 << 2) != 0,
            recvfrom: bits & (1 << 3) != 0,
            recvmsg: bits & (1 << 4) != 0,
            close: bits & (1 << 5) != 0,
            close_range: bits & (1 << 6) != 0,
            dup2: bits & (1 << 7) != 0,
            dup3: bits & (1 << 8) != 0,
        })
    }

    fn syscalls(self) -> Vec<u32> {
        let mut nrs = Vec::new();
        if self.connect {
            nrs.push(libc::SYS_connect as u32);
        }
        if self.sendto {
            nrs.push(libc::SYS_sendto as u32);
        }
        if self.sendmsg {
            nrs.push(libc::SYS_sendmsg as u32);
        }
        if self.recvfrom {
            nrs.push(libc::SYS_recvfrom as u32);
        }
        if self.recvmsg {
            nrs.push(libc::SYS_recvmsg as u32);
        }
        if self.close {
            nrs.push(libc::SYS_close as u32);
        }
        if self.close_range {
            nrs.push(libc::SYS_close_range as u32);
        }
        if self.dup2 {
            nrs.push(libc::SYS_dup2 as u32);
        }
        if self.dup3 {
            nrs.push(libc::SYS_dup3 as u32);
        }
        nrs
    }
}

pub fn query_notif_sizes() -> io::Result<SeccompNotifSizes> {
    let mut sizes = SeccompNotifSizes::default();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let local_notif = mem::size_of::<SeccompNotif>() as u16;
    let local_resp = mem::size_of::<SeccompNotifResp>() as u16;
    let local_data = mem::size_of::<SeccompData>() as u16;
    if sizes.seccomp_notif > local_notif
        || sizes.seccomp_notif_resp > local_resp
        || sizes.seccomp_data > local_data
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "kernel seccomp notif structs are larger than compiled ABI: kernel=({},{},{}) local=({},{},{})",
                sizes.seccomp_notif,
                sizes.seccomp_notif_resp,
                sizes.seccomp_data,
                local_notif,
                local_resp,
                local_data
            ),
        ));
    }
    Ok(sizes)
}

pub fn install_listener(traps: TrapSet) -> io::Result<RawFd> {
    let mut filter = socket_filter(traps);
    let mut prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &mut prog as *mut libc::sock_fprog,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as RawFd)
    }
}

pub fn socket_filter(traps: TrapSet) -> Vec<libc::sock_filter> {
    let nrs = traps.syscalls();
    let mut filter = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    for (index, nr) in nrs.iter().enumerate() {
        let remaining = nrs.len() - 1 - index;
        let jump_to_user_notif = (remaining + 1) as u8;
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, jump_to_user_notif, 0));
    }
    filter.extend([
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    ]);
    filter
}

pub fn notif_recv(fd: RawFd) -> io::Result<SeccompNotif> {
    let mut notif = SeccompNotif::default();
    ioctl_mut(fd, ioctl_notif_recv(), &mut notif)?;
    Ok(notif)
}

pub fn notif_send(fd: RawFd, resp: &mut SeccompNotifResp) -> io::Result<()> {
    ioctl_mut_retry(fd, ioctl_notif_send(), resp)
}

pub fn notif_id_valid(fd: RawFd, id: u64) -> bool {
    let mut id = id;
    match ioctl_mut_retry(fd, ioctl_notif_id_valid(), &mut id) {
        Ok(()) => true,
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => false,
        Err(err) => {
            record_notification_error(err);
            false
        }
    }
}

pub fn take_notification_error() -> Option<io::Error> {
    NOTIFICATION_ERROR.with(|error| error.borrow_mut().take())
}

pub fn notif_addfd(fd: RawFd, addfd: &mut SeccompNotifAddfd) -> io::Result<RawFd> {
    let rc = unsafe { libc::ioctl(fd, ioctl_notif_addfd(), addfd as *mut SeccompNotifAddfd) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

pub fn send_continue(fd: RawFd, id: u64) {
    let mut resp = SeccompNotifResp {
        id,
        flags: USER_NOTIF_FLAG_CONTINUE,
        ..SeccompNotifResp::default()
    };
    if let Err(err) = notif_send(fd, &mut resp) {
        record_notification_error_unless_stale(err);
    }
}

pub fn send_success(fd: RawFd, id: u64) {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    if let Err(err) = notif_send(fd, &mut resp) {
        record_notification_error_unless_stale(err);
    }
}

pub fn send_errno(fd: RawFd, id: u64, errno: i32) {
    let mut resp = SeccompNotifResp {
        id,
        val: -1,
        error: -errno,
        flags: 0,
    };
    if let Err(err) = notif_send(fd, &mut resp) {
        record_notification_error_unless_stale(err);
    }
}

pub fn send_value(fd: RawFd, id: u64, value: i64) {
    let mut resp = SeccompNotifResp {
        id,
        val: value,
        error: 0,
        flags: 0,
    };
    if let Err(err) = notif_send(fd, &mut resp) {
        record_notification_error_unless_stale(err);
    }
}

fn record_notification_error_unless_stale(err: io::Error) {
    if err.raw_os_error() != Some(libc::ENOENT) {
        record_notification_error(err);
    }
}

fn record_notification_error(err: io::Error) {
    NOTIFICATION_ERROR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
    });
}

fn ioctl_mut_retry<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    loop {
        match ioctl_mut(fd, request, arg) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn ioctl_mut<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, request, arg as *mut T) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

const IOC_NRBITS: u8 = 8;
const IOC_TYPEBITS: u8 = 8;
const IOC_SIZEBITS: u8 = 14;

const IOC_NRSHIFT: u8 = 0;
const IOC_TYPESHIFT: u8 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u8 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u8 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_WRITE: u8 = 1;
const IOC_READ: u8 = 2;
const SECCOMP_IOC_MAGIC: u8 = b'!';

const fn ioc(dir: u8, ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    ((dir as libc::c_ulong) << IOC_DIRSHIFT)
        | ((ty as libc::c_ulong) << IOC_TYPESHIFT)
        | ((nr as libc::c_ulong) << IOC_NRSHIFT)
        | ((size as libc::c_ulong) << IOC_SIZESHIFT)
}

const fn iow<T>(nr: u8) -> libc::c_ulong {
    ioc(IOC_WRITE, SECCOMP_IOC_MAGIC, nr, mem::size_of::<T>())
}

const fn iowr<T>(nr: u8) -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        SECCOMP_IOC_MAGIC,
        nr,
        mem::size_of::<T>(),
    )
}

const fn ioctl_notif_recv() -> libc::c_ulong {
    iowr::<SeccompNotif>(0)
}

const fn ioctl_notif_send() -> libc::c_ulong {
    iowr::<SeccompNotifResp>(1)
}

const fn ioctl_notif_id_valid() -> libc::c_ulong {
    iow::<u64>(2)
}

const fn ioctl_notif_addfd() -> libc::c_ulong {
    iow::<SeccompNotifAddfd>(3)
}

#[allow(dead_code)]
fn _assert_no_null_filter() {
    let _ = ptr::null::<libc::sock_filter>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_filter_shape() {
        let filter = socket_filter(TrapSet::tcp_only());
        assert_eq!(filter.len(), 7);
        assert_eq!(filter[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(filter[2].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(filter[4].k, libc::SYS_connect as u32);
        assert_eq!(filter[4].jt, 1);
        assert_eq!(filter[5].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[6].k, SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn socket_filter_traps_udp_senders() {
        let filter = socket_filter(TrapSet::with_udp());
        assert_eq!(filter.len(), 15);
        assert_eq!(filter[4].k, libc::SYS_connect as u32);
        assert_eq!(filter[5].k, libc::SYS_sendto as u32);
        assert_eq!(filter[6].k, libc::SYS_sendmsg as u32);
        assert_eq!(filter[7].k, libc::SYS_recvfrom as u32);
        assert_eq!(filter[8].k, libc::SYS_recvmsg as u32);
        assert_eq!(filter[9].k, libc::SYS_close as u32);
        assert_eq!(filter[10].k, libc::SYS_close_range as u32);
        assert_eq!(filter[11].k, libc::SYS_dup2 as u32);
        assert_eq!(filter[12].k, libc::SYS_dup3 as u32);
        assert_eq!(filter[13].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[14].k, SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn trap_set_round_trips() {
        assert_eq!(
            TrapSet::decode(&TrapSet::with_udp().encode()),
            Some(TrapSet::with_udp())
        );
    }

    #[test]
    fn trap_set_rejects_unknown_bits() {
        assert_eq!(TrapSet::decode("512"), None);
    }

    #[test]
    fn records_fatal_notification_ioctl_errors() {
        assert!(take_notification_error().is_none());
        assert!(!notif_id_valid(-1, 1));
        assert_eq!(
            take_notification_error().and_then(|err| err.raw_os_error()),
            Some(libc::EBADF)
        );

        send_continue(-1, 1);
        assert_eq!(
            take_notification_error().and_then(|err| err.raw_os_error()),
            Some(libc::EBADF)
        );
    }
}
