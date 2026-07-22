use std::io;
use std::net::{Shutdown, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crossbeam_channel as channel;

const REGISTRATION_QUEUE_CAPACITY: usize = 128;
const RELAY_BUFFER_CAPACITY: usize = 64 * 1024;
const READ_CHUNK_SIZE: usize = 16 * 1024;

#[derive(Clone)]
pub struct TcpBroker {
    tx: channel::Sender<BrokerCommand>,
    wake_fd: Arc<OwnedFd>,
}

pub struct TcpBrokerReactor {
    rx: channel::Receiver<BrokerCommand>,
    wake_fd: Arc<OwnedFd>,
    relays: Vec<TcpRelay>,
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
}

#[derive(Default)]
struct PendingBuffer {
    bytes: Vec<u8>,
    offset: usize,
}

impl TcpBroker {
    pub fn new() -> io::Result<(Self, TcpBrokerReactor)> {
        let wake_fd = Arc::new(create_eventfd()?);
        let (tx, rx) = channel::bounded(REGISTRATION_QUEUE_CAPACITY);
        Ok((
            Self {
                tx,
                wake_fd: Arc::clone(&wake_fd),
            },
            TcpBrokerReactor {
                rx,
                wake_fd,
                relays: Vec::new(),
            },
        ))
    }

    pub fn register(&self, target: TcpStream, upstream: TcpStream) -> io::Result<()> {
        let relay = TcpRelay::new(target, upstream)?;
        self.tx
            .try_send(BrokerCommand::Register(relay))
            .map_err(|err| match err {
                channel::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "TCP broker queue is full")
                }
                channel::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "TCP broker stopped")
                }
            })?;
        wake_eventfd(self.wake_fd.as_raw_fd())
    }

    #[cfg(test)]
    fn shutdown(&self) -> io::Result<()> {
        self.tx
            .send(BrokerCommand::Shutdown)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP broker stopped"))?;
        wake_eventfd(self.wake_fd.as_raw_fd())
    }
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
                    events: relay.target_events(),
                    revents: 0,
                });
                pollfds.push(libc::pollfd {
                    fd: relay.upstream.as_raw_fd(),
                    events: relay.upstream_events(),
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
                if self.drain_commands()? {
                    return Ok(());
                }
            }

            let polled_relays = (pollfds.len() - 1) / 2;
            for index in (0..polled_relays).rev() {
                let target_events = pollfds[1 + index * 2].revents;
                let upstream_events = pollfds[2 + index * 2].revents;
                let relay = &mut self.relays[index];
                if relay.process(target_events, upstream_events).is_err() || relay.is_finished() {
                    self.relays.swap_remove(index);
                }
            }
        }
    }

    fn drain_commands(&mut self) -> io::Result<bool> {
        loop {
            match self.rx.try_recv() {
                Ok(BrokerCommand::Register(relay)) => self.relays.push(relay),
                #[cfg(test)]
                Ok(BrokerCommand::Shutdown) => return Ok(true),
                Err(channel::TryRecvError::Empty) => return Ok(false),
                Err(channel::TryRecvError::Disconnected) => return Ok(true),
            }
        }
    }
}

impl TcpRelay {
    fn new(target: TcpStream, upstream: TcpStream) -> io::Result<Self> {
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
        })
    }

    fn target_events(&self) -> libc::c_short {
        let mut events = libc::POLLRDHUP;
        if !self.target_read_eof && !self.target_to_upstream.is_full() {
            events |= libc::POLLIN;
        }
        if !self.target_write_shutdown && !self.upstream_to_target.is_empty() {
            events |= libc::POLLOUT;
        }
        events
    }

    fn upstream_events(&self) -> libc::c_short {
        let mut events = libc::POLLRDHUP;
        if !self.upstream_read_eof && !self.upstream_to_target.is_full() {
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
            flush_socket(&self.target, &mut self.upstream_to_target)?;
        }
        if upstream_events & libc::POLLOUT != 0 {
            flush_socket(&self.upstream, &mut self.target_to_upstream)?;
        }
        let target_read = if target_events
            & (libc::POLLIN | libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR)
            != 0
        {
            read_socket(&self.target, &mut self.target_to_upstream)?
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
            read_socket(&self.upstream, &mut self.upstream_to_target)?
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
        }
        if self.upstream_read_eof
            && self.upstream_to_target.is_empty()
            && !self.target_write_shutdown
        {
            let _ = self.target.shutdown(Shutdown::Write);
            self.target_write_shutdown = true;
        }
    }

    fn is_finished(&self) -> bool {
        self.target_read_eof
            && self.upstream_read_eof
            && self.target_to_upstream.is_empty()
            && self.upstream_to_target.is_empty()
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

fn read_socket(stream: &TcpStream, pending: &mut PendingBuffer) -> io::Result<ReadOutcome> {
    if pending.is_full() {
        return Ok(ReadOutcome::Idle);
    }
    let mut chunk = [0_u8; READ_CHUNK_SIZE];
    let available = RELAY_BUFFER_CAPACITY - pending.len();
    loop {
        let rc = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len().min(available),
                libc::MSG_DONTWAIT,
            )
        };
        if rc > 0 {
            pending.append(&chunk[..rc as usize]);
            return Ok(ReadOutcome::Progress);
        }
        if rc == 0 {
            return Ok(ReadOutcome::Eof);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(ReadOutcome::Idle);
        }
        return Err(err);
    }
}

fn flush_socket(stream: &TcpStream, pending: &mut PendingBuffer) -> io::Result<()> {
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
        if rc > 0 {
            pending.consume(rc as usize);
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
        let (broker, reactor) = TcpBroker::new().unwrap();
        let reactor_thread = thread::spawn(move || reactor.run().unwrap());
        let (mut target, broker_target) = tcp_pair();
        let (broker_upstream, mut remote) = tcp_pair();
        set_timeout(&target);
        set_timeout(&remote);
        broker.register(broker_target, broker_upstream).unwrap();

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
        let (broker, reactor) = TcpBroker::new().unwrap();
        let reactor_thread = thread::spawn(move || reactor.run().unwrap());
        let (mut stalled_target, stalled_broker_target) = tcp_pair();
        let (stalled_broker_upstream, _stalled_remote) = tcp_pair();
        broker
            .register(stalled_broker_target, stalled_broker_upstream)
            .unwrap();

        let payload = vec![0x5a; RELAY_BUFFER_CAPACITY * 4];
        thread::spawn(move || {
            let _ = stalled_target.write_all(&payload);
        });

        let (mut active_target, active_broker_target) = tcp_pair();
        let (active_broker_upstream, mut active_remote) = tcp_pair();
        set_timeout(&active_target);
        set_timeout(&active_remote);
        broker
            .register(active_broker_target, active_broker_upstream)
            .unwrap();
        active_target.write_all(b"ping").unwrap();
        let mut received = [0_u8; 4];
        active_remote.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ping");

        broker.shutdown().unwrap();
        reactor_thread.join().unwrap();
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
