//! Independent UDP sends and receives. A silent peer never owns the worker.
use super::*;

// Bound work per direction so a busy sender or responder cannot starve the
// other direction or delay shutdown indefinitely.
const IO_BATCH: usize = 16;
// Separate streams preserve each original DNS destination even if replies
// arrive out of order or reuse transaction IDs across destinations.
const MAX_DNS_STREAMS: usize = 16;

struct DnsStream {
    source: Destination,
    connection: proxy::DnsTcpConnection,
}

#[derive(Default)]
struct Transports {
    dns: Vec<DnsStream>,
    socks: Option<proxy::Socks5UdpAssociation>,
    direct: Option<DirectUdpSocket>,
}

impl Transports {
    fn send(
        &mut self,
        cfg: &UdpRelayConfig,
        handle: &UdpRelayHandle,
        job: &UdpJob,
    ) -> Result<bool> {
        let deadline = proxy::Deadline::after(cfg.timeout);
        match job.route {
            UdpRouteKind::Direct => {
                send_direct_udp(&mut self.direct, &handle.local_bind, job.dest, &job.payload)?;
            }
            UdpRouteKind::Generic => {
                if self.socks.is_none() {
                    self.socks = Some(proxy::Socks5UdpAssociation::connect(&cfg.proxy, deadline)?);
                }
                self.socks
                    .as_ref()
                    .unwrap()
                    .send_datagram(job.dest, &job.payload)?;
            }
            UdpRouteKind::Dns => {
                let index = match self.dns.iter().position(|stream| stream.source == job.dest) {
                    Some(index) => index,
                    None => {
                        if self.dns.len() >= MAX_DNS_STREAMS {
                            bail!("UDP relay DNS stream limit of {MAX_DNS_STREAMS} reached");
                        }
                        self.dns.push(DnsStream {
                            source: job.dest,
                            connection: proxy::DnsTcpConnection::connect(
                                &cfg.proxy,
                                cfg.dns_server,
                                deadline,
                            )?,
                        });
                        self.dns.len() - 1
                    }
                };
                match self.dns[index]
                    .connection
                    .send_query(&job.payload, deadline)
                {
                    Ok(accepted) => return Ok(accepted),
                    Err(err) => {
                        // A partial write cannot be replayed safely. Discard
                        // this stream; the next job establishes a fresh one.
                        self.dns.remove(index);
                        return Err(err);
                    }
                }
            }
        }
        Ok(true)
    }

    fn receive(&mut self, cfg: &UdpRelayConfig, handle: &UdpRelayHandle) {
        if let Some(direct) = &mut self.direct {
            for _ in 0..IO_BATCH {
                match direct.sock.recv_from(&mut direct.recv_buf) {
                    Ok((n, source)) => deliver(
                        cfg,
                        handle,
                        UdpRelayResponse {
                            source: Destination {
                                ip: source.ip(),
                                port: source.port(),
                            },
                            payload: direct.recv_buf[..n].to_vec(),
                        },
                    ),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => {
                        log_error(cfg, &err.into());
                        break;
                    }
                }
            }
        }
        if let Some(socks) = &mut self.socks {
            for _ in 0..IO_BATCH {
                match socks.recv_datagram() {
                    Ok(Some(response)) => deliver(
                        cfg,
                        handle,
                        UdpRelayResponse {
                            source: response.source,
                            payload: response.payload,
                        },
                    ),
                    Ok(None) => break,
                    Err(err) => {
                        log_error(cfg, &err);
                        break;
                    }
                }
            }
        }
        self.dns.retain_mut(|stream| {
            // Read first: a server can send its final answer and close while
            // there are still queued writes. Preserve that answer before EOF.
            for _ in 0..IO_BATCH {
                match stream.connection.recv_response() {
                    Ok(Some(payload)) => deliver(
                        cfg,
                        handle,
                        UdpRelayResponse {
                            source: stream.source,
                            payload,
                        },
                    ),
                    Ok(None) => break,
                    Err(err) => {
                        if stream.connection.wants_write() {
                            cfg.observability.record_udp_job_dropped();
                        }
                        log_error(cfg, &err);
                        return false;
                    }
                }
            }
            if let Err(err) = stream.connection.flush() {
                cfg.observability.record_udp_job_dropped();
                log_error(cfg, &err);
                return false;
            }
            true
        });
    }

    fn poll(
        &self,
        handle: &UdpRelayHandle,
        pending: &[Option<(UdpJob, Instant)>; UDP_ROUTE_COUNT],
        queued: bool,
    ) -> io::Result<()> {
        let mut fds = vec![libc::pollfd {
            fd: handle.wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let mut add = |fd, writable| {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN | if writable { libc::POLLOUT } else { 0 },
                revents: 0,
            })
        };
        if let Some(direct) = &self.direct {
            add(
                direct.sock.as_raw_fd(),
                pending[UdpRouteKind::Direct.index()].is_some(),
            );
        }
        if let Some(socks) = &self.socks {
            add(socks.fd(), pending[UdpRouteKind::Generic.index()].is_some());
        }
        for stream in &self.dns {
            add(stream.connection.fd(), stream.connection.wants_write());
        }
        // The periodic wake checks stalled write deadlines. Data and shutdown
        // wake immediately; this is not a per-packet response wait.
        let timeout = if queued {
            0
        } else if pending.iter().any(Option::is_some)
            || self
                .dns
                .iter()
                .any(|stream| stream.connection.wants_write())
        {
            100
        } else {
            -1
        };
        // SAFETY: fds holds initialized pollfd entries for the duration of poll.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Ok(())
    }
}

pub(super) fn udp_relay_io(
    cfg: UdpRelayConfig,
    handle: UdpRelayHandle,
    rx: [channel::Receiver<UdpJob>; UDP_ROUTE_COUNT],
) {
    let mut transports = Transports::default();
    let mut pending: [Option<(UdpJob, Instant)>; UDP_ROUTE_COUNT] = std::array::from_fn(|_| None);
    while !handle.shutdown.load(Ordering::SeqCst) {
        let _ = drain_eventfd(handle.wake.as_raw_fd());
        // AF_UNSPEC disconnect can release an automatic bind. Do not keep
        // receiving on the old port after the logical socket has lost it.
        if let Some(direct) = &transports.direct {
            let bound = handle.local_bind.lock().unwrap();
            if bound
                .as_ref()
                .and_then(|local| socket_cookie(local.socket.as_raw_fd()))
                != Some(direct.cookie)
            {
                transports.direct = None;
            }
        }
        transports.receive(&cfg, &handle);
        // Preserve FIFO within each route, but never let an unwritable
        // transport prevent another route from sending its admitted jobs.
        for (rx, pending) in rx.iter().zip(pending.iter_mut()) {
            for _ in 0..IO_BATCH {
                if handle.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let (job, started) = match pending.take() {
                    Some(job) => job,
                    None => match rx.try_recv() {
                        Ok(job) => (job, Instant::now()),
                        Err(_) => break,
                    },
                };
                if started.elapsed() >= cfg.timeout {
                    cfg.observability.record_udp_job_dropped();
                    log_error(&cfg, &anyhow!("UDP relay send deadline exceeded"));
                    continue;
                }
                let result = transports.send(&cfg, &handle, &job);
                let blocked = matches!(&result, Ok(false))
                    || result
                        .as_ref()
                        .err()
                        .and_then(|err| err.downcast_ref::<io::Error>())
                        .is_some_and(|err| {
                            matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            )
                        });
                if blocked {
                    *pending = Some((job, started));
                    break;
                }
                if let Err(err) = result {
                    cfg.observability.record_udp_job_dropped();
                    log_error(&cfg, &err);
                }
            }
        }
        if handle.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let runnable = rx
            .iter()
            .zip(&pending)
            .any(|(rx, pending)| !rx.is_empty() && pending.is_none());
        if let Err(err) = transports.poll(&handle, &pending, runnable) {
            log_error(&cfg, &err.into());
            break;
        }
    }
    // Also releases a reader blocked on a full job queue when rx is dropped.
    handle.shutdown();
}

fn deliver(cfg: &UdpRelayConfig, handle: &UdpRelayHandle, response: UdpRelayResponse) {
    let mut pending = handle.pending_sources.lock().unwrap();
    if pending.len() >= MAX_PENDING_SOURCES {
        cfg.observability.record_udp_pending_response_dropped();
        return;
    }
    pending.push_back(response.source);
    if !send_relay_response(handle.relay_fd.as_raw_fd(), &response.payload) {
        pending.pop_back();
    }
}

fn log_error(cfg: &UdpRelayConfig, err: &anyhow::Error) {
    if cfg.debug {
        eprintln!("yatht: UDP relay forward failed: {err:#}");
    }
}
