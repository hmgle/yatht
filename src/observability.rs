use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel as channel;
use serde::Serialize;

const METRIC_QUEUE_CAPACITY: usize = 4096;
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Default)]
pub struct Observability {
    inner: Option<Arc<ObservabilityInner>>,
}

pub struct ObservabilityRuntime {
    observability: Observability,
    writer: Option<JoinHandle<io::Result<()>>>,
}

struct ObservabilityInner {
    tx: channel::Sender<WriterCommand>,
    dropped_events: AtomicU64,
    next_flow_id: AtomicU64,
    setup_completed: AtomicU64,
    setup_failed: AtomicU64,
    setup_cancelled: AtomicU64,
    started: Instant,
}

enum WriterCommand {
    Event(MetricEvent),
    Finish(RunSummary),
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum MetricEvent {
    RunStart {
        schema_version: u32,
        pid: u32,
        package_version: &'static str,
        started_unix_ns: u64,
        metric_queue_capacity: usize,
    },
    TcpSetup(Box<TcpSetupEvent>),
}

#[derive(Serialize)]
struct TcpSetupEvent {
    schema_version: u32,
    flow_id: u64,
    target_pid: u32,
    target_fd: i32,
    destination: String,
    target_cookie: Option<u64>,
    proxy_cookie: Option<u64>,
    outcome: &'static str,
    failure_stage: Option<&'static str>,
    error: Option<String>,
    queue_wait_ns: u64,
    handler_ns: u64,
    fd_inspection_ns: Option<u64>,
    proxy_connect_ns: Option<u64>,
    proxy_handshake_ns: Option<u64>,
    loopback_connect_accept_ns: Option<u64>,
    broker_register_ns: Option<u64>,
    notification_reply_ns: Option<u64>,
}

#[derive(Serialize)]
struct RunSummary {
    event: &'static str,
    schema_version: u32,
    elapsed_ns: u64,
    process_user_cpu_ns: u64,
    process_system_cpu_ns: u64,
    tcp_setup_completed: u64,
    tcp_setup_failed: u64,
    tcp_setup_cancelled: u64,
    dropped_metric_events: u64,
}

pub struct TcpSetupTrace {
    observability: Observability,
    flow_id: u64,
    target_pid: u32,
    target_fd: i32,
    destination: String,
    started: Instant,
    queue_wait_ns: u64,
    fd_inspection_ns: Option<u64>,
    proxy_connect_ns: Option<u64>,
    proxy_handshake_ns: Option<u64>,
    loopback_connect_accept_ns: Option<u64>,
    broker_register_ns: Option<u64>,
    notification_reply_ns: Option<u64>,
    target_cookie: Option<u64>,
    proxy_cookie: Option<u64>,
    finished: bool,
}

impl ObservabilityRuntime {
    pub fn start(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self {
                observability: Observability::default(),
                writer: None,
            });
        };

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create metrics file {}", path.display()))?;
        let (tx, rx) = channel::bounded(METRIC_QUEUE_CAPACITY);
        let inner = Arc::new(ObservabilityInner {
            tx,
            dropped_events: AtomicU64::new(0),
            next_flow_id: AtomicU64::new(1),
            setup_completed: AtomicU64::new(0),
            setup_failed: AtomicU64::new(0),
            setup_cancelled: AtomicU64::new(0),
            started: Instant::now(),
        });
        let start = MetricEvent::RunStart {
            schema_version: SCHEMA_VERSION,
            pid: std::process::id(),
            package_version: env!("CARGO_PKG_VERSION"),
            started_unix_ns: unix_time_ns(),
            metric_queue_capacity: METRIC_QUEUE_CAPACITY,
        };
        let writer = thread::Builder::new()
            .name("yatht-metrics".to_string())
            .spawn(move || write_metrics(file, start, rx))
            .context("spawn metrics writer")?;

        Ok(Self {
            observability: Observability { inner: Some(inner) },
            writer: Some(writer),
        })
    }

    pub fn observability(&self) -> Observability {
        self.observability.clone()
    }

    pub fn finish(mut self) -> Result<()> {
        let Some(inner) = &self.observability.inner else {
            return Ok(());
        };
        let (user_cpu_ns, system_cpu_ns) = process_cpu_time();
        let summary = RunSummary {
            event: "run_summary",
            schema_version: SCHEMA_VERSION,
            elapsed_ns: duration_ns(inner.started.elapsed()),
            process_user_cpu_ns: user_cpu_ns,
            process_system_cpu_ns: system_cpu_ns,
            tcp_setup_completed: inner.setup_completed.load(Ordering::Relaxed),
            tcp_setup_failed: inner.setup_failed.load(Ordering::Relaxed),
            tcp_setup_cancelled: inner.setup_cancelled.load(Ordering::Relaxed),
            dropped_metric_events: inner.dropped_events.load(Ordering::Relaxed),
        };
        inner
            .tx
            .send(WriterCommand::Finish(summary))
            .map_err(|_| anyhow!("metrics writer stopped before final summary"))?;
        let writer = self.writer.take().expect("enabled metrics writer missing");
        writer
            .join()
            .map_err(|_| anyhow!("metrics writer panicked"))??;
        Ok(())
    }
}

impl Observability {
    pub fn begin_tcp_setup(
        &self,
        target_pid: u32,
        target_fd: i32,
        destination: String,
        started: Instant,
        queue_wait: Duration,
    ) -> TcpSetupTrace {
        let flow_id = self.inner.as_ref().map_or(0, |inner| {
            inner.next_flow_id.fetch_add(1, Ordering::Relaxed)
        });
        TcpSetupTrace {
            observability: self.clone(),
            flow_id,
            target_pid,
            target_fd,
            destination,
            started,
            queue_wait_ns: duration_ns(queue_wait),
            fd_inspection_ns: None,
            proxy_connect_ns: None,
            proxy_handshake_ns: None,
            loopback_connect_accept_ns: None,
            broker_register_ns: None,
            notification_reply_ns: None,
            target_cookie: None,
            proxy_cookie: None,
            finished: false,
        }
    }

    fn record_setup(&self, event: TcpSetupEvent) {
        let Some(inner) = &self.inner else {
            return;
        };
        match event.outcome {
            "completed" => &inner.setup_completed,
            "failed" => &inner.setup_failed,
            _ => &inner.setup_cancelled,
        }
        .fetch_add(1, Ordering::Relaxed);
        if inner
            .tx
            .try_send(WriterCommand::Event(MetricEvent::TcpSetup(Box::new(event))))
            .is_err()
        {
            inner.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl TcpSetupTrace {
    pub fn set_fd_inspection(&mut self, elapsed: Duration, target_cookie: Option<u64>) {
        self.fd_inspection_ns = Some(duration_ns(elapsed));
        self.target_cookie = target_cookie;
    }

    pub fn set_proxy_timings(&mut self, connect: Option<Duration>, handshake: Option<Duration>) {
        self.proxy_connect_ns = connect.map(duration_ns);
        self.proxy_handshake_ns = handshake.map(duration_ns);
    }

    pub fn set_proxy_cookie(&mut self, cookie: Option<u64>) {
        self.proxy_cookie = cookie;
    }

    pub fn set_loopback(&mut self, elapsed: Duration) {
        self.loopback_connect_accept_ns = Some(duration_ns(elapsed));
    }

    pub fn set_broker_register(&mut self, elapsed: Duration) {
        self.broker_register_ns = Some(duration_ns(elapsed));
    }

    pub fn set_notification_reply(&mut self, elapsed: Duration) {
        self.notification_reply_ns = Some(duration_ns(elapsed));
    }

    pub fn completed(mut self) {
        self.finish("completed", None, None);
    }

    pub fn failed(mut self, stage: &'static str, error: impl ToString) {
        self.finish("failed", Some(stage), Some(error.to_string()));
    }

    pub fn cancelled(mut self, stage: &'static str) {
        self.finish("cancelled", Some(stage), None);
    }

    fn finish(
        &mut self,
        outcome: &'static str,
        failure_stage: Option<&'static str>,
        error: Option<String>,
    ) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.observability.record_setup(TcpSetupEvent {
            schema_version: SCHEMA_VERSION,
            flow_id: self.flow_id,
            target_pid: self.target_pid,
            target_fd: self.target_fd,
            destination: self.destination.clone(),
            target_cookie: self.target_cookie,
            proxy_cookie: self.proxy_cookie,
            outcome,
            failure_stage,
            error,
            queue_wait_ns: self.queue_wait_ns,
            handler_ns: duration_ns(self.started.elapsed()),
            fd_inspection_ns: self.fd_inspection_ns,
            proxy_connect_ns: self.proxy_connect_ns,
            proxy_handshake_ns: self.proxy_handshake_ns,
            loopback_connect_accept_ns: self.loopback_connect_accept_ns,
            broker_register_ns: self.broker_register_ns,
            notification_reply_ns: self.notification_reply_ns,
        });
    }
}

impl Drop for TcpSetupTrace {
    fn drop(&mut self) {
        self.finish("cancelled", Some("handler_unwind"), None);
    }
}

fn write_metrics(
    file: std::fs::File,
    start: MetricEvent,
    rx: channel::Receiver<WriterCommand>,
) -> io::Result<()> {
    let mut writer = BufWriter::new(file);
    write_json_line(&mut writer, &start)?;
    while let Ok(command) = rx.recv() {
        match command {
            WriterCommand::Event(event) => write_json_line(&mut writer, &event)?,
            WriterCommand::Finish(summary) => {
                write_json_line(&mut writer, &summary)?;
                writer.flush()?;
                return Ok(());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "metrics channel closed without final summary",
    ))
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

fn unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_ns)
        .unwrap_or(0)
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn process_cpu_time() -> (u64, u64) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (0, 0);
    }
    (timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime))
}

fn timeval_ns(value: libc::timeval) -> u64 {
    (value.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((value.tv_usec.max(0) as u64).saturating_mul(1_000))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn writes_start_setup_and_summary_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metrics.jsonl");
        let runtime = ObservabilityRuntime::start(Some(&path)).unwrap();
        let metrics = runtime.observability();
        let mut setup = metrics.begin_tcp_setup(
            42,
            7,
            "203.0.113.1:443".to_string(),
            Instant::now(),
            Duration::from_micros(5),
        );
        setup.set_fd_inspection(Duration::from_micros(2), Some(11));
        setup.set_proxy_timings(
            Some(Duration::from_micros(3)),
            Some(Duration::from_micros(4)),
        );
        setup.set_proxy_cookie(Some(12));
        setup.completed();
        runtime.finish().unwrap();

        let events = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event"], "run_start");
        assert_eq!(events[1]["event"], "tcp_setup");
        assert_eq!(events[1]["target_cookie"], 11);
        assert_eq!(events[2]["event"], "run_summary");
        assert_eq!(events[2]["tcp_setup_completed"], 1);
    }

    #[test]
    fn refuses_to_overwrite_metrics_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metrics.jsonl");
        fs::write(&path, "existing").unwrap();

        assert!(ObservabilityRuntime::start(Some(&path)).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "existing");
    }
}
