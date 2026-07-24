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
const SCHEMA_VERSION: u32 = 3;

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
    notification_queue_depth: AtomicU64,
    notification_queue_peak: AtomicU64,
    notification_queue_full: AtomicU64,
    tcp_active_flows: AtomicU64,
    tcp_peak_flows: AtomicU64,
    tcp_registration_queue_depth: AtomicU64,
    tcp_registration_queue_peak: AtomicU64,
    tcp_registration_queue_full: AtomicU64,
    tcp_pending_bytes: AtomicU64,
    tcp_peak_pending_bytes: AtomicU64,
    tcp_reserved_pending_bytes: AtomicU64,
    tcp_peak_reserved_pending_bytes: AtomicU64,
    tcp_buffer_capacity_bytes: AtomicU64,
    tcp_peak_buffer_capacity_bytes: AtomicU64,
    tcp_target_to_upstream_bytes: AtomicU64,
    tcp_upstream_to_target_bytes: AtomicU64,
    tcp_recv_syscalls: AtomicU64,
    tcp_send_syscalls: AtomicU64,
    tcp_command_wakeups: AtomicU64,
    tcp_poll_calls: AtomicU64,
    tcp_poll_ready_returns: AtomicU64,
    tcp_poll_ready_fds: AtomicU64,
    tcp_no_progress_iterations: AtomicU64,
    tcp_half_closes: AtomicU64,
    tcp_resets: AtomicU64,
    tcp_flow_failures: AtomicU64,
    tcp_flows_started: AtomicU64,
    tcp_flows_completed: AtomicU64,
    tcp_flows_cancelled: AtomicU64,
    tcp_active_flow_rejections: AtomicU64,
    tcp_fd_headroom_rejections: AtomicU64,
    tcp_pending_byte_rejections: AtomicU64,
    tcp_buffer_capacity_rejections: AtomicU64,
    tcp_relay_init_rejections: AtomicU64,
    tcp_reactor_stopped_rejections: AtomicU64,
    tcp_reactor_failures: AtomicU64,
    started: Instant,
}

impl ObservabilityInner {
    fn new(tx: channel::Sender<WriterCommand>) -> Self {
        Self {
            tx,
            dropped_events: AtomicU64::new(0),
            next_flow_id: AtomicU64::new(1),
            setup_completed: AtomicU64::new(0),
            setup_failed: AtomicU64::new(0),
            setup_cancelled: AtomicU64::new(0),
            notification_queue_depth: AtomicU64::new(0),
            notification_queue_peak: AtomicU64::new(0),
            notification_queue_full: AtomicU64::new(0),
            tcp_active_flows: AtomicU64::new(0),
            tcp_peak_flows: AtomicU64::new(0),
            tcp_registration_queue_depth: AtomicU64::new(0),
            tcp_registration_queue_peak: AtomicU64::new(0),
            tcp_registration_queue_full: AtomicU64::new(0),
            tcp_pending_bytes: AtomicU64::new(0),
            tcp_peak_pending_bytes: AtomicU64::new(0),
            tcp_reserved_pending_bytes: AtomicU64::new(0),
            tcp_peak_reserved_pending_bytes: AtomicU64::new(0),
            tcp_buffer_capacity_bytes: AtomicU64::new(0),
            tcp_peak_buffer_capacity_bytes: AtomicU64::new(0),
            tcp_target_to_upstream_bytes: AtomicU64::new(0),
            tcp_upstream_to_target_bytes: AtomicU64::new(0),
            tcp_recv_syscalls: AtomicU64::new(0),
            tcp_send_syscalls: AtomicU64::new(0),
            tcp_command_wakeups: AtomicU64::new(0),
            tcp_poll_calls: AtomicU64::new(0),
            tcp_poll_ready_returns: AtomicU64::new(0),
            tcp_poll_ready_fds: AtomicU64::new(0),
            tcp_no_progress_iterations: AtomicU64::new(0),
            tcp_half_closes: AtomicU64::new(0),
            tcp_resets: AtomicU64::new(0),
            tcp_flow_failures: AtomicU64::new(0),
            tcp_flows_started: AtomicU64::new(0),
            tcp_flows_completed: AtomicU64::new(0),
            tcp_flows_cancelled: AtomicU64::new(0),
            tcp_active_flow_rejections: AtomicU64::new(0),
            tcp_fd_headroom_rejections: AtomicU64::new(0),
            tcp_pending_byte_rejections: AtomicU64::new(0),
            tcp_buffer_capacity_rejections: AtomicU64::new(0),
            tcp_relay_init_rejections: AtomicU64::new(0),
            tcp_reactor_stopped_rejections: AtomicU64::new(0),
            tcp_reactor_failures: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

enum WriterCommand {
    Event(MetricEvent),
    Finish(Box<RunSummary>),
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
    TcpBrokerLimits {
        schema_version: u32,
        max_active_flows: usize,
        max_pending_bytes: usize,
        max_buffer_capacity_bytes: usize,
        registration_queue_capacity: usize,
        rlimit_nofile: u64,
        baseline_fds: usize,
        reserved_fds: usize,
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
    notification_queue_depth: u64,
    notification_queue_peak: u64,
    notification_queue_full: u64,
    tcp_active_flows: u64,
    tcp_peak_flows: u64,
    tcp_registration_queue_depth: u64,
    tcp_registration_queue_peak: u64,
    tcp_registration_queue_full: u64,
    tcp_pending_bytes: u64,
    tcp_peak_pending_bytes: u64,
    tcp_reserved_pending_bytes: u64,
    tcp_peak_reserved_pending_bytes: u64,
    tcp_buffer_capacity_bytes: u64,
    tcp_peak_buffer_capacity_bytes: u64,
    tcp_target_to_upstream_bytes: u64,
    tcp_upstream_to_target_bytes: u64,
    tcp_recv_syscalls: u64,
    tcp_send_syscalls: u64,
    tcp_command_wakeups: u64,
    tcp_poll_calls: u64,
    tcp_poll_ready_returns: u64,
    tcp_poll_ready_fds: u64,
    tcp_no_progress_iterations: u64,
    tcp_half_closes: u64,
    tcp_resets: u64,
    tcp_flow_failures: u64,
    tcp_flows_started: u64,
    tcp_flows_completed: u64,
    tcp_flows_cancelled: u64,
    tcp_active_flow_rejections: u64,
    tcp_fd_headroom_rejections: u64,
    tcp_pending_byte_rejections: u64,
    tcp_buffer_capacity_rejections: u64,
    tcp_relay_init_rejections: u64,
    tcp_reactor_stopped_rejections: u64,
    tcp_reactor_failures: u64,
    tcp_cpu_ns_per_byte: Option<f64>,
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
        let inner = Arc::new(ObservabilityInner::new(tx));
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
        let total_bytes = inner
            .tcp_target_to_upstream_bytes
            .load(Ordering::Relaxed)
            .saturating_add(inner.tcp_upstream_to_target_bytes.load(Ordering::Relaxed));
        let total_cpu_ns = user_cpu_ns.saturating_add(system_cpu_ns);
        let summary = RunSummary {
            event: "run_summary",
            schema_version: SCHEMA_VERSION,
            elapsed_ns: duration_ns(inner.started.elapsed()),
            process_user_cpu_ns: user_cpu_ns,
            process_system_cpu_ns: system_cpu_ns,
            tcp_setup_completed: inner.setup_completed.load(Ordering::Relaxed),
            tcp_setup_failed: inner.setup_failed.load(Ordering::Relaxed),
            tcp_setup_cancelled: inner.setup_cancelled.load(Ordering::Relaxed),
            notification_queue_depth: inner.notification_queue_depth.load(Ordering::Relaxed),
            notification_queue_peak: inner.notification_queue_peak.load(Ordering::Relaxed),
            notification_queue_full: inner.notification_queue_full.load(Ordering::Relaxed),
            tcp_active_flows: inner.tcp_active_flows.load(Ordering::Relaxed),
            tcp_peak_flows: inner.tcp_peak_flows.load(Ordering::Relaxed),
            tcp_registration_queue_depth: inner
                .tcp_registration_queue_depth
                .load(Ordering::Relaxed),
            tcp_registration_queue_peak: inner.tcp_registration_queue_peak.load(Ordering::Relaxed),
            tcp_registration_queue_full: inner.tcp_registration_queue_full.load(Ordering::Relaxed),
            tcp_pending_bytes: inner.tcp_pending_bytes.load(Ordering::Relaxed),
            tcp_peak_pending_bytes: inner.tcp_peak_pending_bytes.load(Ordering::Relaxed),
            tcp_reserved_pending_bytes: inner.tcp_reserved_pending_bytes.load(Ordering::Relaxed),
            tcp_peak_reserved_pending_bytes: inner
                .tcp_peak_reserved_pending_bytes
                .load(Ordering::Relaxed),
            tcp_buffer_capacity_bytes: inner.tcp_buffer_capacity_bytes.load(Ordering::Relaxed),
            tcp_peak_buffer_capacity_bytes: inner
                .tcp_peak_buffer_capacity_bytes
                .load(Ordering::Relaxed),
            tcp_target_to_upstream_bytes: inner
                .tcp_target_to_upstream_bytes
                .load(Ordering::Relaxed),
            tcp_upstream_to_target_bytes: inner
                .tcp_upstream_to_target_bytes
                .load(Ordering::Relaxed),
            tcp_recv_syscalls: inner.tcp_recv_syscalls.load(Ordering::Relaxed),
            tcp_send_syscalls: inner.tcp_send_syscalls.load(Ordering::Relaxed),
            tcp_command_wakeups: inner.tcp_command_wakeups.load(Ordering::Relaxed),
            tcp_poll_calls: inner.tcp_poll_calls.load(Ordering::Relaxed),
            tcp_poll_ready_returns: inner.tcp_poll_ready_returns.load(Ordering::Relaxed),
            tcp_poll_ready_fds: inner.tcp_poll_ready_fds.load(Ordering::Relaxed),
            tcp_no_progress_iterations: inner.tcp_no_progress_iterations.load(Ordering::Relaxed),
            tcp_half_closes: inner.tcp_half_closes.load(Ordering::Relaxed),
            tcp_resets: inner.tcp_resets.load(Ordering::Relaxed),
            tcp_flow_failures: inner.tcp_flow_failures.load(Ordering::Relaxed),
            tcp_flows_started: inner.tcp_flows_started.load(Ordering::Relaxed),
            tcp_flows_completed: inner.tcp_flows_completed.load(Ordering::Relaxed),
            tcp_flows_cancelled: inner.tcp_flows_cancelled.load(Ordering::Relaxed),
            tcp_active_flow_rejections: inner.tcp_active_flow_rejections.load(Ordering::Relaxed),
            tcp_fd_headroom_rejections: inner.tcp_fd_headroom_rejections.load(Ordering::Relaxed),
            tcp_pending_byte_rejections: inner.tcp_pending_byte_rejections.load(Ordering::Relaxed),
            tcp_buffer_capacity_rejections: inner
                .tcp_buffer_capacity_rejections
                .load(Ordering::Relaxed),
            tcp_relay_init_rejections: inner.tcp_relay_init_rejections.load(Ordering::Relaxed),
            tcp_reactor_stopped_rejections: inner
                .tcp_reactor_stopped_rejections
                .load(Ordering::Relaxed),
            tcp_reactor_failures: inner.tcp_reactor_failures.load(Ordering::Relaxed),
            tcp_cpu_ns_per_byte: (total_bytes != 0)
                .then_some(total_cpu_ns as f64 / total_bytes as f64),
            dropped_metric_events: inner.dropped_events.load(Ordering::Relaxed),
        };
        let send_result = inner
            .tx
            .send(WriterCommand::Finish(Box::new(summary)))
            .map_err(|_| anyhow!("metrics writer stopped before final summary"));
        let writer = self.writer.take().expect("enabled metrics writer missing");
        match writer.join() {
            Err(_) => Err(anyhow!("metrics writer panicked")),
            Ok(Err(err)) => Err(err).context("write performance metrics"),
            Ok(Ok(())) => send_result,
        }
    }
}

impl Observability {
    pub fn notification_queued(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner
            .notification_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        update_peak(&inner.notification_queue_peak, current);
    }

    pub fn notification_dequeued(&self) {
        if let Some(inner) = &self.inner {
            let previous = inner
                .notification_queue_depth
                .fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
        }
    }

    pub fn notification_queue_full(&self) {
        if let Some(inner) = &self.inner {
            inner
                .notification_queue_full
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_tcp_broker_limits(
        &self,
        max_active_flows: usize,
        max_pending_bytes: usize,
        max_buffer_capacity_bytes: usize,
        registration_queue_capacity: usize,
        rlimit_nofile: u64,
        baseline_fds: usize,
        reserved_fds: usize,
    ) {
        let event = MetricEvent::TcpBrokerLimits {
            schema_version: SCHEMA_VERSION,
            max_active_flows,
            max_pending_bytes,
            max_buffer_capacity_bytes,
            registration_queue_capacity,
            rlimit_nofile,
            baseline_fds,
            reserved_fds,
        };
        self.try_record(event);
    }

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
        self.try_record(MetricEvent::TcpSetup(Box::new(event)));
    }

    pub fn tcp_flow_acquired(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner.tcp_active_flows.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&inner.tcp_peak_flows, current);
    }

    pub fn tcp_flow_released(&self) {
        if let Some(inner) = &self.inner {
            let previous = inner.tcp_active_flows.fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
        }
    }

    pub fn tcp_registration_queued(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner
            .tcp_registration_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        update_peak(&inner.tcp_registration_queue_peak, current);
    }

    pub fn tcp_registration_dequeued(&self) {
        if let Some(inner) = &self.inner {
            let previous = inner
                .tcp_registration_queue_depth
                .fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
        }
    }

    pub fn tcp_pending_budget_reserved(&self, reserved: usize) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner
            .tcp_reserved_pending_bytes
            .fetch_add(reserved as u64, Ordering::Relaxed)
            .saturating_add(reserved as u64);
        update_peak(&inner.tcp_peak_reserved_pending_bytes, current);
    }

    pub fn tcp_pending_budget_released(&self, released: usize) {
        if let Some(inner) = &self.inner {
            let previous = inner
                .tcp_reserved_pending_bytes
                .fetch_sub(released as u64, Ordering::Relaxed);
            debug_assert!(previous >= released as u64);
        }
    }

    pub fn tcp_buffer_capacity_reserved(&self, reserved: usize) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner
            .tcp_buffer_capacity_bytes
            .fetch_add(reserved as u64, Ordering::Relaxed)
            .saturating_add(reserved as u64);
        update_peak(&inner.tcp_peak_buffer_capacity_bytes, current);
    }

    pub fn tcp_buffer_capacity_released(&self, released: usize) {
        if let Some(inner) = &self.inner {
            let previous = inner
                .tcp_buffer_capacity_bytes
                .fetch_sub(released as u64, Ordering::Relaxed);
            debug_assert!(previous >= released as u64);
        }
    }

    pub fn tcp_pending_added(&self, added: usize) {
        let Some(inner) = &self.inner else {
            return;
        };
        let current = inner
            .tcp_pending_bytes
            .fetch_add(added as u64, Ordering::Relaxed)
            .saturating_add(added as u64);
        update_peak(&inner.tcp_peak_pending_bytes, current);
    }

    pub fn tcp_pending_removed(&self, removed: usize) {
        if let Some(inner) = &self.inner {
            let previous = inner
                .tcp_pending_bytes
                .fetch_sub(removed as u64, Ordering::Relaxed);
            debug_assert!(previous >= removed as u64);
        }
    }

    pub fn tcp_recv(&self, bytes: usize, target_to_upstream: bool) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.tcp_recv_syscalls.fetch_add(1, Ordering::Relaxed);
        if bytes != 0 {
            let counter = if target_to_upstream {
                &inner.tcp_target_to_upstream_bytes
            } else {
                &inner.tcp_upstream_to_target_bytes
            };
            counter.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    pub fn tcp_send(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_send_syscalls.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_command_wakeup(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_command_wakeups.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_poll(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_poll_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_poll_ready(&self, ready_fds: usize) {
        if let Some(inner) = &self.inner {
            inner.tcp_poll_ready_returns.fetch_add(1, Ordering::Relaxed);
            inner
                .tcp_poll_ready_fds
                .fetch_add(ready_fds as u64, Ordering::Relaxed);
        }
    }

    pub fn tcp_no_progress_iteration(&self) {
        if let Some(inner) = &self.inner {
            inner
                .tcp_no_progress_iterations
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_half_close(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_half_closes.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_flow_finished(&self, error: Option<&io::Error>) {
        let Some(inner) = &self.inner else {
            return;
        };
        match error {
            None => {
                inner.tcp_flows_completed.fetch_add(1, Ordering::Relaxed);
            }
            Some(error) => {
                inner.tcp_flow_failures.fetch_add(1, Ordering::Relaxed);
                if error.raw_os_error() == Some(libc::ECONNRESET) {
                    inner.tcp_resets.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn tcp_flow_started(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_flows_started.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_flow_cancelled(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_flows_cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_reactor_failed(&self) {
        if let Some(inner) = &self.inner {
            inner.tcp_reactor_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn tcp_resource_rejection(&self, reason: &'static str) {
        let Some(inner) = &self.inner else {
            return;
        };
        let counter = match reason {
            "active_flow" => &inner.tcp_active_flow_rejections,
            "fd_headroom" => &inner.tcp_fd_headroom_rejections,
            "pending_bytes" => &inner.tcp_pending_byte_rejections,
            "buffer_capacity" => &inner.tcp_buffer_capacity_rejections,
            "registration_queue" => &inner.tcp_registration_queue_full,
            "relay_init" => &inner.tcp_relay_init_rejections,
            _ => &inner.tcp_reactor_stopped_rejections,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn try_record(&self, event: MetricEvent) {
        let Some(inner) = &self.inner else {
            return;
        };
        if inner.tx.try_send(WriterCommand::Event(event)).is_err() {
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

fn update_peak(peak: &AtomicU64, value: u64) {
    let _ = peak.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (value > current).then_some(value)
    });
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
        metrics.tcp_flow_cancelled();
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
        assert_eq!(events[2]["tcp_flows_cancelled"], 1);
    }

    #[test]
    fn refuses_to_overwrite_metrics_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metrics.jsonl");
        fs::write(&path, "existing").unwrap();

        assert!(ObservabilityRuntime::start(Some(&path)).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "existing");
    }

    #[test]
    fn finish_preserves_writer_io_error_after_channel_disconnect() {
        let (tx, rx) = channel::bounded(METRIC_QUEUE_CAPACITY);
        drop(rx);
        let writer = thread::spawn(|| Err(io::Error::from_raw_os_error(libc::ENOSPC)));
        let runtime = ObservabilityRuntime {
            observability: Observability {
                inner: Some(Arc::new(ObservabilityInner::new(tx))),
            },
            writer: Some(writer),
        };

        let error = runtime.finish().unwrap_err();
        let io_error = error.root_cause().downcast_ref::<io::Error>().unwrap();
        assert_eq!(io_error.raw_os_error(), Some(libc::ENOSPC));
    }
}
