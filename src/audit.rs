//! Bounded, local payload archive. Serialization and disk I/O run on one writer thread.
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use capture_lifecycle::{CaptureChannel, CaptureLayout, CaptureRoot, ClosedFileSealer, SealSkipReason};
use chrono::{NaiveDate, Utc};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::Config;

#[derive(Clone, Copy)]
struct Limits {
    records: usize,
    payload_records: usize,
    bytes: usize,
    payload_bytes: usize,
    record_bytes: usize,
}

const LIMITS: Limits =
    Limits { records: 1024, payload_records: 960, bytes: 64 << 20, payload_bytes: 60 << 20, record_bytes: 16 << 20 };

// Rotation is checked even when there are no requests. Hashing is bounded and
// runs on another thread; it never holds the live producer mutex.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(300);
const SEAL_BATCH_FILES: usize = 2;

fn process_instance_id() -> &'static str {
    static INSTANCE: OnceLock<String> = OnceLock::new();
    INSTANCE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Local archive coverage and queue pressure, without payloads or account identifiers.
#[derive(Default, Clone, Serialize)]
pub struct ArchiveStats {
    pub pending_records: usize,
    pub pending_bytes: usize,
    pub written: u64,
    pub dropped_payloads: u64,
    pub dropped_summaries: u64,
    pub write_errors: u64,
    pub last_error_kind: Option<String>,
    pub last_os_error: Option<i32>,
    pub sealed_files: u64,
    pub seal_errors: u64,
    pub seal_blocked_files: usize,
    pub seal_deferred_files: usize,
    pub seal_pending_roots: usize,
    pub seal_failed_roots: usize,
    pub last_seal_error_kind: Option<String>,
    pub last_seal_os_error: Option<i32>,
}

struct Job {
    path: PathBuf,
    root: Root,
    observed_day: NaiveDate,
    record: Value,
    bytes: usize,
    summary: bool,
}

struct CaptureHandle {
    path: PathBuf,
    producer: Mutex<CaptureRoot>,
}

type Root = Arc<CaptureHandle>;
type Roots = Arc<Mutex<HashMap<PathBuf, Root>>>;

/// Cleared only after the writer closure and its file handles have dropped,
/// including thread unwinding and concurrent shutdown calls.
struct RootLifetime(Roots);

impl Drop for RootLifetime {
    fn drop(&mut self) {
        self.0.lock().clear();
    }
}

/// A configuration validated before a management handler writes config.yaml.
pub struct PreparedCapture(Option<Root>);

struct Writer {
    sender: Option<mpsc::SyncSender<Job>>,
    handle: Option<JoinHandle<()>>,
}

/// Outcome of admission; queued records are not yet durable.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Disabled,
    Queued,
    Dropped,
}

pub struct Audit {
    directory: RwLock<Option<Root>>,
    roots: Roots,
    writer: Mutex<Writer>,
    drain: Mutex<()>,
    stats: Arc<Mutex<ArchiveStats>>,
    limits: Limits,
}

trait ArchiveWriter: Send + 'static {
    fn write(&mut self, job: &mut Job) -> io::Result<()>;
    fn maintain(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
struct TestWriter<F>(F);

#[cfg(test)]
impl<F: FnMut(&mut Job) -> io::Result<()> + Send + 'static> ArchiveWriter for TestWriter<F> {
    fn write(&mut self, job: &mut Job) -> io::Result<()> {
        (self.0)(job)
    }
}

impl Audit {
    pub fn new(cfg: &Config) -> io::Result<Self> {
        Self::with_archive_writer(cfg, LIMITS, CaptureWriter::new)
    }

    #[cfg(test)]
    fn with_writer(
        cfg: &Config,
        limits: Limits,
        write: impl FnMut(&mut Job) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        Self::with_archive_writer(cfg, limits, move |_, _| Ok(TestWriter(write)))
    }

    fn with_archive_writer<W: ArchiveWriter>(
        cfg: &Config,
        limits: Limits,
        create: impl FnOnce(Roots, Arc<Mutex<ArchiveStats>>) -> io::Result<W>,
    ) -> io::Result<Self> {
        let roots = Arc::new(Mutex::new(HashMap::new()));
        let directory = Self::prepare(&roots, cfg)?;
        if let Some(root) = &directory.0 {
            roots.lock().insert(root.path.clone(), root.clone());
        }
        let worker_roots = roots.clone();
        let stats = Arc::new(Mutex::new(ArchiveStats::default()));
        let worker_stats = stats.clone();
        let writer = create(roots.clone(), stats.clone())?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(limits.records);
        let handle = std::thread::Builder::new().name("proxy-archive".into()).spawn(move || {
            let lifetime = RootLifetime(worker_roots);
            // Locals drop in reverse order during unwinding. The write closure
            // closes its file handles before RootLifetime releases the guards.
            let mut write = writer;
            let mut reported = (0, 0, 0);
            let mut next_maintenance = Instant::now();
            loop {
                if Instant::now() >= next_maintenance {
                    if let Err(error) = write.maintain() {
                        note_seal_error(&worker_stats, &error);
                    }
                    next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                }
                let mut job = match receiver.recv_timeout(next_maintenance.saturating_duration_since(Instant::now())) {
                    Ok(job) => job,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let result = write.write(&mut job);
                let bytes = job.bytes;
                // Release the payload before releasing its memory reservation.
                drop(job);
                let snapshot = {
                    let mut stats = worker_stats.lock();
                    stats.pending_records -= 1;
                    stats.pending_bytes -= bytes;
                    match result {
                        Ok(()) => stats.written += 1,
                        Err(error) => {
                            stats.write_errors += 1;
                            stats.last_error_kind = Some(format!("{:?}", error.kind()));
                            stats.last_os_error = error.raw_os_error();
                        }
                    }
                    stats.clone()
                };
                // Formatting/output may block. Only the dedicated writer does it,
                // after releasing shared locks; never report overflow on admission.
                if needs_report(snapshot.dropped_payloads, reported.0)
                    || needs_report(snapshot.dropped_summaries, reported.1)
                    || needs_report(snapshot.write_errors, reported.2)
                {
                    reported = (snapshot.dropped_payloads, snapshot.dropped_summaries, snapshot.write_errors);
                    tracing::warn!(dropped_payloads = reported.0, dropped_summaries = reported.1,
                        write_errors = reported.2, error_kind = ?snapshot.last_error_kind,
                        os_error = ?snapshot.last_os_error, "local archive coverage is incomplete");
                }
            }
            if let Err(error) = write.finish() {
                note_seal_error(&worker_stats, &error);
            }
            // Close the current BufWriter before releasing any previous roots.
            // This order also holds when the Audit owner drops without joining.
            drop(write);
            drop(lifetime);
        })?;
        let writer = Writer { sender: Some(sender), handle: Some(handle) };
        Ok(Self {
            directory: RwLock::new(directory.0),
            roots,
            writer: Mutex::new(writer),
            drain: Mutex::new(()),
            stats,
            limits,
        })
    }

    pub fn path(cfg: &Config) -> Option<PathBuf> {
        if !cfg.request_log {
            return None;
        }
        let raw = &cfg.request_log_dir;
        Some(if let Some(tail) = raw.strip_prefix("~/") {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(tail)
        } else {
            PathBuf::from(raw)
        })
    }

    fn prepare(roots: &Roots, cfg: &Config) -> io::Result<PreparedCapture> {
        let Some(path) = Self::path(cfg) else { return Ok(PreparedCapture(None)) };
        if std::fs::symlink_metadata(&path)?.is_symlink() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "capture root must be a real directory"));
        }
        let canonical = std::fs::canonicalize(&path)?;
        let retained = roots.lock().get(&canonical).cloned();
        let root = match retained {
            Some(root) => root,
            None => Arc::new(CaptureHandle {
                path: canonical.clone(),
                producer: Mutex::new(CaptureRoot::open(&path, CaptureLayout::Proxy)?),
            }),
        };
        Ok(PreparedCapture(Some(root)))
    }

    pub fn prepare_configuration(&self, cfg: &Config) -> io::Result<PreparedCapture> {
        if self.writer.lock().sender.is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "archive writer is closed"));
        }
        Self::prepare(&self.roots, cfg)
    }

    pub fn apply_configuration(&self, prepared: PreparedCapture) -> io::Result<()> {
        let writer = self.writer.lock();
        if writer.sender.is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "archive writer is closed"));
        }
        if let Some(root) = &prepared.0 {
            self.roots.lock().insert(root.path.clone(), root.clone());
        }
        *self.directory.write() = prepared.0;
        Ok(())
    }

    #[cfg(test)]
    pub fn configure(&self, cfg: &Config) -> io::Result<()> {
        self.apply_configuration(self.prepare_configuration(cfg)?)
    }

    pub fn stats(&self) -> ArchiveStats {
        self.stats.lock().clone()
    }

    /// Admit a record without waiting for disk I/O or queue capacity.
    ///
    /// Budget includes the record being written. Payloads leave reserved space for
    /// summaries; overload and oversized records produce observable coverage loss.
    pub fn record(&self, request_id: u64, direction: &str, transport: &str, data: Value) -> io::Result<Admission> {
        let root = self.directory.read().clone();
        let Some(root) = root else {
            if self.writer.lock().sender.is_none() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "archive writer is closed"));
            }
            return Ok(Admission::Disabled);
        };
        let summary = direction == "summary";
        let now = Utc::now();
        // Budget only the path length here. Root resolution and filesystem work
        // stay on the writer thread.
        let path = root.path.join(format!("rust-{}.jsonl", now.format("%Y-%m-%d")));
        let record = json!({ "timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "process_id": std::process::id(), "process_instance_id": process_instance_id(), "request_id": request_id,
            "direction": direction, "transport": transport, "data": data });
        let bytes = heap_budget(&record, 0, self.limits.record_bytes)
            .and_then(|bytes| bytes.checked_add(path.as_os_str().len() + 256));
        let writer = self.writer.lock();
        let Some(sender) = &writer.sender else {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "archive writer is closed or unavailable"));
        };
        let mut stats = self.stats.lock();
        let record_limit = if summary { self.limits.records } else { self.limits.payload_records };
        let byte_limit = if summary { self.limits.bytes } else { self.limits.payload_bytes };
        let Some(bytes) = bytes.filter(|bytes| {
            *bytes <= self.limits.record_bytes
                && stats.pending_records < record_limit
                && stats.pending_bytes.saturating_add(*bytes) <= byte_limit
        }) else {
            note_drop(&mut stats, summary);
            return Ok(Admission::Dropped);
        };
        stats.pending_records += 1;
        stats.pending_bytes += bytes;
        // The writer lock orders admissions; the budget lock prevents the worker
        // releasing a reservation until try_send has either accepted or rolled back.
        match sender.try_send(Job { path, root, observed_day: now.date_naive(), record, bytes, summary }) {
            Ok(()) => Ok(Admission::Queued),
            Err(_) => {
                stats.pending_records -= 1;
                stats.pending_bytes -= bytes;
                note_drop(&mut stats, summary);
                Ok(Admission::Dropped)
            }
        }
    }

    /// Close admission and drain accepted records. Call off async request workers.
    pub fn shutdown(&self) -> io::Result<()> {
        let _drain = self.drain.lock();
        let handle = {
            let mut writer = self.writer.lock();
            writer.sender.take();
            self.directory.write().take();
            writer.handle.take()
        };
        if let Some(handle) = handle {
            handle.join().map_err(|_| io::Error::other("archive writer panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Audit {
    fn drop(&mut self) {
        // Dropping an App must never wait for disk I/O on a request worker.
        // Serve explicitly drains before process exit; abandoned instances close admission.
        self.writer.get_mut().sender.take();
    }
}

fn note_drop(stats: &mut ArchiveStats, summary: bool) {
    if summary {
        stats.dropped_summaries += 1;
    } else {
        stats.dropped_payloads += 1;
    }
}

fn needs_report(count: u64, previous: u64) -> bool {
    count > 0 && (previous == 0 || count >= previous.saturating_mul(2))
}

/// Conservative owned-heap estimate, capped before serialization or queue admission.
fn heap_budget(value: &Value, depth: usize, limit: usize) -> Option<usize> {
    if depth > 128 {
        return None;
    }
    let mut bytes = std::mem::size_of::<Value>();
    match value {
        Value::String(text) => bytes = bytes.checked_add(text.capacity())?,
        Value::Array(values) => {
            bytes = bytes.checked_add(values.capacity().checked_mul(std::mem::size_of::<Value>())?)?;
            for value in values {
                bytes = bytes.checked_add(heap_budget(value, depth + 1, limit.saturating_sub(bytes))?)?;
                if bytes > limit {
                    return None;
                }
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                bytes = bytes.checked_add(128 + key.capacity())?;
                bytes = bytes.checked_add(heap_budget(value, depth + 1, limit.saturating_sub(bytes))?)?;
                if bytes > limit {
                    return None;
                }
            }
        }
        _ => {}
    }
    (bytes <= limit).then_some(bytes)
}

struct CachedCapture {
    path: PathBuf,
    root: Root,
    file: BufWriter<File>,
}

struct SealJob {
    root: PathBuf,
    sealer: ClosedFileSealer,
    health_sequence: u64,
}

struct SealWorker {
    sender: Option<mpsc::SyncSender<SealJob>>,
    handle: Option<JoinHandle<()>>,
    pending: Arc<Mutex<HashSet<PathBuf>>>,
    stats: Arc<Mutex<ArchiveStats>>,
    health: Arc<Mutex<SealHealth>>,
}

#[derive(Default)]
struct SealHealth {
    blocked: HashMap<PathBuf, usize>,
    deferred: HashMap<PathBuf, usize>,
    errors: HashMap<PathBuf, (String, Option<i32>, u64)>,
    sequence: u64,
}

impl SealHealth {
    fn update_stats(&self, stats: &mut ArchiveStats) {
        stats.seal_blocked_files = self.blocked.values().sum();
        stats.seal_deferred_files = self.deferred.values().sum();
        stats.seal_failed_roots = self.errors.len();
        let last = self.errors.values().max_by_key(|error| error.2);
        stats.last_seal_error_kind = last.map(|error| error.0.clone());
        stats.last_seal_os_error = last.and_then(|error| error.1);
    }
}

fn note_root_seal_error(health: &Mutex<SealHealth>, stats: &Mutex<ArchiveStats>, root: &Path, error: &io::Error) {
    let mut health = health.lock();
    health.sequence = health.sequence.saturating_add(1);
    let sequence = health.sequence;
    health.errors.insert(root.to_path_buf(), (format!("{:?}", error.kind()), error.raw_os_error(), sequence));
    let mut stats = stats.lock();
    stats.seal_errors += 1;
    health.update_stats(&mut stats);
    drop(stats);
    drop(health);
    tracing::warn!(error_kind = ?error.kind(), os_error = ?error.raw_os_error(), "capture sealing is incomplete");
}

impl SealWorker {
    fn new(stats: Arc<Mutex<ArchiveStats>>) -> io::Result<Self> {
        Self::with_runner(stats, |mut sealer| sealer.seal_closed_files_bounded(Utc::now(), SEAL_BATCH_FILES))
    }

    fn with_runner(
        stats: Arc<Mutex<ArchiveStats>>,
        mut seal: impl FnMut(ClosedFileSealer) -> io::Result<capture_lifecycle::SealReport> + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<SealJob>(1);
        let pending = Arc::new(Mutex::new(HashSet::new()));
        let worker_pending = pending.clone();
        let worker_stats = stats.clone();
        let health = Arc::new(Mutex::new(SealHealth::default()));
        let worker_health = health.clone();
        let handle = std::thread::Builder::new().name("proxy-capture-seals".into()).spawn(move || {
            for job in receiver {
                let pending = PendingSeal {
                    root: job.root.clone(),
                    pending: worker_pending.clone(),
                    stats: worker_stats.clone(),
                };
                match seal(job.sealer) {
                    Ok(report) => {
                        let mut health = worker_health.lock();
                        health.blocked.insert(
                            job.root.clone(),
                            report.skipped.iter().filter(|skip| skip.reason == SealSkipReason::FailedCapture).count(),
                        );
                        health.deferred.insert(
                            job.root.clone(),
                            report.skipped.iter().filter(|skip| skip.reason == SealSkipReason::Deferred).count(),
                        );
                        let mut stats = worker_stats.lock();
                        stats.sealed_files += report.sealed.len() as u64;
                        // A newer floor/close/preparation error may appear while
                        // an older immutable snapshot hashes successfully.
                        if health.errors.get(&job.root).is_some_and(|error| error.2 <= job.health_sequence) {
                            health.errors.remove(&job.root);
                        }
                        health.update_stats(&mut stats);
                    }
                    Err(error) => note_root_seal_error(&worker_health, &worker_stats, &job.root, &error),
                }
                drop(pending);
            }
        })?;
        Ok(Self { sender: Some(sender), handle: Some(handle), pending, stats, health })
    }

    fn record_error(&self, root: &Path, error: &io::Error) {
        note_root_seal_error(&self.health, &self.stats, root, error);
    }

    fn submit(&self, root: &Root) -> io::Result<()> {
        {
            let mut pending = self.pending.lock();
            if !pending.insert(root.path.clone()) {
                return Ok(());
            }
            self.stats.lock().seal_pending_roots = pending.len();
        }
        let result = (|| {
            let health_sequence = self.health.lock().sequence;
            let sealer = root.producer.lock().closed_file_sealer()?;
            let Some(sender) = &self.sender else {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "capture seal worker is closed"));
            };
            match sender.try_send(SealJob { root: root.path.clone(), sealer, health_sequence }) {
                Ok(()) => return Ok(true),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "capture seal worker is unavailable"));
                }
                Err(mpsc::TrySendError::Full(_)) => {}
            }
            // One running pass and one waiting pass are enough. A skipped root
            // is retried on the next maintenance tick, without queue growth.
            Ok(false)
        })();
        if !matches!(result, Ok(true)) {
            let mut pending = self.pending.lock();
            pending.remove(&root.path);
            self.stats.lock().seal_pending_roots = pending.len();
        }
        result.map(|_| ())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.sender.take();
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| io::Error::other("capture seal worker panicked"))?;
        }
        Ok(())
    }
}

struct PendingSeal {
    root: PathBuf,
    pending: Arc<Mutex<HashSet<PathBuf>>>,
    stats: Arc<Mutex<ArchiveStats>>,
}

impl Drop for PendingSeal {
    fn drop(&mut self) {
        let mut pending = self.pending.lock();
        pending.remove(&self.root);
        self.stats.lock().seal_pending_roots = pending.len();
    }
}

impl Drop for SealWorker {
    fn drop(&mut self) {
        self.sender.take();
        // Detached tickets retain the OS producer lock while a dropped Audit
        // drains. Normal shutdown joins explicitly after closing capture files.
    }
}

struct CaptureWriter {
    current: Option<CachedCapture>,
    roots: Roots,
    seals: SealWorker,
    maintenance_cursor: usize,
}

impl CaptureWriter {
    fn new(roots: Roots, stats: Arc<Mutex<ArchiveStats>>) -> io::Result<Self> {
        Ok(Self { current: None, roots, seals: SealWorker::new(stats)?, maintenance_cursor: 0 })
    }

    fn maintain_at(&mut self, day: NaiveDate) -> io::Result<()> {
        // The sole cached handle must close before any root publishes a newer
        // floor. Switching roots also closes it, so no older handles survive.
        if self.current.as_ref().is_some_and(|capture| capture.root.producer.lock().capture_day_floor() < day) {
            let root = self.current.as_ref().unwrap().root.path.clone();
            if let Err(error) = close_capture(&mut self.current) {
                self.seals.record_error(&root, &error);
                return Err(error);
            }
        }
        let mut roots: Vec<_> = self.roots.lock().values().cloned().collect();
        roots.sort_by(|left, right| left.path.cmp(&right.path));
        if !roots.is_empty() {
            let cursor = self.maintenance_cursor % roots.len();
            roots.rotate_left(cursor);
            self.maintenance_cursor = cursor + 1;
        }
        let mut first_error = None;
        for root in roots {
            let result = (|| {
                root.producer.lock().resolve(day, CaptureChannel::Proxy)?;
                self.seals.submit(&root)
            })();
            if let Err(error) = result {
                self.seals.record_error(&root.path, &error);
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl ArchiveWriter for CaptureWriter {
    fn write(&mut self, job: &mut Job) -> io::Result<()> {
        let previous_floor = job.root.producer.lock().capture_day_floor();
        let result = write_job(job, &mut self.current);
        // A successful floor transition is safe even when opening/writing the
        // new file fails: old handles are already closed. Its failed new path
        // remains blocked and cannot become cleanup authority later.
        let advanced = job.root.producer.lock().capture_day_floor() > previous_floor;
        if advanced && let Err(error) = self.seals.submit(&job.root) {
            self.seals.record_error(&job.root.path, &error);
        }
        result
    }

    fn maintain(&mut self) -> io::Result<()> {
        // Per-root maintenance errors already update health. Other roots can
        // still progress, and only that failed root's retry clears its error.
        let _ = self.maintain_at(Utc::now().date_naive());
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        let closed = close_capture(&mut self.current);
        let sealed = self.seals.finish();
        closed.and(sealed)
    }
}

fn note_seal_error(stats: &Mutex<ArchiveStats>, error: &io::Error) {
    let mut stats = stats.lock();
    stats.seal_errors += 1;
    stats.last_seal_error_kind = Some(format!("{:?}", error.kind()));
    stats.last_seal_os_error = error.raw_os_error();
    drop(stats);
    tracing::warn!(error_kind = ?error.kind(), os_error = ?error.raw_os_error(), "capture sealing is incomplete");
}

fn discard_capture(capture: CachedCapture, failed: bool) -> io::Result<()> {
    let CachedCapture { path, root, file } = capture;
    // into_parts prevents BufWriter::drop from retrying bytes after a failed
    // write or flush. The underlying writable handle closes before the marker.
    let (file, buffer) = file.into_parts();
    drop(buffer);
    drop(file);
    if failed {
        let relative = path
            .strip_prefix(&root.path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "capture path is outside its root"))?;
        root.producer.lock().block_sealing(relative)?;
    }
    Ok(())
}

fn close_capture(current: &mut Option<CachedCapture>) -> io::Result<()> {
    close_capture_with(current, |file| {
        file.flush()?;
        file.get_ref().sync_all()
    })
}

fn close_capture_with(
    current: &mut Option<CachedCapture>,
    close: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>,
) -> io::Result<()> {
    let Some(mut capture) = current.take() else { return Ok(()) };
    let result = close(&mut capture.file);
    let marker = discard_capture(capture, result.is_err());
    marker.and(result)
}

fn write_job(job: &mut Job, current: &mut Option<CachedCapture>) -> io::Result<()> {
    write_job_with_io(job, current, close_capture, |file, job| {
        serde_json::to_writer(&mut *file, &job.record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        if job.summary {
            file.get_ref().sync_all()?;
        }
        Ok(())
    })
}

fn write_job_with_io(
    job: &mut Job,
    current: &mut Option<CachedCapture>,
    mut close: impl FnMut(&mut Option<CachedCapture>) -> io::Result<()>,
    write: impl FnOnce(&mut BufWriter<File>, &Job) -> io::Result<()>,
) -> io::Result<()> {
    let mut producer = job.root.producer.lock();
    let day = job.observed_day.max(producer.capture_day_floor());
    let changing_root = current.as_ref().is_some_and(|capture| !Arc::ptr_eq(&capture.root, &job.root));
    let advancing = day > producer.capture_day_floor();
    drop(producer);
    if changing_root || advancing {
        close(current)?;
    }
    producer = job.root.producer.lock();
    // Resolve happens only after cached old handles have flushed, synced and
    // dropped. Old queued event days are clamped to the newer durable floor.
    job.path = producer.resolve(job.observed_day, CaptureChannel::Proxy)?;
    if current.as_ref().is_none_or(|capture| capture.path != job.path) {
        drop(producer);
        close(current)?;
        producer = job.root.producer.lock();
        let (path, file) = producer.open_append(job.observed_day, CaptureChannel::Proxy)?;
        if path != job.path {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "capture storage day changed before append"));
        }
        *current = Some(CachedCapture { path, root: job.root.clone(), file: BufWriter::with_capacity(64 << 10, file) });
    }
    drop(producer);
    let result = write(&mut current.as_mut().unwrap().file, job);
    if result.is_err()
        && let Some(capture) = current.take()
    {
        discard_capture(capture, true)?;
    }
    result
}

#[cfg(test)]
#[path = "audit/diagnostic_benchmark.rs"]
mod diagnostic_benchmark;
#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
