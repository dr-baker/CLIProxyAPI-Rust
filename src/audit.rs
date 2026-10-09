//! Bounded, local payload archive. Serialization and disk I/O run on one writer thread.
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::JoinHandle;

use capture_lifecycle::{CaptureChannel, CaptureLayout, CaptureRoot};
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

impl Audit {
    pub fn new(cfg: &Config) -> io::Result<Self> {
        let mut file = None;
        Self::with_writer(cfg, LIMITS, move |job| write_job(job, &mut file))
    }

    fn with_writer(
        cfg: &Config,
        limits: Limits,
        write: impl FnMut(&Job) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        let roots = Arc::new(Mutex::new(HashMap::new()));
        let directory = Self::prepare(&roots, cfg)?;
        if let Some(root) = &directory.0 {
            roots.lock().insert(root.path.clone(), root.clone());
        }
        let worker_roots = roots.clone();
        let stats = Arc::new(Mutex::new(ArchiveStats::default()));
        let worker_stats = stats.clone();
        let (sender, receiver) = mpsc::sync_channel::<Job>(limits.records);
        let handle = std::thread::Builder::new().name("proxy-archive".into()).spawn(move || {
            let lifetime = RootLifetime(worker_roots);
            // Locals drop in reverse order during unwinding. The write closure
            // closes its file handles before RootLifetime releases the guards.
            let mut write = write;
            let mut reported = (0, 0, 0);
            for mut job in receiver {
                // Resolve when writing, so clock rollback and old queued jobs
                // cannot reopen a path below this root's durable day floor.
                let result = (|| {
                    job.path = job.root.producer.lock().resolve(job.observed_day, CaptureChannel::Proxy)?;
                    write(&job)
                })();
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

fn write_job(job: &Job, current: &mut Option<(PathBuf, BufWriter<File>)>) -> io::Result<()> {
    if current.as_ref().is_none_or(|(path, _)| path != &job.path) {
        if let Some((_, file)) = current {
            file.flush()?;
        }
        let (path, file) = job.root.producer.lock().open_append(job.observed_day, CaptureChannel::Proxy)?;
        if path != job.path {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "capture storage day changed before append"));
        }
        *current = Some((path, BufWriter::with_capacity(64 << 10, file)));
    }
    let file = &mut current.as_mut().unwrap().1;
    let result = (|| {
        serde_json::to_writer(&mut *file, &job.record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        if job.summary {
            file.get_ref().sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        // Do not retry buffered bytes from a failed record on the next event.
        if let Some((_, file)) = current.take() {
            let _ = file.into_parts();
        }
    }
    result
}

#[cfg(test)]
#[path = "audit/diagnostic_benchmark.rs"]
mod diagnostic_benchmark;
#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
