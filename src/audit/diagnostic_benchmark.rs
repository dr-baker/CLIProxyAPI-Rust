//! Synthetic archive diagnostics; no credentials, upstream calls, or production files.
use super::*;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
struct CountingWriter {
    writes: usize,
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.bytes += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn payload() -> Value {
    json!({"input": (0..1000).map(|n| json!({"type":"message","role":"user","content":[
        {"type":"input_text","text":format!("synthetic item {n}")}
    ]})).collect::<Vec<_>>()})
}

/// Measure the write-call amplification of serializing JSON directly to a file.
#[test]
fn buffered_json_preserves_bytes_and_reduces_write_calls() {
    let body = payload();
    let mut direct = CountingWriter::default();
    serde_json::to_writer(&mut direct, &body).unwrap();
    let mut buffered = std::io::BufWriter::with_capacity(64 * 1024, CountingWriter::default());
    serde_json::to_writer(&mut buffered, &body).unwrap();
    buffered.flush().unwrap();
    assert_eq!(direct.bytes, buffered.get_ref().bytes);
    assert!(direct.writes > buffered.get_ref().writes * 100);
    println!(
        "archive_write_calls direct={} buffered={} bytes={}",
        direct.writes,
        buffered.get_ref().writes,
        direct.bytes
    );
}

async fn measure(background: bool) -> Value {
    let dir = std::env::temp_dir().join(format!("cliproxy-heartbeat-{}", uuid::Uuid::new_v4()));
    let cfg = Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
    capture_lifecycle::enroll(&dir, CaptureLayout::Proxy, Utc::now().date_naive()).unwrap();
    let audit = Arc::new(Audit::new(&cfg).unwrap());
    let legacy_lock = Arc::new(Mutex::new(()));
    let done = Arc::new(AtomicBool::new(false));
    let monitor_done = done.clone();
    let monitor = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        loop {
            let before = Instant::now();
            tokio::time::sleep(Duration::from_millis(10)).await;
            worst = worst.max(before.elapsed().saturating_sub(Duration::from_millis(10)));
            if monitor_done.load(Ordering::Relaxed) {
                return worst.as_secs_f64() * 1000.0;
            }
        }
    });
    // Start the heartbeat before the archive tasks occupy the request workers.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let body = payload();
    let start = Instant::now();
    let mut jobs = Vec::new();
    for id in 0..8 {
        let audit = audit.clone();
        let body = body.clone();
        let dir = dir.clone();
        let legacy_lock = legacy_lock.clone();
        jobs.push(tokio::spawn(async move {
            for _ in 0..4 {
                if background {
                    assert_eq!(
                        audit.record(id, "synthetic_payload", "benchmark", body.clone()).unwrap(),
                        Admission::Queued
                    );
                } else {
                    // Reproduce the installed implementation: synchronous, unbuffered,
                    // serialized file writes on request workers.
                    let _guard = legacy_lock.lock();
                    std::fs::create_dir_all(&dir).unwrap();
                    let now = Utc::now();
                    let path = dir.join(format!("rust-{}.jsonl", now.format("%Y-%m-%d")));
                    let record = json!({"timestamp":now.to_rfc3339(), "process_id":std::process::id(),
                        "request_id":id,"direction":"synthetic_payload","transport":"benchmark","data":body});
                    let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
                    serde_json::to_writer(&mut file, &record).unwrap();
                    file.write_all(b"\n").unwrap();
                    file.flush().unwrap();
                }
            }
        }));
    }
    for job in jobs {
        job.await.unwrap();
    }
    let drained = audit.clone();
    tokio::task::spawn_blocking(move || drained.shutdown()).await.unwrap().unwrap();
    assert_eq!(audit.stats().dropped_payloads, 0);
    if background {
        assert_eq!(audit.stats().written, 32);
    }
    done.store(true, Ordering::Relaxed);
    let delay = monitor.await.unwrap();
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    std::fs::remove_dir_all(dir).unwrap();
    json!({"background_writer":background,"records":32,"elapsed_ms":elapsed,"max_heartbeat_delay_ms":delay})
}

/// Compare the installed synchronous archive with the bounded background writer.
/// Timing is observational, so this probe has no timing-based pass/fail threshold.
#[test]
#[ignore = "manual synthetic disk and scheduler benchmark"]
fn archive_scheduler_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    for modes in [[false, true], [true, false], [false, true]] {
        for offload in modes {
            println!("{}", rt.block_on(measure(offload)));
        }
    }
}
