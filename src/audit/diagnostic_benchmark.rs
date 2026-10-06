//! Synthetic archive diagnostics; no credentials, upstream calls, or production files.
use super::*;
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

async fn measure(offload: bool) -> Value {
    let dir = std::env::temp_dir().join(format!("cliproxy-heartbeat-{}", uuid::Uuid::new_v4()));
    let cfg = Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
    let audit = Arc::new(Audit::new(&cfg));
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
        jobs.push(tokio::spawn(async move {
            if offload {
                tokio::task::spawn_blocking(move || {
                    for _ in 0..4 {
                        audit.record(id, "synthetic_payload", "benchmark", body.clone()).unwrap();
                    }
                })
                .await
                .unwrap();
            } else {
                for _ in 0..4 {
                    audit.record(id, "synthetic_payload", "benchmark", body.clone()).unwrap();
                }
            }
        }));
    }
    for job in jobs {
        job.await.unwrap();
    }
    done.store(true, Ordering::Relaxed);
    let delay = monitor.await.unwrap();
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    std::fs::remove_dir_all(dir).unwrap();
    json!({"offload":offload,"records":32,"elapsed_ms":elapsed,"max_heartbeat_delay_ms":delay})
}

/// Compare the installed archive code on request workers versus blocking workers.
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
