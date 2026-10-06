use super::*;
use std::sync::{Condvar, Mutex as StdMutex};
use std::time::Duration;

fn config() -> (Config, PathBuf) {
    let dir = std::env::temp_dir().join(format!("cliproxy-audit-{}", uuid::Uuid::new_v4()));
    (Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() }, dir)
}

#[test]
fn queued_archive_drains_in_order_and_retains_private_permissions() {
    let (mut cfg, dir) = config();
    cfg.request_log = false;
    let audit = Audit::new(&cfg);
    assert_eq!(audit.record(0, "summary", "test", json!({})).unwrap(), Admission::Disabled);
    assert!(!dir.exists());
    cfg.request_log = true;
    audit.configure(&cfg);
    for id in 1..=20 {
        assert_eq!(audit.record(id, "summary", "test", json!({"id":id})).unwrap(), Admission::Queued);
    }
    audit.shutdown().unwrap();
    assert_eq!(audit.stats().written, 20);
    assert_eq!(audit.stats().pending_records, 0);
    assert_eq!(audit.stats().pending_bytes, 0);
    assert!(audit.record(21, "summary", "test", json!({})).is_err());
    let path = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    let text = std::fs::read_to_string(&path).unwrap();
    let rows: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(rows.len(), 20);
    assert_eq!(rows[0]["request_id"], 1);
    assert_eq!(rows[19]["request_id"], 20);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

struct Gate {
    started: mpsc::Receiver<()>,
    open: Arc<(StdMutex<bool>, Condvar)>,
}

impl Gate {
    fn release(&self) {
        let (lock, ready) = &*self.open;
        *lock.lock().unwrap() = true;
        ready.notify_all();
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

fn blocked(limits: Limits) -> (Audit, Gate) {
    let (cfg, _) = config();
    let open = Arc::new((StdMutex::new(false), Condvar::new()));
    let gate = open.clone();
    let (sender, started) = mpsc::channel();
    let audit = Audit::with_writer(&cfg, limits, move |_| {
        let _ = sender.send(());
        let (lock, ready) = &*gate;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = ready.wait(open).unwrap();
        }
        Ok(())
    });
    (audit, Gate { started, open })
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_writer_never_blocks_requests_and_reserves_summary_capacity() {
    let limits = Limits { records: 3, payload_records: 2, ..LIMITS };
    let (audit, gate) = blocked(limits);
    assert_eq!(audit.record(1, "upstream_event", "test", json!({})).unwrap(), Admission::Queued);
    gate.started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(audit.record(2, "upstream_event", "test", json!({})).unwrap(), Admission::Queued);
    assert_eq!(audit.record(3, "upstream_event", "test", json!({})).unwrap(), Admission::Dropped);
    assert_eq!(audit.record(4, "summary", "test", json!({})).unwrap(), Admission::Queued);
    assert_eq!(audit.record(5, "summary", "test", json!({})).unwrap(), Admission::Dropped);
    tokio::time::timeout(Duration::from_millis(100), tokio::time::sleep(Duration::from_millis(1))).await.unwrap();
    let stats = audit.stats();
    assert_eq!((stats.pending_records, stats.dropped_payloads, stats.dropped_summaries), (3, 1, 1));
    gate.release();
    tokio::task::spawn_blocking(move || {
        audit.shutdown().unwrap();
        assert_eq!(audit.stats().written, 3);
    })
    .await
    .unwrap();
}

#[test]
fn byte_budget_and_oversized_records_are_observable_and_released() {
    let limits = Limits { bytes: 6000, payload_bytes: 3500, record_bytes: 4000, ..LIMITS };
    let (audit, gate) = blocked(limits);
    assert_eq!(audit.record(1, "upstream_event", "test", json!({"text":"x".repeat(1200)})).unwrap(), Admission::Queued);
    gate.started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        audit.record(2, "upstream_event", "test", json!({"text":"x".repeat(1200)})).unwrap(),
        Admission::Dropped
    );
    assert_eq!(audit.record(3, "summary", "test", json!({"text":"x".repeat(5000)})).unwrap(), Admission::Dropped);
    assert_eq!(audit.record(4, "summary", "test", json!({})).unwrap(), Admission::Queued);
    assert!(audit.stats().pending_bytes <= limits.bytes);
    gate.release();
    audit.shutdown().unwrap();
    let stats = audit.stats();
    assert_eq!(
        (stats.pending_records, stats.pending_bytes, stats.dropped_payloads, stats.dropped_summaries),
        (0, 0, 1, 1)
    );
}

#[test]
fn write_failure_does_not_stop_later_records_or_leak_reservations() {
    let (cfg, _) = config();
    let mut first = true;
    let audit = Audit::with_writer(&cfg, LIMITS, move |_| {
        if std::mem::take(&mut first) { Err(io::Error::other("synthetic disk failure")) } else { Ok(()) }
    });
    for id in 0..2 {
        audit.record(id, "summary", "test", json!({})).unwrap();
    }
    audit.shutdown().unwrap();
    let stats = audit.stats();
    assert_eq!((stats.write_errors, stats.written, stats.pending_records, stats.pending_bytes), (1, 1, 0, 0));
}

#[test]
fn records_capture_directory_before_configuration_changes() {
    let (cfg, first) = config();
    let (next, second) = config();
    let audit = Audit::new(&cfg);
    audit.record(1, "summary", "test", json!({})).unwrap();
    audit.configure(&next);
    audit.record(2, "summary", "test", json!({})).unwrap();
    audit.shutdown().unwrap();
    for (dir, expected) in [(first, 1), (second, 2)] {
        let path = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        let record: Value = serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(record["request_id"], expected);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn serialization_admission_limits_depth_and_preserves_summary_sync() {
    let (cfg, dir) = config();
    let audit = Audit::new(&cfg);
    let mut deep = json!({});
    for _ in 0..130 {
        deep = json!([deep]);
    }
    assert_eq!(audit.record(1, "upstream_event", "test", deep).unwrap(), Admission::Dropped);
    audit.record(2, "summary", "test", json!({"status":200})).unwrap();
    audit.shutdown().unwrap();
    assert_eq!((audit.stats().dropped_payloads, audit.stats().written), (1, 1));
    std::fs::remove_dir_all(dir).unwrap();
}
