use super::*;
use std::sync::{Condvar, Mutex as StdMutex};
use std::time::Duration;

fn config() -> (Config, PathBuf) {
    let dir = std::env::temp_dir().join(format!("cliproxy-audit-{}", uuid::Uuid::new_v4()));
    capture_lifecycle::enroll(&dir, CaptureLayout::Proxy, Utc::now().date_naive()).unwrap();
    (Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() }, dir)
}

#[test]
fn queued_archive_drains_in_order_and_retains_private_permissions() {
    let dir = std::env::temp_dir().join(format!("cliproxy-audit-{}", uuid::Uuid::new_v4()));
    let mut cfg = Config { request_log: false, request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
    let audit = Audit::new(&cfg).unwrap();
    assert_eq!(audit.record(0, "summary", "test", json!({})).unwrap(), Admission::Disabled);
    assert!(!dir.exists());
    cfg.request_log = true;
    capture_lifecycle::enroll(&dir, CaptureLayout::Proxy, Utc::now().date_naive()).unwrap();
    audit.configure(&cfg).unwrap();
    for id in 1..=20 {
        assert_eq!(audit.record(id, "summary", "test", json!({"id":id})).unwrap(), Admission::Queued);
    }
    audit.shutdown().unwrap();
    assert_eq!(audit.stats().written, 20);
    assert_eq!(audit.stats().pending_records, 0);
    assert_eq!(audit.stats().pending_bytes, 0);
    assert!(audit.record(21, "summary", "test", json!({})).is_err());
    let path = capture_path(&dir);
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

fn capture_path(dir: &std::path::Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "jsonl"))
        .unwrap()
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
    })
    .unwrap();
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
    let (cfg, dir) = config();
    let mut first = true;
    let audit = Audit::with_writer(&cfg, LIMITS, move |_| {
        if std::mem::take(&mut first) { Err(io::Error::other("synthetic disk failure")) } else { Ok(()) }
    })
    .unwrap();
    for id in 0..2 {
        audit.record(id, "summary", "test", json!({})).unwrap();
    }
    audit.shutdown().unwrap();
    let stats = audit.stats();
    assert_eq!((stats.write_errors, stats.written, stats.pending_records, stats.pending_bytes), (1, 1, 0, 0));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn records_capture_directory_before_configuration_changes() {
    let (cfg, first) = config();
    let (next, second) = config();
    let audit = Audit::new(&cfg).unwrap();
    audit.record(1, "summary", "test", json!({})).unwrap();
    audit.configure(&next).unwrap();
    audit.record(2, "summary", "test", json!({})).unwrap();
    audit.shutdown().unwrap();
    for (dir, expected) in [(first, 1), (second, 2)] {
        let path = capture_path(&dir);
        let record: Value = serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(record["request_id"], expected);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn serialization_admission_limits_depth_and_preserves_summary_sync() {
    let (cfg, dir) = config();
    let audit = Audit::new(&cfg).unwrap();
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

#[test]
fn startup_rejects_unenrolled_busy_and_corrupt_roots_before_account_loading() {
    let (cfg, dir) = config();
    let mut missing = cfg.clone();
    missing.request_log_dir = dir.join("unenrolled").to_string_lossy().into();
    assert!(Audit::new(&missing).is_err());
    let audit = Audit::new(&cfg).unwrap();
    assert!(Audit::new(&cfg).is_err());
    audit.shutdown().unwrap();
    std::fs::write(dir.join(capture_lifecycle::STATE_DIRECTORY).join("state.json"), b"null").unwrap();
    let app_cfg = Config { auth_dir: "/nonexistent".into(), ..cfg };
    assert!(crate::state::App::new(app_cfg, dir.join("unused.yaml")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejected_configuration_retains_the_previous_capture_directory() {
    let (cfg, dir) = config();
    let audit = Audit::new(&cfg).unwrap();
    let mut invalid = cfg.clone();
    invalid.request_log_dir = dir.join("unenrolled").to_string_lossy().into();
    assert!(audit.configure(&invalid).is_err());
    audit.record(1, "summary", "test", json!({})).unwrap();
    audit.shutdown().unwrap();
    assert_eq!(audit.stats().written, 1);
    assert!(capture_path(&dir).exists());
    assert!(!dir.join("unenrolled").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unapplied_configuration_releases_its_new_guard_without_waiting_for_shutdown() {
    let (cfg, first) = config();
    let (next, second) = config();
    let audit = Audit::new(&cfg).unwrap();
    let prepared = audit.prepare_configuration(&next).unwrap();
    assert_eq!(CaptureRoot::open(&second, CaptureLayout::Proxy).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    drop(prepared);
    assert!(CaptureRoot::open(&second, CaptureLayout::Proxy).is_ok());
    assert_eq!(CaptureRoot::open(&first, CaptureLayout::Proxy).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    audit.shutdown().unwrap();
    std::fs::remove_dir_all(first).unwrap();
    std::fs::remove_dir_all(second).unwrap();
}

#[test]
fn requests_do_not_wait_for_the_root_guard_or_floor_persistence() {
    let (cfg, dir) = config();
    let audit = Arc::new(Audit::new(&cfg).unwrap());
    let root = audit.directory.read().clone().unwrap();
    let held = root.producer.lock();
    let (sent, received) = mpsc::channel();
    let requester = audit.clone();
    let task = std::thread::spawn(move || {
        sent.send(requester.record(1, "summary", "test", json!({}))).unwrap();
    });
    let admission = received.recv_timeout(Duration::from_secs(1));
    drop(held);
    task.join().unwrap();
    assert_eq!(admission.unwrap().unwrap(), Admission::Queued);
    drop(root);
    audit.shutdown().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn backdated_queued_records_use_the_floor_bucket_without_rewriting_event_time() {
    let (cfg, dir) = config();
    let today = Utc::now().date_naive();
    let floor = today.succ_opt().unwrap().succ_opt().unwrap();
    capture_lifecycle::enroll(&dir, CaptureLayout::Proxy, floor).unwrap();
    let old = dir.join(format!("rust-{today}.jsonl"));
    std::fs::write(&old, b"{\"historic\":true}\n").unwrap();
    let audit = Audit::new(&cfg).unwrap();
    audit.record(1, "summary", "test", json!({})).unwrap();
    audit.shutdown().unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"{\"historic\":true}\n");
    let path = dir.join(format!("rust-{floor}.jsonl"));
    let row: Value = serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
    let event_day = chrono::DateTime::parse_from_rfc3339(row["timestamp"].as_str().unwrap()).unwrap().date_naive();
    assert!(event_day < floor);
    assert_eq!(row["request_id"], 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dropped_audit_retains_all_previous_root_locks_through_real_queue_drain() {
    let (cfg, first) = config();
    let (next, second) = config();
    let open = Arc::new((StdMutex::new(false), Condvar::new()));
    let waiting = open.clone();
    let (started, received) = mpsc::channel();
    let mut current = None;
    let audit = Audit::with_writer(&cfg, LIMITS, move |job| {
        let _ = started.send(());
        let (lock, ready) = &*waiting;
        let mut state = lock.lock().unwrap();
        while !*state {
            state = ready.wait(state).unwrap();
        }
        drop(state);
        write_job(job, &mut current)
    })
    .unwrap();
    let gate = Gate { started: received, open };
    audit.record(1, "summary", "test", json!({})).unwrap();
    gate.started.recv_timeout(Duration::from_secs(1)).unwrap();
    audit.record(2, "summary", "test", json!({})).unwrap();
    audit.configure(&next).unwrap();
    audit.record(3, "summary", "test", json!({})).unwrap();
    let disabled = Config { request_log: false, ..next };
    audit.configure(&disabled).unwrap();
    drop(audit);
    for dir in [&first, &second] {
        assert_eq!(CaptureRoot::open(dir, CaptureLayout::Proxy).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    }
    let paths = [first.clone(), second.clone()];
    let (done, finished) = mpsc::channel();
    // Blocking OS locks give the test an event, without polling the writer.
    let observer = std::thread::spawn(move || {
        let mut locks = Vec::new();
        for path in paths {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path.join(capture_lifecycle::STATE_DIRECTORY).join("producer.lock"))
                .unwrap();
            file.lock().unwrap();
            locks.push(file);
        }
        drop(locks);
        done.send(()).unwrap();
    });
    assert!(finished.recv_timeout(Duration::from_millis(30)).is_err());
    gate.release();
    finished.recv_timeout(Duration::from_secs(5)).unwrap();
    observer.join().unwrap();
    for (dir, ids) in [(&first, vec![1, 2]), (&second, vec![3])] {
        let text = std::fs::read_to_string(capture_path(dir)).unwrap();
        let actual: Vec<_> = text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["request_id"].as_u64().unwrap())
            .collect();
        assert_eq!(actual, ids);
        assert!(CaptureRoot::open(dir, CaptureLayout::Proxy).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn concurrent_shutdown_waits_for_file_close_and_releases_all_guards() {
    let (audit, gate) = blocked(LIMITS);
    let dir = audit.directory.read().as_ref().unwrap().path.clone();
    let audit = Arc::new(audit);
    audit.record(1, "summary", "test", json!({})).unwrap();
    gate.started.recv_timeout(Duration::from_secs(1)).unwrap();
    let (done, finished) = mpsc::channel();
    let a = audit.clone();
    let sent = done.clone();
    let first = std::thread::spawn(move || {
        a.shutdown().unwrap();
        sent.send(()).unwrap();
    });
    let b = audit.clone();
    let second = std::thread::spawn(move || {
        b.shutdown().unwrap();
        done.send(()).unwrap();
    });
    assert!(finished.recv_timeout(Duration::from_millis(30)).is_err());
    assert_eq!(CaptureRoot::open(&dir, CaptureLayout::Proxy).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    gate.release();
    finished.recv_timeout(Duration::from_secs(5)).unwrap();
    finished.recv_timeout(Duration::from_secs(5)).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    assert!(CaptureRoot::open(&dir, CaptureLayout::Proxy).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writer_unwind_closes_files_before_the_previous_roots_can_be_reopened() {
    let (cfg, dir) = config();
    let audit = Audit::with_writer(&cfg, LIMITS, move |_| panic!("synthetic archive worker panic")).unwrap();
    audit.record(1, "summary", "test", json!({})).unwrap();
    assert!(audit.shutdown().is_err());
    assert!(CaptureRoot::open(&dir, CaptureLayout::Proxy).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}
