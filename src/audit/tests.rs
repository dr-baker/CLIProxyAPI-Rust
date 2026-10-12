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

#[test]
fn process_identity_is_stable_across_audit_reconfiguration_and_preserves_original_data() {
    let (cfg, first) = config();
    let (next, second) = config();
    let root_id = capture_lifecycle::enroll(&first, CaptureLayout::Proxy, Utc::now().date_naive()).unwrap().root_uuid;
    let audit = Audit::new(&cfg).unwrap();
    let original = json!({"type":"response.output_text.delta","delta":"synthetic","process_instance_id":"wire-value"});
    for direction in ["client_request", "upstream_event", "summary"] {
        audit.record(1, direction, "websocket", original.clone()).unwrap();
    }
    audit.configure(&next).unwrap();
    audit.record(2, "downstream_event", "websocket", original.clone()).unwrap();
    audit.shutdown().unwrap();
    let restarted_audit = Audit::new(&cfg).unwrap();
    restarted_audit.record(1, "summary", "http", original.clone()).unwrap();
    restarted_audit.shutdown().unwrap();
    for directory in [&first, &second] {
        let text = std::fs::read_to_string(capture_path(directory)).unwrap();
        for line in text.lines() {
            let record: Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["process_instance_id"], process_instance_id());
            let id = uuid::Uuid::parse_str(record["process_instance_id"].as_str().unwrap()).unwrap();
            assert_ne!(id, root_id);
            assert_eq!(record["process_id"], std::process::id());
            assert_eq!(record["data"], original);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn process_identity_changes_across_proxy_process_starts() {
    let (_, dir) = config();
    for _ in 0..2 {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::tests::process_identity_child", "--ignored"])
            .env("PROXY_AUDIT_PROCESS_TEST_ROOT", &dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "subprocess fixture failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let text = std::fs::read_to_string(capture_path(&dir)).unwrap();
    let records: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(records.len(), 2);
    let first = uuid::Uuid::parse_str(records[0]["process_instance_id"].as_str().unwrap()).unwrap();
    let second = uuid::Uuid::parse_str(records[1]["process_instance_id"].as_str().unwrap()).unwrap();
    assert_ne!(first, second);
    assert_ne!(first.to_string(), process_instance_id());
    assert_ne!(second.to_string(), process_instance_id());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "subprocess fixture, called by process_identity_changes_across_proxy_process_starts"]
fn process_identity_child() {
    let dir = PathBuf::from(std::env::var_os("PROXY_AUDIT_PROCESS_TEST_ROOT").expect("subprocess fixture root"));
    let cfg = Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
    let audit = Audit::new(&cfg).unwrap();
    audit.record(1, "summary", "test", json!({})).unwrap();
    audit.shutdown().unwrap();
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

fn historic_root(day: NaiveDate) -> (Config, PathBuf, Root) {
    let dir = std::env::temp_dir().join(format!("cliproxy-online-seal-{}", uuid::Uuid::new_v4()));
    capture_lifecycle::enroll(&dir, CaptureLayout::Proxy, day).unwrap();
    let cfg = Config { request_log: true, request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
    let root = Arc::new(CaptureHandle {
        path: dir.clone(),
        producer: Mutex::new(CaptureRoot::open(&dir, CaptureLayout::Proxy).unwrap()),
    });
    (cfg, dir, root)
}

fn synthetic_job(root: Root, day: NaiveDate, id: u64) -> Job {
    Job {
        path: root.path.join(format!("rust-{day}.jsonl")),
        root,
        observed_day: day,
        record: json!({"timestamp": format!("{day}T00:00:00Z"), "request_id": id}),
        bytes: 0,
        summary: false,
    }
}

fn capture_writer(root: &Root) -> CaptureWriter {
    let roots = Arc::new(Mutex::new(HashMap::from([(root.path.clone(), root.clone())])));
    CaptureWriter::new(roots, Arc::new(Mutex::new(ArchiveStats::default()))).unwrap()
}

#[test]
fn daily_rotation_flushes_every_cached_byte_before_publishing_floor_and_seal() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (_, dir, root) = historic_root(day);
    let mut writer = capture_writer(&root);
    writer.write(&mut synthetic_job(root.clone(), day, 1)).unwrap();
    // Leave bytes in the buffer to prove rotation flushes the old handle.
    writer.current.as_mut().unwrap().file.write_all(b"{\"buffered\":true}\n").unwrap();
    assert!(!std::fs::read_to_string(dir.join(format!("rust-{day}.jsonl"))).unwrap().contains("buffered"));
    writer.maintain_at(next).unwrap();
    assert!(writer.current.is_none());
    assert_eq!(root.producer.lock().capture_day_floor(), next);
    writer.finish().unwrap();
    let seal = capture_lifecycle::read_seal(&dir, format!("rust-{day}.jsonl")).unwrap();
    let bytes = std::fs::read(dir.join(format!("rust-{day}.jsonl"))).unwrap();
    assert!(bytes.ends_with(b"{\"buffered\":true}\n"));
    assert_eq!(seal.closed_length, bytes.len() as u64);
    assert_eq!(seal.capture_day_floor, next);
    drop(writer);
    drop(root);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn delayed_queued_records_and_clock_rollback_never_append_to_the_sealed_file() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (_, dir, root) = historic_root(day);
    let mut writer = capture_writer(&root);
    writer.write(&mut synthetic_job(root.clone(), day, 1)).unwrap();
    writer.write(&mut synthetic_job(root.clone(), next, 2)).unwrap();
    let before = std::fs::read(dir.join(format!("rust-{day}.jsonl"))).unwrap();
    writer.write(&mut synthetic_job(root.clone(), day, 3)).unwrap();
    writer.maintain_at(day).unwrap();
    writer.write(&mut synthetic_job(root.clone(), day.pred_opt().unwrap(), 4)).unwrap();
    writer.finish().unwrap();
    assert_eq!(std::fs::read(dir.join(format!("rust-{day}.jsonl"))).unwrap(), before);
    assert!(capture_lifecycle::read_seal(&dir, format!("rust-{day}.jsonl")).is_ok());
    let rows: Vec<Value> = std::fs::read_to_string(dir.join(format!("rust-{next}.jsonl")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.iter().map(|row| row["request_id"].as_u64().unwrap()).collect::<Vec<_>>(), [2, 3, 4]);
    assert_eq!(rows[1]["timestamp"], format!("{day}T00:00:00Z"));
    drop(writer);
    drop(root);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_rotation_closes_the_handle_without_advancing_floor_or_sealing_after_restart() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (cfg, dir, root) = historic_root(day);
    let mut current = None;
    write_job(&mut synthetic_job(root.clone(), day, 1), &mut current).unwrap();
    current.as_mut().unwrap().file.write_all(b"unflushed failure bytes").unwrap();
    let error = write_job_with_io(
        &mut synthetic_job(root.clone(), next, 2),
        &mut current,
        |current| close_capture_with(current, |_| Err(io::Error::other("synthetic close sync failure"))),
        |_, _| panic!("new record cannot be written after old close fails"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(current.is_none());
    assert_eq!(root.producer.lock().capture_day_floor(), day);
    assert!(!dir.join(format!("rust-{next}.jsonl")).exists());
    assert!(!std::fs::read_to_string(dir.join(format!("rust-{day}.jsonl"))).unwrap().contains("unflushed"));
    drop(root);
    let restarted = Audit::new(&cfg).unwrap();
    restarted.record(3, "summary", "test", json!({})).unwrap();
    restarted.shutdown().unwrap();
    assert_eq!(restarted.stats().seal_blocked_files, 1);
    assert!(capture_lifecycle::read_seal(&dir, format!("rust-{day}.jsonl")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_record_with_a_complete_newline_is_durably_excluded_from_online_seals() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (cfg, dir, root) = historic_root(day);
    let mut current = None;
    let result = write_job_with_io(&mut synthetic_job(root.clone(), day, 1), &mut current, close_capture, |file, _| {
        file.write_all(b"{\"complete_prefix\":true}\n")?;
        file.flush()?;
        Err(io::Error::other("synthetic post-flush failure"))
    });
    assert!(result.is_err());
    assert!(current.is_none());
    root.producer.lock().resolve(next, CaptureChannel::Proxy).unwrap();
    let report = root.producer.lock().closed_file_sealer().unwrap().seal_closed_files(Utc::now()).unwrap();
    assert!(report.sealed.is_empty());
    assert!(report.skipped.iter().any(|skip| skip.reason == SealSkipReason::FailedCapture));
    drop(root);
    let restarted = Audit::new(&cfg).unwrap();
    restarted.shutdown().unwrap();
    assert_eq!(restarted.stats().seal_blocked_files, 1);
    assert!(capture_lifecycle::read_seal(&dir, format!("rust-{day}.jsonl")).is_err());
    assert_eq!(std::fs::read(dir.join(format!("rust-{day}.jsonl"))).unwrap(), b"{\"complete_prefix\":true}\n");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn startup_seals_closed_history_without_adding_requests() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let (cfg, dir, root) = historic_root(day);
    let path = dir.join(format!("rust-{day}.jsonl"));
    std::fs::write(&path, b"{\"historic\":true}\n").unwrap();
    drop(root);
    let audit = Audit::new(&cfg).unwrap();
    audit.shutdown().unwrap();
    let seal = capture_lifecycle::read_seal(&dir, format!("rust-{day}.jsonl")).unwrap();
    assert_eq!(seal.closed_length, 18);
    assert_eq!(audit.stats().written, 0);
    assert_eq!(audit.stats().sealed_files, 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn background_hashes_leave_the_live_producer_and_capture_queue_available() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let (cfg, dir, root) = historic_root(day);
    std::fs::write(dir.join(format!("rust-{day}.jsonl")), b"{\"historic\":true}\n").unwrap();
    drop(root);
    let open = Arc::new((StdMutex::new(false), Condvar::new()));
    let wait = open.clone();
    let (started, received) = mpsc::channel();
    let (written, recorded) = mpsc::channel();
    let audit = Arc::new(
        Audit::with_archive_writer(&cfg, LIMITS, move |roots, stats| {
            let seals = SealWorker::with_runner(stats.clone(), move |mut sealer| {
                started.send(()).unwrap();
                let (lock, ready) = &*wait;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = ready.wait(released).unwrap();
                }
                sealer.seal_closed_files(Utc::now())
            })?;
            Ok(ObservedCaptureWriter {
                inner: CaptureWriter { current: None, roots, seals, maintenance_cursor: 0 },
                written,
            })
        })
        .unwrap(),
    );
    let gate = Gate { started: received, open };
    gate.started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(audit.record(1, "summary", "test", json!({})).unwrap(), Admission::Queued);
    // This notification comes after real serialization, flush and fsync, while
    // the old-file hash is still blocked. It proves capture itself progresses.
    recorded.recv_timeout(Duration::from_secs(1)).unwrap();
    let root = audit.directory.read().clone().unwrap();
    assert!(root.producer.try_lock().is_some());
    assert!(CaptureRoot::open(&dir, CaptureLayout::Proxy).is_err());
    let drained = audit.clone();
    let (done, finished) = mpsc::channel();
    let shutdown = std::thread::spawn(move || {
        drained.shutdown().unwrap();
        done.send(()).unwrap();
    });
    assert!(finished.recv_timeout(Duration::from_millis(30)).is_err());
    gate.release();
    finished.recv_timeout(Duration::from_secs(5)).unwrap();
    shutdown.join().unwrap();
    assert_eq!(audit.stats().written, 1);
    drop(root);
    assert!(CaptureRoot::open(&dir, CaptureLayout::Proxy).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

struct ObservedCaptureWriter {
    inner: CaptureWriter,
    written: mpsc::Sender<()>,
}

impl ArchiveWriter for ObservedCaptureWriter {
    fn write(&mut self, job: &mut Job) -> io::Result<()> {
        self.inner.write(job)?;
        self.written.send(()).unwrap();
        Ok(())
    }
    fn maintain(&mut self) -> io::Result<()> {
        self.inner.maintain()
    }
    fn finish(&mut self) -> io::Result<()> {
        self.inner.finish()
    }
}

#[test]
fn successful_other_roots_do_not_hide_seal_errors_and_retry_clears_only_its_root() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let (_, first, first_root) = historic_root(day);
    let (_, second, second_root) = historic_root(day);
    let stats = Arc::new(Mutex::new(ArchiveStats::default()));
    let (entered, started) = mpsc::channel();
    let (allow, released) = mpsc::channel();
    let mut calls = 0;
    let mut worker = SealWorker::with_runner(stats.clone(), move |mut sealer| {
        calls += 1;
        entered.send(calls).unwrap();
        released.recv().unwrap();
        if calls == 1 {
            Err(io::Error::other("synthetic receipt publication failure"))
        } else {
            sealer.seal_closed_files(Utc::now())
        }
    })
    .unwrap();
    worker.submit(&first_root).unwrap();
    assert_eq!(started.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
    worker.submit(&second_root).unwrap();
    allow.send(()).unwrap();
    assert_eq!(started.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
    assert_eq!(stats.lock().seal_failed_roots, 1);
    worker.submit(&first_root).unwrap();
    allow.send(()).unwrap();
    assert_eq!(started.recv_timeout(Duration::from_secs(1)).unwrap(), 3);
    // The second root has now succeeded, and the first root's retry has started.
    assert_eq!(stats.lock().seal_failed_roots, 1);
    assert_eq!(stats.lock().last_seal_error_kind.as_deref(), Some("Other"));
    allow.send(()).unwrap();
    worker.finish().unwrap();
    assert_eq!(stats.lock().seal_failed_roots, 0);
    assert_eq!(stats.lock().last_seal_error_kind, None);
    assert_eq!(stats.lock().seal_errors, 1);
    assert_eq!(stats.lock().seal_pending_roots, 0);
    drop(first_root);
    drop(second_root);
    std::fs::remove_dir_all(first).unwrap();
    std::fs::remove_dir_all(second).unwrap();
}

#[test]
fn successful_old_snapshot_cannot_clear_a_newer_failure_for_the_same_root() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let (_, dir, root) = historic_root(day);
    let stats = Arc::new(Mutex::new(ArchiveStats::default()));
    let (entered, started) = mpsc::channel();
    let (allow, released) = mpsc::channel();
    let mut worker = SealWorker::with_runner(stats.clone(), move |mut sealer| {
        entered.send(()).unwrap();
        released.recv().unwrap();
        sealer.seal_closed_files(Utc::now())
    })
    .unwrap();
    worker.submit(&root).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    worker.record_error(&root.path, &io::Error::other("newer floor publication failure"));
    allow.send(()).unwrap();
    worker.finish().unwrap();
    assert_eq!(stats.lock().seal_errors, 1);
    assert_eq!(stats.lock().seal_failed_roots, 1);
    assert_eq!(stats.lock().last_seal_error_kind.as_deref(), Some("Other"));
    drop(root);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_failed_new_file_open_cannot_retain_the_old_writable_handle() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (_, dir, root) = historic_root(day);
    let mut writer = capture_writer(&root);
    writer.write(&mut synthetic_job(root.clone(), day, 1)).unwrap();
    writer.current.as_mut().unwrap().file.write_all(b"{\"buffered\":true}\n").unwrap();
    std::fs::create_dir(dir.join(format!("rust-{next}.jsonl"))).unwrap();
    assert!(writer.write(&mut synthetic_job(root.clone(), next, 2)).is_err());
    assert!(writer.current.is_none());
    assert_eq!(root.producer.lock().capture_day_floor(), next);
    // Remove only the fixture directory which deliberately obstructed the open.
    // Discovery rejects invalid source entries, so the queued seal pass may
    // have failed first. A new pass must safely retry after that obstruction.
    writer.seals.finish().unwrap();
    std::fs::remove_dir(dir.join(format!("rust-{next}.jsonl"))).unwrap();
    let seal = root.producer.lock().closed_file_sealer().unwrap().seal_closed_files(Utc::now()).unwrap();
    assert_eq!(seal.sealed.len() + seal.already_sealed, 1);
    assert!(std::fs::read(dir.join(format!("rust-{day}.jsonl"))).unwrap().ends_with(b"{\"buffered\":true}\n"));
    drop(writer);
    drop(root);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn root_switches_close_cached_handles_and_delayed_jobs_keep_their_original_root() {
    let day = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let next = day.succ_opt().unwrap();
    let (_, first, first_root) = historic_root(day);
    let (_, second, second_root) = historic_root(day);
    let roots = Arc::new(Mutex::new(HashMap::from([
        (first.clone(), first_root.clone()),
        (second.clone(), second_root.clone()),
    ])));
    let mut writer = CaptureWriter::new(roots, Arc::new(Mutex::new(ArchiveStats::default()))).unwrap();
    writer.write(&mut synthetic_job(first_root.clone(), day, 1)).unwrap();
    writer.current.as_mut().unwrap().file.write_all(b"{\"buffered_first\":true}\n").unwrap();
    writer.write(&mut synthetic_job(second_root.clone(), next, 2)).unwrap();
    assert!(Arc::ptr_eq(&writer.current.as_ref().unwrap().root, &second_root));
    let first_bytes = std::fs::read(first.join(format!("rust-{day}.jsonl"))).unwrap();
    assert!(first_bytes.ends_with(b"{\"buffered_first\":true}\n"));
    writer.maintain_at(next).unwrap();
    writer.write(&mut synthetic_job(first_root.clone(), day, 3)).unwrap();
    assert!(Arc::ptr_eq(&writer.current.as_ref().unwrap().root, &first_root));
    writer.finish().unwrap();
    assert_eq!(std::fs::read(first.join(format!("rust-{day}.jsonl"))).unwrap(), first_bytes);
    let late: Value =
        serde_json::from_str(std::fs::read_to_string(first.join(format!("rust-{next}.jsonl"))).unwrap().trim())
            .unwrap();
    assert_eq!(late["request_id"], 3);
    let second_row: Value =
        serde_json::from_str(std::fs::read_to_string(second.join(format!("rust-{next}.jsonl"))).unwrap().trim())
            .unwrap();
    assert_eq!(second_row["request_id"], 2);
    drop(writer);
    drop(first_root);
    drop(second_root);
    std::fs::remove_dir_all(first).unwrap();
    std::fs::remove_dir_all(second).unwrap();
}
