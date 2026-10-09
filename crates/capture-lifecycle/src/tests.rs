use super::*;
use std::fs::{self, File, FileTimes};
use std::io::Write;
use std::process::Command;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("capture-lifecycle-test-{}", Uuid::new_v4())))
    }

    fn enrolled(layout: CaptureLayout, floor: &str) -> Self {
        let temp = Self::new();
        enroll(&temp.0, layout, day(floor)).unwrap();
        temp
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)))
            .unwrap();
    }

    fn state_path(&self) -> PathBuf {
        self.0.join(STATE_DIRECTORY).join("state.json")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn day(value: &str) -> NaiveDate {
    files::parse_day(value).unwrap()
}

fn options(layout: CaptureLayout) -> SealOptions {
    SealOptions {
        layout,
        before: day("2026-10-10"),
        keep_latest: 2,
        hot_days: 2,
        now: DateTime::parse_from_rfc3339("2026-10-10T12:00:00Z").unwrap().with_timezone(&Utc),
        only_relative_paths: None,
    }
}

#[cfg(unix)]
fn fill_proxy(temp: &Temp) {
    for i in 1..=9 {
        temp.write(&format!("rust-2026-10-{i:02}.jsonl"), b"{}\n");
    }
}

#[test]
fn enrollment_is_explicit_stable_and_preserves_legacy_bytes() {
    let temp = Temp::new();
    temp.write("rust-2026-10-01.jsonl", b"{\"synthetic\":true}\n");
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    let first = enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-02")).unwrap();
    let second = enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-01")).unwrap();
    assert!(first.created);
    assert!(!second.created);
    assert_eq!(first.root_uuid, second.root_uuid);
    assert_eq!(second.capture_day_floor, day("2026-10-02"));
    assert_eq!(fs::read(temp.0.join("rust-2026-10-01.jsonl")).unwrap(), b"{\"synthetic\":true}\n");
    assert!(enroll(&temp.0, CaptureLayout::Otel, day("2026-10-02")).is_err());
}

#[test]
fn enrollment_resumes_state_first_crash_without_changing_uuid() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let state: state::RootState = files::read_json(&temp.state_path()).unwrap();
    fs::remove_file(temp.0.join(ROOT_MARKER)).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    let recovered = enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-03")).unwrap();
    assert_eq!(state.root_uuid, recovered.root_uuid);
    assert_eq!(recovered.capture_day_floor, day("2026-10-03"));
}

#[test]
fn missing_or_malformed_initialized_state_cannot_reset_a_root() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    fs::remove_file(temp.state_path()).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-01")).is_err());
    fs::write(temp.state_path(), b"null\n").unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-01")).is_err());
}

#[test]
fn malformed_marker_uuid_and_unknown_state_fields_fail_closed() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let mut marker: Value = files::read_json(&temp.0.join(ROOT_MARKER)).unwrap();
    marker["root_uuid"] = json!(Uuid::new_v4());
    fs::write(temp.0.join(ROOT_MARKER), serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    let state: state::RootState = files::read_json(&temp.state_path()).unwrap();
    marker["root_uuid"] = json!(state.root_uuid);
    fs::write(temp.0.join(ROOT_MARKER), serde_json::to_vec(&marker).unwrap()).unwrap();
    let mut value: Value = files::read_json(&temp.state_path()).unwrap();
    value["unknown_contract"] = json!(true);
    fs::write(temp.state_path(), serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
}

#[test]
fn day_floor_survives_restart_clock_rollback_and_late_jobs() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    let (_, mut file) = root.open_append(day("2026-10-05"), CaptureChannel::Proxy).unwrap();
    file.write_all(b"{\"old_event_time\":true}\n").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(root.resolve(day("2026-10-01"), CaptureChannel::Proxy).unwrap().ends_with("rust-2026-10-05.jsonl"));
    drop(root);
    let mut restarted = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert_eq!(restarted.capture_day_floor(), day("2026-10-05"));
    let (path, file) = restarted.open_append(day("2026-10-01"), CaptureChannel::Proxy).unwrap();
    assert!(path.ends_with("rust-2026-10-05.jsonl"));
    drop(file);
    assert!(!temp.0.join("rust-2026-10-01.jsonl").exists());
}

#[test]
fn failed_state_transition_poisoning_prevents_cached_floor_bypass() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    fs::remove_file(temp.state_path()).unwrap();
    assert!(root.open_append(day("2026-10-03"), CaptureChannel::Proxy).is_err());
    assert!(root.open_append(day("2026-10-01"), CaptureChannel::Proxy).is_err());
    assert!(!temp.0.join("rust-2026-10-03.jsonl").exists());
    assert!(!temp.state_path().exists());
}

#[test]
fn failed_directory_sync_after_state_rename_refuses_older_writes_until_restart() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    files::FAIL_AFTER_PUBLICATION.with(|failure| failure.set(true));
    assert!(root.open_append(day("2026-10-06"), CaptureChannel::Proxy).is_err());
    let published: state::RootState = files::read_json(&temp.state_path()).unwrap();
    assert_eq!(published.capture_day_floor, day("2026-10-06"));
    assert!(root.open_append(day("2026-10-01"), CaptureChannel::Proxy).is_err());
    assert!(!temp.0.join("rust-2026-10-02.jsonl").exists());
    assert!(!temp.0.join("rust-2026-10-06.jsonl").exists());
    drop(root);
    let mut restarted = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert!(restarted.resolve(day("2026-10-01"), CaptureChannel::Proxy).unwrap().ends_with("rust-2026-10-06.jsonl"));
}

#[test]
fn missing_permanent_lock_cannot_be_recreated_on_an_initialized_root() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    fs::remove_file(temp.0.join(STATE_DIRECTORY).join("producer.lock")).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-03")).is_err());
    assert!(!temp.0.join(STATE_DIRECTORY).join("producer.lock").exists());
}

#[cfg(unix)]
#[test]
fn stale_metadata_publication_link_recovers_without_resetting_root() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let original: state::RootState = files::read_json(&temp.state_path()).unwrap();
    let staged = temp.0.join(STATE_DIRECTORY).join(format!(".capture-tmp-{}", Uuid::new_v4()));
    fs::hard_link(temp.state_path(), &staged).unwrap();
    assert!(files::read_json::<state::RootState>(&temp.state_path()).is_err());
    let root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert_eq!(root.root_uuid(), original.root_uuid);
    assert!(!staged.exists());
    assert_eq!(root.capture_day_floor(), original.capture_day_floor);
}

#[test]
fn append_handle_can_read_partial_tail_and_normalizes_private_permissions() {
    use std::io::{Read, Seek, SeekFrom};
    let temp = Temp::enrolled(CaptureLayout::Otel, "2026-10-02");
    temp.write("2026-10-02/logs.jsonl", b"{}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.0.join("2026-10-02/logs.jsonl"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(temp.0.join("2026-10-02"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Otel).unwrap();
    let (path, mut file) = root.open_append(day("2026-10-02"), CaptureChannel::Logs).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut last = [0u8; 1];
    file.read_exact(&mut last).unwrap();
    assert_eq!(last, *b"}");
    file.write_all(b"\n{}\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{}\n{}\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn linked_files_and_fifo_sources_are_rejected_without_blocking() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    temp.write("rust-2026-10-02.jsonl", b"{}\n");
    let other = Temp::new();
    fs::create_dir_all(&other.0).unwrap();
    fs::hard_link(temp.0.join("rust-2026-10-02.jsonl"), other.0.join("alias.jsonl")).unwrap();
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert!(root.open_append(day("2026-10-02"), CaptureChannel::Proxy).is_err());
    drop(root);
    fs::remove_file(temp.0.join("rust-2026-10-02.jsonl")).unwrap();
    let status = Command::new("mkfifo").arg(temp.0.join("rust-2026-10-02.jsonl")).status().unwrap();
    assert!(status.success());
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert!(root.open_append(day("2026-10-02"), CaptureChannel::Proxy).is_err());
    assert!(files::read_file(&temp.0.join("rust-2026-10-02.jsonl")).is_err());
}

#[test]
fn otel_floor_is_root_wide_and_preserves_signal_names() {
    let temp = Temp::enrolled(CaptureLayout::Otel, "2026-10-02");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Otel).unwrap();
    let (_, file) = root.open_append(day("2026-10-06"), CaptureChannel::Logs).unwrap();
    drop(file);
    let (path, file) = root.open_append(day("2026-10-01"), CaptureChannel::Traces).unwrap();
    assert!(path.ends_with("2026-10-06/traces.jsonl"));
    drop(file);
    assert!(root.resolve(day("2026-10-02"), CaptureChannel::Proxy).is_err());
}

#[test]
fn root_lock_blocks_second_writer_enrollment_and_sealing() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert_eq!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-02")).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    #[cfg(unix)]
    assert_eq!(seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    drop(root);
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_ok());
}

#[test]
fn lock_is_enforced_across_processes_and_released_after_process_exit() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    let run = |blocked: bool| {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::lock_process_probe", "--ignored"])
            .env("CAPTURE_TEST_ROOT", &temp.0)
            .env("CAPTURE_TEST_BLOCKED", if blocked { "1" } else { "0" })
            .output()
            .unwrap()
    };
    let denied = run(true);
    assert!(denied.status.success(), "{}", String::from_utf8_lossy(&denied.stderr));
    drop(root);
    let allowed = run(false);
    assert!(allowed.status.success(), "{}", String::from_utf8_lossy(&allowed.stderr));
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_ok());
}

#[test]
#[ignore = "subprocess helper invoked by lock_is_enforced_across_processes"]
fn lock_process_probe() {
    let root = std::env::var_os("CAPTURE_TEST_ROOT").unwrap();
    let result = CaptureRoot::open(PathBuf::from(root), CaptureLayout::Proxy);
    if std::env::var("CAPTURE_TEST_BLOCKED").unwrap() == "1" {
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::WouldBlock);
    } else {
        assert!(result.is_ok());
        // Exit without a Rust Drop to prove OS process teardown releases the lock.
        std::process::exit(0);
    }
}

#[cfg(unix)]
#[test]
fn seal_preserves_union_of_filename_mtime_hot_and_active_exclusions() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    // File 1 is hot, file 2 is the other latest mtime. Files 8 and 9 are
    // latest by filename. File 7 is neither pair and remains old enough.
    File::options()
        .write(true)
        .open(temp.0.join("rust-2026-10-01.jsonl"))
        .unwrap()
        .set_modified(options(CaptureLayout::Proxy).now.into())
        .unwrap();
    File::options()
        .write(true)
        .open(temp.0.join("rust-2026-10-02.jsonl"))
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(2))
        .unwrap();
    temp.write("rust-2026-10-10.jsonl", b"{}\n");
    let mut opts = options(CaptureLayout::Proxy);
    opts.before = day("2026-10-12");
    let report = seal_offline(&temp.0, opts).unwrap();
    let sealed: Vec<_> = report.sealed.iter().map(|seal| seal.relative_path.as_str()).collect();
    assert_eq!(sealed, (3..=7).map(|i| format!("rust-2026-10-{i:02}.jsonl")).collect::<Vec<_>>());
    assert!(
        report
            .skipped
            .iter()
            .any(|skip| skip.relative_path == "rust-2026-10-10.jsonl" && skip.reason == SealSkipReason::ActiveDay)
    );
    assert!(
        report
            .skipped
            .iter()
            .any(|skip| skip.relative_path == "rust-2026-10-09.jsonl" && skip.reason == SealSkipReason::RecentFilename)
    );
    assert!(
        report
            .skipped
            .iter()
            .any(|skip| skip.relative_path == "rust-2026-10-02.jsonl" && skip.reason == SealSkipReason::RecentMtime)
    );
}

#[cfg(unix)]
#[test]
fn seal_receipt_is_byte_exact_idempotent_and_survives_raw_removal() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    let raw = b"{\"order\":2,\"spacing\":  true}\n\n";
    temp.write("rust-2026-10-01.jsonl", raw);
    let first = seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap();
    assert_eq!(first.sealed.len(), 7);
    let seal = read_seal(&temp.0, "rust-2026-10-01.jsonl").unwrap();
    assert_eq!(seal.closed_length, raw.len() as u64);
    assert_eq!(seal.sha256, hex::encode(Sha256::digest(raw)));
    assert_eq!(fs::read(temp.0.join(&seal.relative_path)).unwrap(), raw);
    let second = seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap();
    assert!(second.sealed.is_empty());
    assert_eq!(second.already_sealed, 7);
    assert_eq!(read_seal(&temp.0, &seal.relative_path).unwrap(), seal);
    fs::remove_file(temp.0.join(&seal.relative_path)).unwrap();
    assert_eq!(read_seal(&temp.0, &seal.relative_path).unwrap(), seal);
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    let (new_path, file) = root.open_append(day("2026-10-01"), CaptureChannel::Proxy).unwrap();
    assert!(new_path.ends_with("rust-2026-10-10.jsonl"));
    drop(file);
    assert!(!temp.0.join(&seal.relative_path).exists());
}

#[cfg(unix)]
#[test]
fn selected_seal_hashes_only_requested_paths_and_keeps_root_wide_exclusions() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    // A different eligible source has an extra hard link. Whole-root hashing
    // would fail; selected-file sealing must not open or hash it.
    let other = Temp::new();
    fs::create_dir_all(&other.0).unwrap();
    fs::hard_link(temp.0.join("rust-2026-10-02.jsonl"), other.0.join("alias.jsonl")).unwrap();
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["rust-2026-10-01.jsonl".into()]);
    let result = seal_offline(&temp.0, opts).unwrap();
    assert_eq!(result.sealed.len(), 1);
    assert!(result.skipped.is_empty());
    assert!(read_seal(&temp.0, "rust-2026-10-02.jsonl").is_err());
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["rust-2026-10-09.jsonl".into()]);
    let result = seal_offline(&temp.0, opts).unwrap();
    assert!(result.sealed.is_empty());
    assert_eq!(result.skipped[0].reason, SealSkipReason::RecentFilename);
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["rust-2026-10-11.jsonl".into()]);
    assert_eq!(seal_offline(&temp.0, opts).unwrap_err().kind(), io::ErrorKind::NotFound);
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["../rust-2026-10-01.jsonl".into()]);
    assert_eq!(seal_offline(&temp.0, opts).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[cfg(unix)]
#[test]
fn seal_digest_covers_many_buffer_windows_without_rewriting_source() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    let path = temp.0.join("rust-2026-10-01.jsonl");
    let mut file = File::create(&path).unwrap();
    let chunk = b"{\"synthetic\":true}\n".repeat(4096);
    let mut expected = Sha256::new();
    for _ in 0..64 {
        file.write_all(&chunk).unwrap();
        expected.update(&chunk);
    }
    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)).unwrap();
    drop(file);
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["rust-2026-10-01.jsonl".into()]);
    let report = seal_offline(&temp.0, opts).unwrap();
    assert_eq!(report.sealed.len(), 1);
    assert_eq!(report.sealed[0].closed_length, (chunk.len() * 64) as u64);
    assert_eq!(report.sealed[0].sha256, hex::encode(expected.finalize()));
    assert_eq!(fs::metadata(path).unwrap().len(), report.sealed[0].closed_length);
}

#[test]
fn oversized_lifecycle_metadata_is_rejected_before_deserialization() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    fs::write(temp.state_path(), vec![b' '; files::MAX_METADATA_BYTES as usize + 1]).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-03")).is_err());
}

#[cfg(unix)]
#[test]
fn seal_rejects_date_directory_symlink_swap_after_discovery_without_reading_outside_bytes() {
    use std::os::unix::fs::symlink;
    let temp = Temp::enrolled(CaptureLayout::Otel, "2026-10-10");
    for i in 1..=9 {
        temp.write(&format!("2026-10-{i:02}/logs.jsonl"), b"{}\n");
    }
    let outside = Temp::new();
    outside.write("logs.jsonl", b"outside\n");
    let original_parent = temp.0.join("2026-10-02");
    let moved = temp.0.join("original-date-directory");
    let external = outside.0.clone();
    seal::SOURCE_BYTES_READ.with(|counter| counter.set(0));
    seal::AFTER_DISCOVERY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            fs::rename(&original_parent, moved).unwrap();
            symlink(external, original_parent).unwrap();
        }))
    });
    let mut opts = options(CaptureLayout::Otel);
    opts.only_relative_paths = Some(vec!["2026-10-02/logs.jsonl".into()]);
    assert!(seal_offline(&temp.0, opts).is_err());
    assert_eq!(seal::SOURCE_BYTES_READ.with(|counter| counter.get()), 0);
    assert!(read_seal(&temp.0, "2026-10-02/logs.jsonl").is_err());
    assert_eq!(fs::read(outside.0.join("logs.jsonl")).unwrap(), b"outside\n");
}

#[cfg(unix)]
#[test]
fn seal_rejects_replaced_source_and_hot_touch_after_discovery_before_payload_reads() {
    for replace in [false, true] {
        let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
        fill_proxy(&temp);
        let source = temp.0.join("rust-2026-10-01.jsonl");
        let target = source.clone();
        let now: SystemTime = options(CaptureLayout::Proxy).now.into();
        seal::SOURCE_BYTES_READ.with(|counter| counter.set(0));
        seal::AFTER_DISCOVERY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                if replace {
                    fs::rename(&target, target.with_extension("original")).unwrap();
                    fs::write(&target, b"{}\n").unwrap();
                    File::options()
                        .write(true)
                        .open(target)
                        .unwrap()
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                        .unwrap();
                } else {
                    File::options().write(true).open(target).unwrap().set_modified(now).unwrap();
                }
            }))
        });
        let mut opts = options(CaptureLayout::Proxy);
        opts.only_relative_paths = Some(vec!["rust-2026-10-01.jsonl".into()]);
        assert!(seal_offline(&temp.0, opts).is_err());
        assert_eq!(seal::SOURCE_BYTES_READ.with(|counter| counter.get()), 0);
        assert!(read_seal(&temp.0, "rust-2026-10-01.jsonl").is_err());
        assert_eq!(fs::read(source).unwrap(), b"{}\n");
    }
}

#[cfg(unix)]
#[test]
fn append_rejects_substituted_parent_after_directory_open_before_leaf_creation() {
    use std::os::unix::fs::symlink;
    let temp = Temp::enrolled(CaptureLayout::Otel, "2026-10-02");
    temp.write("2026-10-02/logs.jsonl", b"{}\n");
    let outside = Temp::new();
    outside.write("logs.jsonl", b"outside\n");
    let original = temp.0.join("2026-10-02");
    let moved = temp.0.join("original-date-directory");
    let external = outside.0.clone();
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Otel).unwrap();
    files::BEFORE_APPEND_LEAF.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            fs::rename(&original, moved).unwrap();
            symlink(external, original).unwrap();
        }))
    });
    assert!(root.open_append(day("2026-10-02"), CaptureChannel::Traces).is_err());
    assert!(!outside.0.join("traces.jsonl").exists());
    assert_eq!(fs::read(outside.0.join("logs.jsonl")).unwrap(), b"outside\n");
}

#[cfg(unix)]
#[test]
fn capture_leaf_retry_resyncs_parent_after_create_succeeded_but_sync_failed() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-02");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    let parent = root.path().to_owned();
    files::FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(parent.clone()));
    assert!(root.open_append(day("2026-10-02"), CaptureChannel::Proxy).is_err());
    assert!(temp.0.join("rust-2026-10-02.jsonl").exists());
    files::DIRECTORY_SYNCS.with(|trace| trace.borrow_mut().clear());
    let (_, mut file) = root.open_append(day("2026-10-02"), CaptureChannel::Proxy).unwrap();
    file.write_all(b"{}\n").unwrap();
    file.sync_all().unwrap();
    assert!(files::DIRECTORY_SYNCS.with(|trace| trace.borrow().contains(&parent)));
}

#[test]
fn enrollment_retry_resyncs_visible_published_state_before_success() {
    let temp = Temp::new();
    files::FAIL_AFTER_PUBLICATION.with(|failure| failure.set(true));
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-02")).is_err());
    let state: state::RootState = files::read_json(&temp.state_path()).unwrap();
    let state_dir = fs::canonicalize(temp.0.join(STATE_DIRECTORY)).unwrap();
    files::DIRECTORY_SYNCS.with(|trace| trace.borrow_mut().clear());
    let recovered = enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-02")).unwrap();
    assert_eq!(recovered.root_uuid, state.root_uuid);
    assert!(!recovered.created);
    assert!(files::DIRECTORY_SYNCS.with(|trace| trace.borrow().contains(&state_dir)));
}

#[cfg(unix)]
#[test]
fn seal_retry_resyncs_visible_existing_receipt_after_publication_sync_failure() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    let seals = fs::canonicalize(temp.0.join(STATE_DIRECTORY).join("seals")).unwrap();
    let target = seals.clone();
    seal::AFTER_DISCOVERY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            files::FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(target));
        }))
    });
    let mut opts = options(CaptureLayout::Proxy);
    opts.only_relative_paths = Some(vec!["rust-2026-10-01.jsonl".into()]);
    assert!(seal_offline(&temp.0, opts.clone()).is_err());
    assert!(read_seal(&temp.0, "rust-2026-10-01.jsonl").is_ok());
    files::DIRECTORY_SYNCS.with(|trace| trace.borrow_mut().clear());
    let recovered = seal_offline(&temp.0, opts).unwrap();
    assert_eq!(recovered.already_sealed, 1);
    assert!(recovered.sealed.is_empty());
    assert!(files::DIRECTORY_SYNCS.with(|trace| trace.borrow().contains(&seals)));
}

#[test]
fn nested_root_retry_syncs_all_visible_ancestor_names_after_early_sync_failure() {
    let temp = Temp::new();
    fs::create_dir_all(&temp.0).unwrap();
    let root = temp.0.join("a/b/capture");
    files::FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(root.clone()));
    assert!(enroll(&root, CaptureLayout::Proxy, day("2026-10-02")).is_err());
    assert!(root.is_dir());
    assert!(!root.join(ROOT_MARKER).exists());
    files::DIRECTORY_SYNCS.with(|trace| trace.borrow_mut().clear());
    enroll(&root, CaptureLayout::Proxy, day("2026-10-02")).unwrap();
    for ancestor in [&temp.0, &temp.0.join("a"), &temp.0.join("a/b")] {
        assert!(files::DIRECTORY_SYNCS.with(|trace| trace.borrow().contains(ancestor)));
    }
}

#[cfg(unix)]
#[test]
fn partial_tails_are_preserved_and_have_no_seal() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    temp.write("rust-2026-10-01.jsonl", b"{\"partial\":");
    temp.write("rust-2026-10-02.jsonl", b"");
    let report = seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap();
    assert!(
        report
            .skipped
            .iter()
            .any(|skip| skip.relative_path == "rust-2026-10-01.jsonl" && skip.reason == SealSkipReason::PartialTail)
    );
    assert_eq!(fs::read(temp.0.join("rust-2026-10-01.jsonl")).unwrap(), b"{\"partial\":");
    assert_eq!(read_seal(&temp.0, "rust-2026-10-01.jsonl").unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(read_seal(&temp.0, "rust-2026-10-02.jsonl").unwrap().closed_length, 0);
}

#[cfg(unix)]
#[test]
fn root_floor_is_durable_before_receipt_and_retry_completes_crashed_seal() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-01");
    fill_proxy(&temp);
    let mut state: state::RootState = files::read_json(&temp.state_path()).unwrap();
    state.capture_day_floor = day("2026-10-08");
    state::persist(&temp.0, &state).unwrap();
    // Simulate termination after the floor publication and before any receipt.
    assert!(read_seal(&temp.0, "rust-2026-10-01.jsonl").is_err());
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert!(root.resolve(day("2026-10-01"), CaptureChannel::Proxy).unwrap().ends_with("rust-2026-10-08.jsonl"));
    drop(root);
    assert_eq!(seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap().sealed.len(), 7);
}

#[cfg(unix)]
#[test]
fn receipts_reject_source_change_root_mismatch_state_rollback_and_traversal() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    fill_proxy(&temp);
    seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap();
    assert!(read_seal(&temp.0, "../rust-2026-10-01.jsonl").is_err());
    assert!(read_seal(&temp.0, "/rust-2026-10-01.jsonl").is_err());
    temp.write("rust-2026-10-01.jsonl", b"{\"changed\":true}\n");
    assert!(seal_offline(&temp.0, options(CaptureLayout::Proxy)).is_err());
    let mut state: state::RootState = files::read_json(&temp.state_path()).unwrap();
    state.capture_day_floor = day("2026-10-01");
    state::persist(&temp.0, &state).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
    assert!(read_seal(&temp.0, "rust-2026-10-01.jsonl").is_err());
    assert!(enroll(&temp.0, CaptureLayout::Proxy, day("2026-10-10")).is_err());
}

#[cfg(unix)]
#[test]
fn otel_seal_keeps_last_pairs_per_signal_in_sparse_directories() {
    let temp = Temp::enrolled(CaptureLayout::Otel, "2026-10-10");
    for i in 1..=9 {
        temp.write(&format!("2026-10-{i:02}/logs.jsonl"), b"{}\n");
    }
    for i in [1, 2, 3] {
        temp.write(&format!("2026-10-{i:02}/traces.jsonl"), b"{}\n");
    }
    temp.write("2026-10-01/metrics.jsonl", b"{}\n");
    let report = seal_offline(&temp.0, options(CaptureLayout::Otel)).unwrap();
    assert_eq!(report.sealed.len(), 8);
    assert!(report.sealed.iter().any(|seal| seal.relative_path == "2026-10-01/traces.jsonl"));
    assert!(read_seal(&temp.0, "2026-10-02/traces.jsonl").is_err());
    assert!(read_seal(&temp.0, "2026-10-01/metrics.jsonl").is_err());
    assert_eq!(read_seal(&temp.0, "2026-10-01/traces.jsonl").unwrap().channel, CaptureChannel::Traces);
}

#[cfg(unix)]
#[test]
fn symlink_sources_controls_and_root_are_rejected() {
    use std::os::unix::fs::symlink;
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    let outside = Temp::new();
    outside.write("target.jsonl", b"{}\n");
    symlink(outside.0.join("target.jsonl"), temp.0.join("rust-2026-10-01.jsonl")).unwrap();
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    assert!(root.open_append(day("2026-10-01"), CaptureChannel::Proxy).is_ok());
    drop(root);
    assert!(seal_offline(&temp.0, options(CaptureLayout::Proxy)).is_err());
    let link = Temp::new();
    symlink(&temp.0, &link.0).unwrap();
    assert!(CaptureRoot::open(&link.0, CaptureLayout::Proxy).is_err());
    fs::remove_file(temp.state_path()).unwrap();
    symlink(outside.0.join("target.jsonl"), temp.state_path()).unwrap();
    assert!(CaptureRoot::open(&temp.0, CaptureLayout::Proxy).is_err());
}

#[test]
fn invalid_days_and_small_exclusion_windows_are_rejected() {
    for value in ["2026-1-01", "2026-10-32", "0000-01-01", "../2026-10-01"] {
        assert!(files::parse_day(value).is_err());
    }
    #[cfg(unix)]
    {
        let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
        let mut opts = options(CaptureLayout::Proxy);
        opts.keep_latest = 1;
        assert!(seal_offline(&temp.0, opts).is_err());
        let mut opts = options(CaptureLayout::Proxy);
        opts.hot_days = 1;
        assert!(seal_offline(&temp.0, opts).is_err());
    }
}

#[cfg(not(unix))]
#[test]
fn portable_capture_remains_available_and_sealing_is_explicitly_unsupported() {
    let temp = Temp::enrolled(CaptureLayout::Proxy, "2026-10-10");
    let mut root = CaptureRoot::open(&temp.0, CaptureLayout::Proxy).unwrap();
    let (_, mut file) = root.open_append(day("2026-10-10"), CaptureChannel::Proxy).unwrap();
    file.write_all(b"{}\n").unwrap();
    drop(file);
    assert_eq!(seal_offline(&temp.0, options(CaptureLayout::Proxy)).unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert_eq!(read_seal(&temp.0, "rust-2026-10-10.jsonl").unwrap_err().kind(), io::ErrorKind::Unsupported);
}
