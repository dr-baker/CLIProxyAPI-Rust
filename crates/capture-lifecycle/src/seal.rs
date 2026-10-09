use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CaptureChannel, CaptureLayout, CaptureRoot, PROTOCOL_VERSION, STATE_DIRECTORY, files, parse_relative, state,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

/// A closure proof for the exact existing bytes of one raw capture file.
/// Archive recovery and byte equality must be proved separately before removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSealV1 {
    pub protocol_version: u32,
    pub root_uuid: Uuid,
    pub layout: CaptureLayout,
    pub channel: CaptureChannel,
    pub relative_path: String,
    pub identity: FileIdentity,
    pub closed_length: u64,
    pub sha256: String,
    pub ends_with_newline: bool,
    pub capture_day_floor: NaiveDate,
    pub sealed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SealOptions {
    pub layout: CaptureLayout,
    /// Only files whose storage day is strictly earlier than this date qualify.
    pub before: NaiveDate,
    /// At least two most recent files by both filename and mtime, per signal.
    pub keep_latest: usize,
    /// At least two days of both filename dates and modification times stay raw.
    pub hot_days: u32,
    /// Injectable for reproducible planning; the CLI supplies the current time.
    pub now: DateTime<Utc>,
    /// Optional bounded selection of canonical relative source paths. All
    /// root-wide reader exclusions still apply; only hashing is narrowed.
    pub only_relative_paths: Option<Vec<PathBuf>>,
}

impl SealOptions {
    pub fn new(layout: CaptureLayout, before: NaiveDate) -> Self {
        Self { layout, before, keep_latest: 2, hot_days: 2, now: Utc::now(), only_relative_paths: None }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealSkipReason {
    BeforeBoundary,
    ActiveDay,
    RecentFilename,
    RecentMtime,
    Hot,
    PartialTail,
}

#[derive(Debug, Clone, Serialize)]
pub struct SealSkip {
    pub relative_path: String,
    pub reason: SealSkipReason,
}

#[derive(Debug, Default, Serialize)]
pub struct SealReport {
    pub sealed: Vec<CaptureSealV1>,
    pub already_sealed: usize,
    pub skipped: Vec<SealSkip>,
}

struct Candidate {
    relative: PathBuf,
    day: NaiveDate,
    channel: CaptureChannel,
    fingerprint: files::Fingerprint,
    parent_identity: FileIdentity,
}

#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_DISCOVERY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static SOURCE_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Acquire the producer lock, preserve the union of all reader exclusions,
/// persist closure before receipts, and hash sources with a 64 KiB buffer.
/// This operation never rewrites or removes a capture file.
pub fn seal_offline(root: impl AsRef<Path>, options: SealOptions) -> io::Result<SealReport> {
    require_identity_support()?;
    files::validate_day(options.before)?;
    files::validate_day(options.now.date_naive())?;
    if options.keep_latest < 2 || options.keep_latest > files::MAX_ENTRIES || options.hot_days < 2 {
        return Err(files::invalid("seal must preserve at least two latest files and two hot days"));
    }
    let mut producer = CaptureRoot::open(root, options.layout)?;
    let only = if let Some(paths) = &options.only_relative_paths {
        if paths.is_empty() || paths.len() > files::MAX_ENTRIES {
            return Err(files::invalid("seal path selection must be nonempty and bounded"));
        }
        for path in paths {
            parse_relative(options.layout, path)?;
        }
        Some(paths.iter().cloned().collect::<HashSet<_>>())
    } else {
        None
    };
    let candidates = discover(&producer.root, options.layout)?;
    #[cfg(test)]
    if let Some(callback) = AFTER_DISCOVERY.with(|hook| hook.borrow_mut().take()) {
        callback();
    }
    if let Some(only) = &only {
        let available: HashSet<_> = candidates.iter().map(|candidate| &candidate.relative).collect();
        if only.iter().any(|path| !available.contains(path)) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "selected capture source is missing"));
        }
    }
    let by_name = newest(&candidates, options.layout, options.keep_latest, false);
    let by_mtime = newest(&candidates, options.layout, options.keep_latest, true);
    let active = producer.state.capture_day_floor.max(options.now.date_naive());
    let cutoff = options
        .now
        .checked_sub_signed(Duration::days(i64::from(options.hot_days)))
        .ok_or_else(|| files::invalid("hot-window time is out of range"))?;
    let cutoff_time: SystemTime = cutoff.into();
    let mut selected = Vec::new();
    let mut report = SealReport::default();
    for candidate in candidates {
        if only.as_ref().is_some_and(|only| !only.contains(&candidate.relative)) {
            continue;
        }
        let reason = if candidate.day >= options.before {
            Some(SealSkipReason::BeforeBoundary)
        } else if candidate.day >= active {
            Some(SealSkipReason::ActiveDay)
        } else if by_name.contains(&candidate.relative) {
            Some(SealSkipReason::RecentFilename)
        } else if by_mtime.contains(&candidate.relative) {
            Some(SealSkipReason::RecentMtime)
        } else if candidate.day >= cutoff.date_naive() || candidate.fingerprint.modified >= cutoff_time {
            Some(SealSkipReason::Hot)
        } else {
            None
        };
        if let Some(reason) = reason {
            report.skipped.push(SealSkip { relative_path: relative_string(&candidate.relative)?, reason });
        } else {
            selected.push(candidate);
        }
    }
    if let Some(latest) = selected.iter().map(|candidate| candidate.day).max() {
        let after = latest.succ_opt().ok_or_else(|| files::invalid("sealed day has no successor"))?;
        files::validate_day(after)?;
        if after > producer.state.capture_day_floor {
            state::assert_current(&producer.root, &producer.state)?;
            let mut next = producer.state.clone();
            next.capture_day_floor = after;
            state::persist(&producer.root, &next)?;
            producer.state = next;
        }
    }
    // If the process stops here, the floor still forbids future appends. The
    // source remains raw and has no removal proof until a later run publishes it.
    for candidate in selected {
        let snapshot = hash_stable_source(&producer.root, &candidate)?;
        let existing = read_optional_receipt(&producer.root, &candidate.relative)?;
        if let Some(existing) = existing {
            validate_receipt(&existing, &producer.state, &candidate.relative)?;
            if existing.identity != snapshot.identity
                || existing.closed_length != snapshot.length
                || existing.sha256 != snapshot.sha256
                || existing.ends_with_newline != snapshot.newline
            {
                return Err(files::invalid("sealed source no longer matches its immutable receipt"));
            }
            report.already_sealed += 1;
            continue;
        }
        if !snapshot.newline {
            report.skipped.push(SealSkip {
                relative_path: relative_string(&candidate.relative)?,
                reason: SealSkipReason::PartialTail,
            });
            continue;
        }
        let receipt = CaptureSealV1 {
            protocol_version: PROTOCOL_VERSION,
            root_uuid: producer.state.root_uuid,
            layout: options.layout,
            channel: candidate.channel,
            relative_path: relative_string(&candidate.relative)?,
            identity: snapshot.identity,
            closed_length: snapshot.length,
            sha256: snapshot.sha256,
            ends_with_newline: snapshot.newline,
            capture_day_floor: producer.state.capture_day_floor,
            sealed_at: options.now,
        };
        validate_receipt(&receipt, &producer.state, &candidate.relative)?;
        files::write_json(&receipt_path(&producer.root, &candidate.relative)?, &receipt, false)?;
        report.sealed.push(receipt);
    }
    files::sync_lifecycle(&producer.root)?;
    Ok(report)
}

/// Read an immutable receipt and validate its binding to the current initialized
/// root and monotonic day floor. Does not inspect source bytes or archive recovery.
/// A removed raw source still has a readable seal; consumers must check equality
/// against their own checkpoint before any optional source retirement.
pub fn read_seal(root: impl AsRef<Path>, relative_path: impl AsRef<Path>) -> io::Result<CaptureSealV1> {
    require_identity_support()?;
    let root = files::existing_root(root.as_ref())?;
    let layout = state::read_layout(&root)?;
    let state = state::load_pair(&root, layout)?;
    files::require_directory(&root.join(STATE_DIRECTORY).join("seals"))?;
    let relative = relative_path.as_ref();
    parse_relative(layout, relative)?;
    let receipt = read_optional_receipt(&root, relative)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "capture seal is missing"))?;
    validate_receipt(&receipt, &state, relative)?;
    Ok(receipt)
}

pub(crate) fn validate_receipts(root: &Path, state: &state::RootState) -> io::Result<()> {
    let directory = root.join(STATE_DIRECTORY).join("seals");
    files::require_directory(&directory)?;
    for (index, entry) in fs::read_dir(&directory)?.enumerate() {
        if index >= files::MAX_ENTRIES {
            return Err(files::invalid("capture seal count exceeds its limit"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| files::invalid("invalid seal metadata filename"))?;
        if name.strip_prefix(".capture-tmp-").is_some_and(|suffix| Uuid::parse_str(suffix).is_ok()) {
            continue;
        }
        let receipt: CaptureSealV1 = files::read_json(&entry.path())?;
        let relative = Path::new(&receipt.relative_path);
        validate_receipt(&receipt, state, relative)?;
        if entry.path() != receipt_path(root, relative)? {
            return Err(files::invalid("capture seal filename does not match its source path"));
        }
    }
    Ok(())
}

fn validate_receipt(receipt: &CaptureSealV1, state: &state::RootState, relative: &Path) -> io::Result<()> {
    let (day, channel) = parse_relative(state.layout, relative)?;
    if receipt.protocol_version != PROTOCOL_VERSION
        || receipt.root_uuid != state.root_uuid
        || receipt.layout != state.layout
        || receipt.channel != channel
        || Path::new(&receipt.relative_path) != relative
        || !receipt.ends_with_newline
        || receipt.capture_day_floor <= day
        || receipt.capture_day_floor > state.capture_day_floor
        || receipt.sha256.len() != 64
        || !receipt.sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(files::invalid("capture seal is inconsistent with its root, path, digest, or day floor"));
    }
    files::validate_day(receipt.capture_day_floor)
}

fn receipt_path(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    let relative = relative_string(relative)?;
    let name = format!("{}.json", hex::encode(Sha256::digest(relative.as_bytes())));
    Ok(root.join(STATE_DIRECTORY).join("seals").join(name))
}

fn relative_string(relative: &Path) -> io::Result<String> {
    relative.to_str().map(str::to_owned).ok_or_else(|| files::invalid("capture path must be UTF-8"))
}

fn read_optional_receipt(root: &Path, relative: &Path) -> io::Result<Option<CaptureSealV1>> {
    files::optional_json(&receipt_path(root, relative)?)
}

fn discover(root: &Path, layout: CaptureLayout) -> io::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        if index >= files::MAX_ENTRIES {
            return Err(files::invalid("capture root entry count exceeds its limit"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        match layout {
            CaptureLayout::Proxy => {
                let relative = PathBuf::from(name);
                let Ok((day, channel)) = parse_relative(layout, &relative) else { continue };
                add_candidate(root, relative, day, channel, &mut candidates)?;
            }
            CaptureLayout::Otel => {
                let Ok(day) = files::parse_day(name) else { continue };
                files::require_directory(&entry.path())?;
                for &channel in layout.channels() {
                    let relative = channel.relative_path(day);
                    match fs::symlink_metadata(root.join(&relative)) {
                        Ok(_) => add_candidate(root, relative, day, channel, &mut candidates)?,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
    candidates.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(candidates)
}

fn add_candidate(
    root: &Path,
    relative: PathBuf,
    day: NaiveDate,
    channel: CaptureChannel,
    candidates: &mut Vec<Candidate>,
) -> io::Result<()> {
    if candidates.len() >= files::MAX_ENTRIES {
        return Err(files::invalid("capture source count exceeds its limit"));
    }
    let parent = files::CaptureParent::open(root, &relative, false)?;
    let name = relative.file_name().ok_or_else(|| files::invalid("capture path has no filename"))?;
    let file = parent.read_leaf(name, false)?;
    let fingerprint = files::fingerprint(&file.metadata()?)?;
    parent.revalidate()?;
    candidates.push(Candidate { relative, day, channel, fingerprint, parent_identity: parent.identity()? });
    Ok(())
}

fn newest(candidates: &[Candidate], layout: CaptureLayout, keep: usize, mtime: bool) -> HashSet<PathBuf> {
    let mut protected = HashSet::new();
    for &channel in layout.channels() {
        let mut files: Vec<_> = candidates.iter().filter(|candidate| candidate.channel == channel).collect();
        files.sort_by(|a, b| {
            if mtime {
                a.fingerprint.modified.cmp(&b.fingerprint.modified).then_with(|| a.relative.cmp(&b.relative))
            } else {
                a.relative.cmp(&b.relative)
            }
        });
        protected.extend(files.into_iter().rev().take(keep).map(|file| file.relative.clone()));
    }
    protected
}

struct Snapshot {
    identity: FileIdentity,
    length: u64,
    sha256: String,
    newline: bool,
}

fn require_identity_support() -> io::Result<()> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable capture sealing requires Unix file identity and directory fsync",
        ))
    }
}

fn hash_stable_source(root: &Path, candidate: &Candidate) -> io::Result<Snapshot> {
    let parent = files::CaptureParent::open(root, &candidate.relative, false)?;
    if parent.identity()? != candidate.parent_identity {
        return Err(files::invalid("capture parent changed since seal discovery"));
    }
    let name = candidate.relative.file_name().ok_or_else(|| files::invalid("capture path has no filename"))?;
    let mut file = parent.read_leaf(name, true)?;
    let before = files::fingerprint(&file.metadata()?)?;
    if before != candidate.fingerprint {
        return Err(files::invalid("capture source changed since seal discovery"));
    }
    file.sync_all()?;
    parent.sync()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 << 10];
    let mut length = 0u64;
    let mut last = None;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        #[cfg(test)]
        SOURCE_BYTES_READ.with(|bytes| bytes.set(bytes.get() + read as u64));
        length = length.checked_add(read as u64).ok_or_else(|| files::invalid("capture length overflow"))?;
        hash.update(&buffer[..read]);
        last = Some(buffer[read - 1]);
    }
    let after = files::fingerprint(&file.metadata()?)?;
    let current = parent.read_leaf(name, true)?;
    let pathname = files::fingerprint(&current.metadata()?)?;
    if length != before.length || before != after || after != pathname {
        return Err(files::invalid("capture source changed during sealing"));
    }
    Ok(Snapshot {
        identity: before.identity,
        length,
        sha256: hex::encode(hash.finalize()),
        newline: last.is_none_or(|byte| byte == b'\n'),
    })
}
