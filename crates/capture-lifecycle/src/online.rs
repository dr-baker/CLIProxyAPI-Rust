//! Producer-owned closure tickets retain the lock while hashing on another thread.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CaptureLayout, CaptureRoot, CaptureSealV1, PROTOCOL_VERSION, STATE_DIRECTORY, SealReport, SealSkip, SealSkipReason,
    files, parse_relative, seal, state,
};

const BLOCK_DIRECTORY: &str = "seal-blocks";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealBlockV1 {
    protocol_version: u32,
    root_uuid: Uuid,
    layout: CaptureLayout,
    relative_path: String,
    blocked_at: DateTime<Utc>,
}

/// A closed-floor snapshot that owns a duplicate of the producer's existing
/// lock handle. Move it to a maintenance thread; dropping the original producer
/// cannot release the root lock while this ticket still exists. Only Unix is
/// supported. Never explicitly unlock either duplicated handle.
pub struct ClosedFileSealer {
    root: PathBuf,
    state: state::RootState,
    root_handle: File,
    state_handle: File,
    seals_handle: File,
    blocks_handle: File,
    lock: File,
}

impl ClosedFileSealer {
    pub fn capture_day_floor(&self) -> NaiveDate {
        self.state.capture_day_floor
    }

    /// Seal files strictly below the prepared floor, without advancing that
    /// floor or taking another producer lock. Call after all older writable
    /// handles have been synced and dropped. Reader hot/latest exclusions remain
    /// the archive consumer's responsibility; a seal alone permits no deletion.
    pub fn seal_closed_files(&mut self, now: DateTime<Utc>) -> io::Result<SealReport> {
        self.seal_closed_files_bounded(now, files::MAX_ENTRIES)
    }

    /// Limit full-file hashes in this pass. Existing immutable seals require
    /// only metadata checks; partial tails are checked with a one-byte read.
    /// Each selected hash still takes time proportional to that file's size.
    pub fn seal_closed_files_bounded(&mut self, now: DateTime<Utc>, max_files: usize) -> io::Result<SealReport> {
        seal::require_identity_support()?;
        files::validate_day(now.date_naive())?;
        if !(1..=files::MAX_ENTRIES).contains(&max_files) {
            return Err(files::invalid("online seal hash budget must be positive and bounded"));
        }
        self.current_state()?;
        let paths = discover_paths(&self.root, self.state.layout)?;
        #[cfg(test)]
        if let Some(callback) = AFTER_DISCOVERY.with(|hook| hook.borrow_mut().take()) {
            callback();
        }
        let mut report = SealReport::default();
        let mut hashed = 0;
        for relative in paths {
            let (day, channel) = parse_relative(self.state.layout, &relative)?;
            if day >= self.state.capture_day_floor {
                report.skipped.push(SealSkip {
                    relative_path: seal::relative_string(&relative)?,
                    reason: SealSkipReason::ActiveDay,
                });
                continue;
            }
            let current = self.current_state()?;
            if is_blocked(&self.root, &current, &relative)? {
                report.skipped.push(SealSkip {
                    relative_path: seal::relative_string(&relative)?,
                    reason: SealSkipReason::FailedCapture,
                });
                continue;
            }
            if let Some(receipt) = seal::read_optional_receipt(&self.root, &relative)? {
                seal::validate_receipt(&receipt, &current, &relative)?;
                self.check_existing_source(&relative, &receipt)?;
                report.already_sealed += 1;
                continue;
            }
            if hashed == max_files {
                report.skipped.push(SealSkip {
                    relative_path: seal::relative_string(&relative)?,
                    reason: SealSkipReason::Deferred,
                });
                continue;
            }
            let mut candidates = Vec::with_capacity(1);
            seal::add_candidate(&self.root, relative.clone(), day, channel, &mut candidates)?;
            let candidate = candidates.pop().expect("one candidate was added");
            if !complete_tail(&self.root, &candidate)? {
                report.skipped.push(SealSkip {
                    relative_path: seal::relative_string(&relative)?,
                    reason: SealSkipReason::PartialTail,
                });
                continue;
            }
            let snapshot = seal::hash_stable_source(&self.root, &candidate)?;
            hashed += 1;
            if !snapshot.newline {
                return Err(files::invalid("capture tail changed during online sealing"));
            }
            let current = self.current_state()?;
            if is_blocked(&self.root, &current, &relative)? {
                report.skipped.push(SealSkip {
                    relative_path: seal::relative_string(&relative)?,
                    reason: SealSkipReason::FailedCapture,
                });
                continue;
            }
            let receipt = CaptureSealV1 {
                protocol_version: PROTOCOL_VERSION,
                root_uuid: self.state.root_uuid,
                layout: self.state.layout,
                channel,
                relative_path: seal::relative_string(&relative)?,
                identity: snapshot.identity,
                closed_length: snapshot.length,
                sha256: snapshot.sha256,
                ends_with_newline: true,
                capture_day_floor: self.state.capture_day_floor,
                sealed_at: now,
            };
            seal::validate_receipt(&receipt, &current, &relative)?;
            let path = seal::receipt_path(&self.root, &relative)?;
            match files::write_json(&path, &receipt, false) {
                Ok(()) => report.sealed.push(receipt),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    // Two retained tickets can race. They must prove the same
                    // bytes; either ticket's valid closed-floor snapshot works.
                    let existing: CaptureSealV1 = files::read_json(&path)?;
                    seal::validate_receipt(&existing, &self.current_state()?, &relative)?;
                    if existing.identity != receipt.identity
                        || existing.closed_length != receipt.closed_length
                        || existing.sha256 != receipt.sha256
                    {
                        return Err(files::invalid("concurrent capture seal disagrees with the source bytes"));
                    }
                    report.already_sealed += 1;
                }
                Err(error) => return Err(error),
            }
            self.current_state()?;
        }
        // A previous publication may have become visible before its directory
        // sync failed. Retrying resyncs it without reading the payload again.
        files::sync_directory(&self.root.join(STATE_DIRECTORY).join("seals"))?;
        self.current_state()?;
        Ok(report)
    }

    fn current_state(&self) -> io::Result<state::RootState> {
        for (path, handle) in [
            (self.root.clone(), &self.root_handle),
            (self.root.join(STATE_DIRECTORY), &self.state_handle),
            (self.root.join(STATE_DIRECTORY).join("seals"), &self.seals_handle),
            (self.root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY), &self.blocks_handle),
        ] {
            files::require_directory(&path)?;
            if files::identity(&fs::symlink_metadata(path)?)? != files::identity(&handle.metadata()?)? {
                return Err(files::invalid("capture lifecycle namespace changed during online sealing"));
            }
        }
        let lock_path = self.root.join(STATE_DIRECTORY).join("producer.lock");
        if files::fingerprint(&files::read_file(&lock_path)?.metadata()?)?
            != files::fingerprint(&self.lock.metadata()?)?
        {
            return Err(files::invalid("permanent producer lock changed during online sealing"));
        }
        let current = state::load_pair(&self.root, self.state.layout)?;
        if current.root_uuid != self.state.root_uuid
            || current.capture_day_floor < self.state.capture_day_floor
            || current.retirement != self.state.retirement
        {
            return Err(files::invalid("capture state changed incompatibly with its closed-floor snapshot"));
        }
        Ok(current)
    }

    fn check_existing_source(&self, relative: &Path, receipt: &CaptureSealV1) -> io::Result<()> {
        let result = (|| {
            let parent = files::CaptureParent::open(&self.root, relative, false)?;
            let name = relative.file_name().ok_or_else(|| files::invalid("capture path has no filename"))?;
            let file = parent.read_leaf(name, true)?;
            let metadata = file.metadata()?;
            if files::identity(&metadata)? != receipt.identity || metadata.len() != receipt.closed_length {
                return Err(files::invalid("sealed source metadata no longer matches its immutable receipt"));
            }
            parent.revalidate()
        })();
        match result {
            // A completed archive removal or its quarantine can race discovery.
            // The immutable closure proof remains valid after raw removal.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

pub(crate) fn prepare(producer: &mut CaptureRoot) -> io::Result<ClosedFileSealer> {
    seal::require_identity_support()?;
    if producer.poisoned || producer.state.retirement.is_some() {
        return Err(files::invalid("capture root is unavailable for online sealing"));
    }
    state::assert_current(&producer.root, &producer.state)?;
    let blocks = producer.root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY);
    if !blocks.try_exists()? {
        files::private_directory(&blocks)?;
    }
    let ticket = ClosedFileSealer {
        root: producer.root.clone(),
        state: producer.state.clone(),
        root_handle: directory(&producer.root)?,
        state_handle: directory(&producer.root.join(STATE_DIRECTORY))?,
        seals_handle: directory(&producer.root.join(STATE_DIRECTORY).join("seals"))?,
        blocks_handle: directory(&blocks)?,
        lock: producer._lock.try_clone()?,
    };
    ticket.current_state()?;
    Ok(ticket)
}

pub(crate) fn block(producer: &CaptureRoot, relative: &Path) -> io::Result<()> {
    seal::require_identity_support()?;
    let (day, _) = parse_relative(producer.state.layout, relative)?;
    if producer.state.retirement.is_some() || day != producer.state.capture_day_floor {
        return Err(files::invalid("failed capture exclusion must precede advancement of its storage day"));
    }
    state::assert_current(&producer.root, &producer.state)?;
    if seal::read_optional_receipt(&producer.root, relative)?.is_some() {
        return Err(files::invalid("an immutable capture seal cannot gain a later failure exclusion"));
    }
    let blocks = producer.root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY);
    files::private_directory(&blocks)?;
    if is_blocked(&producer.root, &producer.state, relative)? {
        files::sync_directory(&blocks)?;
        return Ok(());
    }
    let value = SealBlockV1 {
        protocol_version: PROTOCOL_VERSION,
        root_uuid: producer.state.root_uuid,
        layout: producer.state.layout,
        relative_path: seal::relative_string(relative)?,
        blocked_at: Utc::now(),
    };
    files::write_json(&block_path(&producer.root, relative)?, &value, false)?;
    state::assert_current(&producer.root, &producer.state)
}

pub(crate) fn is_blocked(root: &Path, state: &state::RootState, relative: &Path) -> io::Result<bool> {
    let directory = root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Ok(_) => files::require_directory(&directory)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let Some(block): Option<SealBlockV1> = files::optional_json(&block_path(root, relative)?)? else {
        return Ok(false);
    };
    validate_block(&block, state, relative)?;
    Ok(true)
}

fn validate_block(block: &SealBlockV1, state: &state::RootState, relative: &Path) -> io::Result<()> {
    if block.protocol_version != PROTOCOL_VERSION
        || block.root_uuid != state.root_uuid
        || block.layout != state.layout
        || Path::new(&block.relative_path) != relative
    {
        return Err(files::invalid("failed capture exclusion is inconsistent with its root or path"));
    }
    parse_relative(state.layout, relative)?;
    files::validate_day(block.blocked_at.date_naive())?;
    Ok(())
}

pub(crate) fn validate_blocks(root: &Path, state: &state::RootState) -> io::Result<()> {
    let directory = root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Ok(_) => files::require_directory(&directory)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    for (index, entry) in fs::read_dir(&directory)?.enumerate() {
        if index >= files::MAX_ENTRIES {
            return Err(files::invalid("failed capture exclusion count exceeds its limit"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| files::invalid("invalid failed capture metadata filename"))?;
        if name.strip_prefix(".capture-tmp-").is_some_and(|suffix| Uuid::parse_str(suffix).is_ok()) {
            continue;
        }
        let block: SealBlockV1 = files::read_json(&entry.path())?;
        let relative = Path::new(&block.relative_path);
        validate_block(&block, state, relative)?;
        if entry.path() != block_path(root, relative)? {
            return Err(files::invalid("failed capture metadata filename does not match its source path"));
        }
    }
    Ok(())
}

fn block_path(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    let digest = hex::encode(Sha256::digest(seal::relative_string(relative)?.as_bytes()));
    Ok(root.join(STATE_DIRECTORY).join(BLOCK_DIRECTORY).join(format!("{digest}.json")))
}

fn directory(path: &Path) -> io::Result<File> {
    files::require_directory(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn discover_paths(root: &Path, layout: CaptureLayout) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
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
                if parse_relative(layout, &relative).is_ok() {
                    paths.push(relative);
                }
            }
            CaptureLayout::Otel => {
                let Ok(day) = files::parse_day(name) else { continue };
                files::require_directory(&entry.path())?;
                for &channel in layout.channels() {
                    let relative = channel.relative_path(day);
                    match fs::symlink_metadata(root.join(&relative)) {
                        Ok(_) => paths.push(relative),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        if paths.len() > files::MAX_ENTRIES {
            return Err(files::invalid("capture source count exceeds its limit"));
        }
    }
    paths.sort();
    Ok(paths)
}

fn complete_tail(root: &Path, candidate: &seal::Candidate) -> io::Result<bool> {
    let parent = files::CaptureParent::open(root, &candidate.relative, false)?;
    if parent.identity()? != candidate.parent_identity {
        return Err(files::invalid("capture parent changed since online seal discovery"));
    }
    let name = candidate.relative.file_name().ok_or_else(|| files::invalid("capture path has no filename"))?;
    let mut file = parent.read_leaf(name, true)?;
    if files::fingerprint(&file.metadata()?)? != candidate.fingerprint {
        return Err(files::invalid("capture source changed before tail inspection"));
    }
    let complete = if candidate.fingerprint.length == 0 {
        true
    } else {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)?;
        #[cfg(test)]
        seal::SOURCE_BYTES_READ.with(|bytes| bytes.set(bytes.get() + 1));
        last[0] == b'\n'
    };
    let current = parent.read_leaf(name, true)?;
    if files::fingerprint(&file.metadata()?)? != candidate.fingerprint
        || files::fingerprint(&current.metadata()?)? != candidate.fingerprint
    {
        return Err(files::invalid("capture source changed during tail inspection"));
    }
    Ok(complete)
}

#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_DISCOVERY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
