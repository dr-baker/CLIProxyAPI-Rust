//! Permanent root closure is separate from per-file byte and archive proofs.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CaptureLayout, FileIdentity, PROTOCOL_VERSION, RETIREMENT_FILE, ROOT_MARKER, STATE_DIRECTORY, files, seal, state,
};

#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_MARKER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRetirementV1 {
    pub protocol_version: u32,
    pub root_uuid: Uuid,
    pub layout: CaptureLayout,
    pub identity: FileIdentity,
    pub retirement_uuid: Uuid,
    pub capture_day_floor: NaiveDate,
    pub retired_at: DateTime<Utc>,
}

fn validate_intent(root: &Path, state: &state::RootState, receipt: &CaptureRetirementV1) -> io::Result<()> {
    files::require_directory(root)?;
    if receipt.protocol_version != PROTOCOL_VERSION
        || receipt.root_uuid != state.root_uuid
        || receipt.layout != state.layout
        || receipt.retirement_uuid.is_nil()
        || receipt.capture_day_floor != state.capture_day_floor
        || receipt.identity != files::identity(&fs::symlink_metadata(root)?)?
    {
        return Err(files::invalid(
            "capture retirement does not match the root UUID, directory identity, layout, or floor",
        ));
    }
    files::validate_day(receipt.retired_at.date_naive())?;
    files::validate_day(receipt.capture_day_floor)
}

pub(crate) fn validate_binding(root: &Path, state: &state::RootState) -> io::Result<()> {
    let recorded: Option<CaptureRetirementV1> =
        files::optional_json(&root.join(STATE_DIRECTORY).join(RETIREMENT_FILE))?;
    if recorded != state.retirement {
        return Err(files::invalid("capture retirement receipt and initialized state disagree"));
    }
    if let Some(retirement) = &state.retirement {
        validate_intent(root, state, retirement)?;
    }
    Ok(())
}

struct RetirementGuard {
    root: File,
    state: File,
    lock: File,
}

impl RetirementGuard {
    fn open(root: &Path) -> io::Result<Self> {
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
        let root_handle = directory(root)?;
        let state_handle = directory(&root.join(STATE_DIRECTORY))?;
        let lock = files::lock_root(root, false)?;
        let guard = Self { root: root_handle, state: state_handle, lock };
        guard.revalidate(root)?;
        Ok(guard)
    }

    fn identity(&self) -> io::Result<FileIdentity> {
        files::identity(&self.root.metadata()?)
    }

    fn revalidate(&self, root: &Path) -> io::Result<()> {
        files::require_directory(root)?;
        let state = root.join(STATE_DIRECTORY);
        files::require_directory(&state)?;
        if files::identity(&fs::symlink_metadata(root)?)? != self.identity()?
            || files::identity(&fs::symlink_metadata(&state)?)? != files::identity(&self.state.metadata()?)?
            || files::fingerprint(&files::read_file(&state.join("producer.lock"))?.metadata()?)?
                != files::fingerprint(&self.lock.metadata()?)?
        {
            return Err(files::invalid(
                "capture root, state directory, or permanent producer lock changed during retirement",
            ));
        }
        Ok(())
    }
}

/// Read the immutable retirement proof without taking a producer lock. Missing,
/// inconsistent, or malformed initialized metadata is an error, not an active root.
pub fn read_retirement(root: impl AsRef<Path>) -> io::Result<Option<CaptureRetirementV1>> {
    seal::require_identity_support()?;
    let root = files::existing_root(root.as_ref())?;
    let state = state::load_pair(&root, state::read_layout(&root)?)?;
    Ok(state.retirement)
}

/// Permanently stop a compliant root while its producer is stopped and drained.
/// This never rewrites capture bytes, removes files, or resets root enrollment.
/// There is no reopening operation. Use a new enrolled directory for future capture.
pub fn retire_offline(root: impl AsRef<Path>, layout: CaptureLayout) -> io::Result<CaptureRetirementV1> {
    seal::require_identity_support()?;
    let root = files::existing_root(root.as_ref())?;
    let guard = RetirementGuard::open(&root)?;
    files::recover_staging(&root)?;
    guard.revalidate(&root)?;
    #[cfg(test)]
    if let Some(callback) = AFTER_LOCK.with(|hook| hook.borrow_mut().take()) {
        callback();
    }
    guard.revalidate(&root)?;
    let state_path = root.join(STATE_DIRECTORY).join("state.json");
    let marker_path = root.join(ROOT_MARKER);
    let receipt_path = root.join(STATE_DIRECTORY).join(RETIREMENT_FILE);
    let mut state: state::RootState = files::read_json(&state_path)?;
    state::validate(&state, layout)?;
    let recorded: state::RootMarker = files::read_json(&marker_path)?;
    let receipt: Option<CaptureRetirementV1> = files::optional_json(&receipt_path)?;
    if let Some(retirement) = &state.retirement {
        validate_intent(&root, &state, retirement)?;
        let mut prior = state.clone();
        prior.retirement = None;
        // Only the state-first interrupted transition can have an active marker.
        if recorded != state::marker(&state) && (recorded != state::marker(&prior) || receipt.is_some()) {
            return Err(files::invalid("capture retirement cannot resume inconsistent root metadata"));
        }
        if receipt.as_ref().is_some_and(|receipt| Some(receipt) != state.retirement.as_ref()) {
            return Err(files::invalid("capture retirement receipt differs from the original intent"));
        }
    } else {
        if recorded != state::marker(&state) || receipt.is_some() {
            return Err(files::invalid("capture retirement cannot reset inconsistent root metadata"));
        }
        seal::validate_receipts(&root, &state)?;
        state.capture_day_floor = seal::closed_root_floor(&root, layout, state.capture_day_floor)?;
        state.retirement = Some(CaptureRetirementV1 {
            protocol_version: PROTOCOL_VERSION,
            root_uuid: state.root_uuid,
            layout,
            identity: guard.identity()?,
            retirement_uuid: Uuid::new_v4(),
            capture_day_floor: state.capture_day_floor,
            retired_at: Utc::now(),
        });
        // State first: old producers deny unknown fields, and new producers
        // reject the incomplete binding. Both refuse capture after publication.
        guard.revalidate(&root)?;
        state::persist(&root, &state)?;
        guard.revalidate(&root)?;
    }
    seal::validate_receipts(&root, &state)?;
    let retirement = state.retirement.clone().expect("retirement intent was created");
    validate_intent(&root, &state, &retirement)?;
    guard.revalidate(&root)?;
    if recorded != state::marker(&state) {
        files::write_json(&marker_path, &state::marker(&state), true)?;
    }
    #[cfg(test)]
    if let Some(callback) = AFTER_MARKER.with(|hook| hook.borrow_mut().take()) {
        callback();
    }
    if receipt.is_none() {
        guard.revalidate(&root)?;
        files::write_json(&receipt_path, &retirement, false)?;
    }
    guard.revalidate(&root)?;
    state::load(&root, layout)?;
    files::sync_lifecycle(&root)?;
    validate_intent(&root, &state, &retirement)?;
    guard.revalidate(&root)?;
    Ok(retirement)
}
