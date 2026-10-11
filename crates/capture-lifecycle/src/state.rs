use std::io;
use std::path::Path;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CaptureLayout, CaptureRetirementV1, PROTOCOL_VERSION, RETIREMENT_FILE, ROOT_MARKER, STATE_DIRECTORY, files, retire,
    seal,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootMarker {
    pub protocol_version: u32,
    pub root_uuid: Uuid,
    pub layout: CaptureLayout,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<CaptureRetirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootState {
    pub protocol_version: u32,
    pub root_uuid: Uuid,
    pub layout: CaptureLayout,
    pub capture_day_floor: NaiveDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<CaptureRetirementV1>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Enrollment {
    pub protocol_version: u32,
    pub root_uuid: Uuid,
    pub layout: CaptureLayout,
    pub capture_day_floor: NaiveDate,
    pub created: bool,
}

pub(crate) fn marker(state: &RootState) -> RootMarker {
    RootMarker {
        protocol_version: state.protocol_version,
        root_uuid: state.root_uuid,
        layout: state.layout,
        retirement: state.retirement.clone(),
    }
}

pub(crate) fn validate(state: &RootState, layout: CaptureLayout) -> io::Result<()> {
    if state.protocol_version != PROTOCOL_VERSION || state.layout != layout || state.root_uuid.is_nil() {
        return Err(files::invalid("capture lifecycle protocol, layout, or root UUID is invalid"));
    }
    files::validate_day(state.capture_day_floor)
}

pub(crate) fn load(root: &Path, layout: CaptureLayout) -> io::Result<RootState> {
    let state = load_pair(root, layout)?;
    seal::validate_receipts(root, &state)?;
    Ok(state)
}

pub(crate) fn load_pair(root: &Path, layout: CaptureLayout) -> io::Result<RootState> {
    files::require_directory(&root.join(STATE_DIRECTORY))?;
    let state: RootState = files::read_json(&root.join(STATE_DIRECTORY).join("state.json"))?;
    validate(&state, layout)?;
    let recorded: RootMarker = files::read_json(&root.join(ROOT_MARKER))?;
    if recorded != marker(&state) {
        return Err(files::invalid("capture root marker and state disagree"));
    }
    retire::validate_binding(root, &state)?;
    Ok(state)
}

pub(crate) fn read_layout(root: &Path) -> io::Result<CaptureLayout> {
    let recorded: RootMarker = files::read_json(&root.join(ROOT_MARKER))?;
    if recorded.protocol_version != PROTOCOL_VERSION || recorded.root_uuid.is_nil() {
        return Err(files::invalid("capture root marker is invalid"));
    }
    Ok(recorded.layout)
}

pub(crate) fn assert_current(root: &Path, expected: &RootState) -> io::Result<()> {
    if load_pair(root, expected.layout)? != *expected {
        return Err(files::invalid("capture state changed while its producer lock was held"));
    }
    Ok(())
}

pub(crate) fn persist(root: &Path, state: &RootState) -> io::Result<()> {
    validate(state, state.layout)?;
    files::write_json(&root.join(STATE_DIRECTORY).join("state.json"), state, true)
}

pub(crate) fn enroll(root: &Path, layout: CaptureLayout, initial_day: NaiveDate) -> io::Result<Enrollment> {
    files::validate_day(initial_day)?;
    files::private_directory(root)?;
    let root = files::existing_root(root)?;
    let state_path = root.join(STATE_DIRECTORY).join("state.json");
    let marker_path = root.join(ROOT_MARKER);
    let initialized = std::fs::symlink_metadata(&state_path).is_ok()
        || std::fs::symlink_metadata(&marker_path).is_ok()
        || root.join(STATE_DIRECTORY).join("seals").try_exists()?
        || root.join(STATE_DIRECTORY).join(RETIREMENT_FILE).try_exists()?;
    // Existing initialized roots never recreate a missing permanent lock file.
    let _lock = files::lock_root(&root, !initialized)?;
    files::recover_staging(&root)?;
    let recorded: Option<RootMarker> = files::optional_json(&marker_path)?;
    let existing: Option<RootState> = files::optional_json(&state_path)?;
    if existing.as_ref().is_some_and(|state| state.retirement.is_some())
        || recorded.as_ref().is_some_and(|marker| marker.retirement.is_some())
        || files::optional_json::<CaptureRetirementV1>(&root.join(STATE_DIRECTORY).join(RETIREMENT_FILE))?.is_some()
    {
        return Err(files::invalid("capture root is permanently retired; enrollment cannot reset it"));
    }
    let (mut state, created) = match (recorded, existing) {
        (None, None) => {
            let seals = root.join(STATE_DIRECTORY).join("seals");
            if seals.try_exists()? && std::fs::read_dir(&seals)?.next().is_some() {
                return Err(files::invalid("capture state is missing beside existing seal metadata"));
            }
            files::private_directory(&seals)?;
            files::sync_directory(&root.join(STATE_DIRECTORY))?;
            let state = RootState {
                protocol_version: PROTOCOL_VERSION,
                root_uuid: Uuid::new_v4(),
                layout,
                capture_day_floor: initial_day,
                retirement: None,
            };
            // State first makes a crash resumable. A marker without state is an
            // invalid initialized root and can never become a fresh enrollment.
            files::write_json(&state_path, &state, false)?;
            files::write_json(&marker_path, &marker(&state), false)?;
            (state, true)
        }
        (None, Some(state)) => {
            validate(&state, layout)?;
            seal::validate_receipts(&root, &state)?;
            // Resume an interrupted explicit enrollment using its original UUID.
            files::write_json(&marker_path, &marker(&state), false)?;
            (state, false)
        }
        (Some(_), None) => return Err(files::invalid("initialized capture root state is missing")),
        (Some(recorded), Some(state)) => {
            validate(&state, layout)?;
            if recorded != marker(&state) {
                return Err(files::invalid("capture root marker and state disagree"));
            }
            seal::validate_receipts(&root, &state)?;
            (state, false)
        }
    };
    if initial_day > state.capture_day_floor {
        state.capture_day_floor = initial_day;
        persist(&root, &state)?;
    }
    files::sync_lifecycle(&root)?;
    Ok(Enrollment {
        protocol_version: PROTOCOL_VERSION,
        root_uuid: state.root_uuid,
        layout,
        capture_day_floor: state.capture_day_floor,
        created,
    })
}
