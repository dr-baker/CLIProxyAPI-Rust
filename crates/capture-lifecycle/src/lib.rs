//! A capture producer owns one root lock until every accepted write has finished.
//! Explicit enrollment precedes capture. Offline sealing uses the same lock and
//! advances a durable day floor before publishing immutable per-file receipts.
//! All producers of a root must honor this protocol; legacy writers must stop first.

mod files;
mod seal;
mod state;

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use seal::{
    CaptureSealV1, FileIdentity, SealOptions, SealReport, SealSkip, SealSkipReason, read_seal, seal_offline,
};
pub use state::Enrollment;

pub const PROTOCOL_VERSION: u32 = 1;
pub const ROOT_MARKER: &str = ".capture-root.json";
pub const STATE_DIRECTORY: &str = ".capture-state";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLayout {
    Proxy,
    Otel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureChannel {
    Proxy,
    Logs,
    Traces,
    Metrics,
}

impl CaptureLayout {
    fn channels(self) -> &'static [CaptureChannel] {
        match self {
            Self::Proxy => &[CaptureChannel::Proxy],
            Self::Otel => &[CaptureChannel::Logs, CaptureChannel::Traces, CaptureChannel::Metrics],
        }
    }
}

impl CaptureChannel {
    pub fn layout(self) -> CaptureLayout {
        match self {
            Self::Proxy => CaptureLayout::Proxy,
            _ => CaptureLayout::Otel,
        }
    }

    fn relative_path(self, day: NaiveDate) -> PathBuf {
        match self {
            Self::Proxy => PathBuf::from(format!("rust-{day}.jsonl")),
            Self::Logs => PathBuf::from(format!("{day}/logs.jsonl")),
            Self::Traces => PathBuf::from(format!("{day}/traces.jsonl")),
            Self::Metrics => PathBuf::from(format!("{day}/metrics.jsonl")),
        }
    }
}

/// Owns the producer lock. Keep this value alive through all queued writes and
/// open capture handles, including writers detached from a dropped application.
pub struct CaptureRoot {
    root: PathBuf,
    state: state::RootState,
    _lock: File,
    poisoned: bool,
}

impl CaptureRoot {
    /// Open an explicitly enrolled root. Lock contention, missing initialized
    /// metadata, malformed state, and inconsistent receipts are errors.
    pub fn open(root: impl AsRef<Path>, layout: CaptureLayout) -> io::Result<Self> {
        let root = files::existing_root(root.as_ref())?;
        let lock = files::lock_root(&root, false)?;
        files::recover_staging(&root)?;
        let state = state::load(&root, layout)?;
        // Retry directory durability after any previous visible publication
        // whose final sync failed before the operation returned success.
        files::sync_lifecycle(&root)?;
        Ok(Self { root, state, _lock: lock, poisoned: false })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn root_uuid(&self) -> Uuid {
        self.state.root_uuid
    }

    pub fn capture_day_floor(&self) -> NaiveDate {
        self.state.capture_day_floor
    }

    /// Resolve on the writer, immediately before opening a capture file. The
    /// observed event day never moves the storage day below the persisted floor.
    /// The event timestamp in the JSONL record remains unchanged.
    pub fn resolve(&mut self, observed_day: NaiveDate, channel: CaptureChannel) -> io::Result<PathBuf> {
        files::validate_day(observed_day)?;
        if self.poisoned {
            return Err(files::invalid("capture root is unavailable after a failed state transition"));
        }
        if channel.layout() != self.state.layout {
            return Err(files::invalid("capture channel does not match the enrolled layout"));
        }
        let day = observed_day.max(self.state.capture_day_floor);
        if day > self.state.capture_day_floor {
            let mut next = self.state.clone();
            next.capture_day_floor = day;
            // Check initialized metadata before replacement. A removed state
            // cannot become an implicit fresh enrollment while a writer runs.
            if let Err(error) =
                state::assert_current(&self.root, &self.state).and_then(|()| state::persist(&self.root, &next))
            {
                self.poisoned = true;
                return Err(error);
            }
            self.state = next;
        }
        Ok(self.root.join(channel.relative_path(day)))
    }

    /// Open the resolved file for append without following a final symlink.
    /// The caller must retain this root until the returned handle is closed.
    pub fn open_append(&mut self, observed_day: NaiveDate, channel: CaptureChannel) -> io::Result<(PathBuf, File)> {
        let path = self.resolve(observed_day, channel)?;
        let relative = path.strip_prefix(&self.root).map_err(|_| files::invalid("capture path is outside its root"))?;
        let parent = files::CaptureParent::open(&self.root, relative, true)?;
        let name = relative.file_name().ok_or_else(|| files::invalid("capture pathname has no filename"))?;
        let file = parent.append_leaf(name)?;
        Ok((path, file))
    }
}

/// Explicitly adopt a new or legacy directory while every old producer is
/// stopped and drained. This operation never resets existing root metadata.
pub fn enroll(root: impl AsRef<Path>, layout: CaptureLayout, initial_day: NaiveDate) -> io::Result<Enrollment> {
    state::enroll(root.as_ref(), layout, initial_day)
}

pub(crate) fn parse_relative(layout: CaptureLayout, relative: &Path) -> io::Result<(NaiveDate, CaptureChannel)> {
    let value = relative.to_str().ok_or_else(|| files::invalid("capture path must be UTF-8"))?;
    let (day, channel) = match layout {
        CaptureLayout::Proxy => {
            let day = value
                .strip_prefix("rust-")
                .and_then(|v| v.strip_suffix(".jsonl"))
                .ok_or_else(|| files::invalid("invalid proxy capture path"))?;
            (day, CaptureChannel::Proxy)
        }
        CaptureLayout::Otel => {
            let (day, name) = value.split_once('/').ok_or_else(|| files::invalid("invalid OTel capture path"))?;
            let channel = match name {
                "logs.jsonl" => CaptureChannel::Logs,
                "traces.jsonl" => CaptureChannel::Traces,
                "metrics.jsonl" => CaptureChannel::Metrics,
                _ => return Err(files::invalid("invalid OTel signal filename")),
            };
            (day, channel)
        }
    };
    let day = files::parse_day(day)?;
    if relative != channel.relative_path(day) {
        return Err(files::invalid("capture path is not canonical"));
    }
    Ok((day, channel))
}

#[cfg(test)]
mod tests;
