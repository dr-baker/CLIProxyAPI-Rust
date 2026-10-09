use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{Datelike, NaiveDate};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::STATE_DIRECTORY;

mod capture;
#[cfg(all(test, unix))]
pub(crate) use capture::BEFORE_APPEND_LEAF;
pub(crate) use capture::{CaptureParent, Fingerprint, fingerprint};

pub(crate) const MAX_METADATA_BYTES: u64 = 64 << 10;
pub(crate) const MAX_ENTRIES: usize = 100_000;
const MAX_DIRECTORY_DEPTH: usize = 128;

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_AFTER_PUBLICATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static FAIL_DIRECTORY_SYNC: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    pub(crate) static DIRECTORY_SYNCS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn validate_day(day: NaiveDate) -> io::Result<()> {
    if !(1..=9999).contains(&day.year()) {
        return Err(invalid("capture day must have a four-digit positive year"));
    }
    Ok(())
}

pub(crate) fn parse_day(value: &str) -> io::Result<NaiveDate> {
    let day = NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| invalid("invalid capture day"))?;
    validate_day(day)?;
    if value.len() != 10 || day.to_string() != value {
        return Err(invalid("capture day is not canonical YYYY-MM-DD"));
    }
    Ok(day)
}

pub(crate) fn existing_root(root: &Path) -> io::Result<PathBuf> {
    require_directory(root)?;
    fs::canonicalize(root)
}

pub(crate) fn private_directory(path: &Path) -> io::Result<()> {
    let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    if absolute.ancestors().take(MAX_DIRECTORY_DEPTH + 1).count() > MAX_DIRECTORY_DEPTH {
        return Err(invalid("capture directory depth exceeds its limit"));
    }
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.try_exists()? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor.parent().ok_or_else(|| invalid("capture directory has no existing parent"))?;
    }
    if !fs::metadata(ancestor)?.is_dir() {
        return Err(invalid("capture directory parent is not a directory"));
    }
    for directory in missing.iter().rev() {
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        match builder.create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        require_directory(directory)?;
    }
    require_directory(&absolute)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&absolute, fs::Permissions::from_mode(0o700))?;
    }
    // A previous failed creation can leave every component visible. Cold-path
    // recovery cannot infer which ancestor names remain unsynced, so sync the
    // bounded chain from child to parent even when no component is missing.
    sync_ancestor_chain(&absolute)?;
    Ok(())
}

pub(crate) fn require_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() || !metadata.is_dir() {
        return Err(invalid("capture directory must be a real directory"));
    }
    Ok(())
}

pub(crate) fn read_file(path: &Path) -> io::Result<File> {
    require_regular_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    validate_regular_file(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn append_file(path: &Path) -> io::Result<File> {
    match require_regular_path(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    private_file_options(&mut options);
    let file = options.open(path)?;
    validate_regular_file(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn private_file_options(options: &mut OpenOptions) {
    no_follow(options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

pub(crate) fn lock_root(root: &Path, create: bool) -> io::Result<File> {
    let state_dir = root.join(STATE_DIRECTORY);
    if create {
        private_directory(&state_dir)?;
    } else {
        require_directory(&state_dir)?;
    }
    let path = state_dir.join("producer.lock");
    match require_regular_path(&path) {
        Ok(()) => {}
        Err(e) if create && e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    private_file_options(&mut options);
    let file = options.open(path)?;
    validate_regular_file(&file)?;
    file.try_lock()?;
    // The permanent lock pathname is never removed or replaced by this library.
    if create {
        file.sync_all()?;
        sync_directory(&state_dir)?;
        sync_directory(root)?;
    }
    Ok(file)
}

fn require_regular_path(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(invalid("capture metadata and source path must be a regular file"));
    }
    Ok(())
}

fn validate_regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("capture metadata and source must be regular files"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("capture metadata and source must not have extra hard links"));
        }
    }
    Ok(())
}

/// Recover only this crate's staged metadata, while holding the root lock. A
/// crash after no-overwrite publication can leave a second link to the complete
/// receipt/state marker; removing the staging name restores its single identity.
pub(crate) fn recover_staging(root: &Path) -> io::Result<()> {
    for directory in [root.to_owned(), root.join(STATE_DIRECTORY), root.join(STATE_DIRECTORY).join("seals")] {
        if !directory.try_exists()? {
            continue;
        }
        require_directory(&directory)?;
        let mut removed = false;
        for (index, entry) in fs::read_dir(&directory)?.enumerate() {
            if index >= MAX_ENTRIES {
                return Err(invalid("capture lifecycle entry count exceeds its limit"));
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(".capture-tmp-") else { continue };
            if Uuid::parse_str(suffix).is_err() {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_symlink() || !metadata.is_file() {
                return Err(invalid("capture lifecycle staging entry must be a regular file"));
            }
            fs::remove_file(entry.path())?;
            removed = true;
        }
        if removed {
            sync_directory(&directory)?;
        }
    }
    Ok(())
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let file = read_file(path)?;
    let mut bytes = Vec::with_capacity(4096);
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(invalid("capture lifecycle metadata exceeds its size limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("capture lifecycle metadata is malformed"))
}

pub(crate) fn optional_json<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match read_json(path) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T, replace: bool) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(invalid("capture lifecycle metadata exceeds its size limit"));
    }
    let parent = path.parent().ok_or_else(|| invalid("metadata pathname has no parent"))?;
    require_directory(parent)?;
    let temporary = parent.join(format!(".capture-tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_file_options(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        if replace {
            fs::rename(&temporary, path)?;
        } else {
            // Publish without ever overwriting an existing enrollment or seal.
            fs::hard_link(&temporary, path)?;
            fs::remove_file(&temporary)?;
        }
        #[cfg(test)]
        if FAIL_AFTER_PUBLICATION.with(|failure| failure.replace(false)) {
            return Err(io::Error::other("injected directory sync failure after metadata publication"));
        }
        sync_directory(parent)
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    observe_directory_sync(path)?;
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Rust's portable File API does not provide directory fsync on Windows.
        // Capture remains available; durable seal proof is Unix-only.
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn observe_directory_sync(path: &Path) -> io::Result<()> {
    DIRECTORY_SYNCS.with(|trace| trace.borrow_mut().push(path.to_owned()));
    let fail = FAIL_DIRECTORY_SYNC.with(|failure| {
        let mut failure = failure.borrow_mut();
        if failure.as_deref() == Some(path) {
            failure.take();
            true
        } else {
            false
        }
    });
    if fail {
        return Err(io::Error::other("injected directory sync failure"));
    }
    Ok(())
}

pub(crate) fn sync_lifecycle(root: &Path) -> io::Result<()> {
    for directory in [root.join(STATE_DIRECTORY).join("seals"), root.join(STATE_DIRECTORY), root.to_owned()] {
        require_directory(&directory)?;
        sync_directory(&directory)?;
    }
    sync_ancestor_chain(root)
}

fn sync_ancestor_chain(path: &Path) -> io::Result<()> {
    let ancestors: Vec<_> = path.ancestors().take(MAX_DIRECTORY_DEPTH + 1).collect();
    if ancestors.len() > MAX_DIRECTORY_DEPTH {
        return Err(invalid("capture directory depth exceeds its limit"));
    }
    for ancestor in ancestors {
        sync_directory(ancestor)?;
    }
    Ok(())
}
