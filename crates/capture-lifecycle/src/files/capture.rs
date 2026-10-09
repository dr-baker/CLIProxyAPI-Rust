//! Capture opens bind to directory descriptors so a substituted date-directory
//! symlink cannot redirect reads or append handles outside an enrolled root.
use std::fs::{self, File, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use super::{invalid, validate_regular_file};
use crate::FileIdentity;

#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_APPEND_LEAF: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    pub identity: FileIdentity,
    pub length: u64,
    pub modified: SystemTime,
    #[cfg(unix)]
    changed: (i64, i64),
    #[cfg(unix)]
    links: u64,
}

pub(crate) fn identity(metadata: &Metadata) -> io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity { device: metadata.dev(), inode: metadata.ino() })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(io::Error::new(io::ErrorKind::Unsupported, "capture identity requires Unix"))
    }
}

pub(crate) fn fingerprint(metadata: &Metadata) -> io::Result<Fingerprint> {
    Ok(Fingerprint {
        identity: identity(metadata)?,
        length: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        changed: {
            use std::os::unix::fs::MetadataExt;
            (metadata.ctime(), metadata.ctime_nsec())
        },
        #[cfg(unix)]
        links: {
            use std::os::unix::fs::MetadataExt;
            metadata.nlink()
        },
    })
}

pub(crate) struct CaptureParent {
    root_path: PathBuf,
    #[cfg(any(test, not(unix)))]
    parent_path: PathBuf,
    #[cfg(unix)]
    child_name: Option<std::ffi::OsString>,
    #[cfg(unix)]
    root: File,
    #[cfg(unix)]
    child: Option<File>,
}

impl CaptureParent {
    pub fn open(root: &Path, relative: &Path, create: bool) -> io::Result<Self> {
        let parts: Vec<_> = relative.components().collect();
        if !(1..=2).contains(&parts.len()) || parts.iter().any(|part| !matches!(part, Component::Normal(_))) {
            return Err(invalid("capture path must be a bounded canonical relative path"));
        }
        let child_name = (parts.len() == 2).then(|| parts[0].as_os_str().to_owned());
        #[cfg(any(test, not(unix)))]
        let parent_path = child_name.as_ref().map_or_else(|| root.to_owned(), |name| root.join(name));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let root_file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(root)?;
            let child = if let Some(name) = &child_name {
                let open = || open_at(&root_file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
                let directory = match open() {
                    Ok(file) => file,
                    Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                        use std::os::fd::AsRawFd;
                        let name = c_name(name)?;
                        // SAFETY: root_file and the CString remain alive for this call.
                        let result = unsafe { libc::mkdirat(root_file.as_raw_fd(), name.as_ptr(), 0o700) };
                        if result != 0 {
                            let error = io::Error::last_os_error();
                            if error.kind() != io::ErrorKind::AlreadyExists {
                                return Err(error);
                            }
                        }
                        let file = open()?;
                        root_file.sync_all()?;
                        file
                    }
                    Err(error) => return Err(error),
                };
                if create {
                    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
                }
                Some(directory)
            } else {
                None
            };
            Ok(Self {
                root_path: root.to_owned(),
                #[cfg(test)]
                parent_path,
                child_name,
                root: root_file,
                child,
            })
        }
        #[cfg(not(unix))]
        {
            if create && child_name.is_some() {
                super::private_directory(&parent_path)?;
            } else {
                super::require_directory(&parent_path)?;
            }
            Ok(Self { root_path: root.to_owned(), parent_path })
        }
    }

    #[cfg(unix)]
    fn directory(&self) -> &File {
        self.child.as_ref().unwrap_or(&self.root)
    }

    pub fn identity(&self) -> io::Result<FileIdentity> {
        #[cfg(unix)]
        {
            identity(&self.directory().metadata()?)
        }
        #[cfg(not(unix))]
        {
            identity(&fs::metadata(&self.parent_path)?)
        }
    }

    pub fn revalidate(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let pathname = fs::symlink_metadata(&self.root_path)?;
            if pathname.is_symlink() || !pathname.is_dir() || identity(&pathname)? != identity(&self.root.metadata()?)?
            {
                return Err(invalid("capture root changed during the operation"));
            }
            if let Some(name) = &self.child_name {
                let current = open_at(&self.root, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                if identity(&current.metadata()?)? != self.identity()? {
                    return Err(invalid("capture parent changed during the operation"));
                }
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            super::require_directory(&self.root_path)?;
            super::require_directory(&self.parent_path)
        }
    }

    /// Discovery can inspect metadata of an unselected linked file without
    /// hashing it. Actual source hashing requires a single-link descriptor.
    pub fn read_leaf(&self, name: &std::ffi::OsStr, single_link: bool) -> io::Result<File> {
        self.revalidate()?;
        #[cfg(unix)]
        let file = open_at(self.directory(), name, libc::O_RDONLY, 0)?;
        #[cfg(not(unix))]
        let file = super::read_file(&self.parent_path.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(invalid("capture source must be a regular file"));
        }
        if single_link {
            validate_regular_file(&file)?;
        }
        self.revalidate()?;
        Ok(file)
    }

    pub fn append_leaf(&self, name: &std::ffi::OsStr) -> io::Result<File> {
        #[cfg(test)]
        if let Some(callback) = BEFORE_APPEND_LEAF.with(|hook| hook.borrow_mut().take()) {
            callback();
        }
        self.revalidate()?;
        #[cfg(unix)]
        let file = open_at(self.directory(), name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT, 0o600)?;
        #[cfg(not(unix))]
        let file = super::append_file(&self.parent_path.join(name))?;
        validate_regular_file(&file)?;
        self.revalidate()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        // Always resync the validated parent. A visible leaf may be a retry
        // after a create succeeded but its directory sync failed.
        self.sync()?;
        Ok(file)
    }

    pub fn sync(&self) -> io::Result<()> {
        #[cfg(test)]
        super::observe_directory_sync(&self.parent_path)?;
        #[cfg(unix)]
        {
            self.directory().sync_all()?;
            self.root.sync_all()?;
        }
        self.revalidate()
    }
}

#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid("capture path contains a NUL byte"))
}

#[cfg(unix)]
fn open_at(parent: &File, name: &std::ffi::OsStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    // SAFETY: the descriptor and CString remain alive, flags include CLOEXEC,
    // and a successful returned descriptor becomes owned by exactly one File.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
