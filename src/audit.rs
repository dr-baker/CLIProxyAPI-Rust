//! Local, append-only payload and timing archive. Authentication headers are never recorded.
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;

use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};

use crate::config::Config;

pub struct Audit {
    directory: RwLock<Option<PathBuf>>,
    writer: Mutex<()>,
}

impl Audit {
    pub fn new(cfg: &Config) -> Self {
        Self { directory: RwLock::new(Self::path(cfg)), writer: Mutex::new(()) }
    }

    fn path(cfg: &Config) -> Option<PathBuf> {
        if !cfg.request_log {
            return None;
        }
        let raw = &cfg.request_log_dir;
        Some(if let Some(tail) = raw.strip_prefix("~/") {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(tail)
        } else {
            PathBuf::from(raw)
        })
    }

    pub fn configure(&self, cfg: &Config) {
        *self.directory.write() = Self::path(cfg);
    }

    pub fn record(&self, request_id: u64, direction: &str, transport: &str, data: Value) -> io::Result<()> {
        let Some(directory) = self.directory.read().clone() else {
            return Ok(());
        };
        let _guard = self.writer.lock();
        let now = Utc::now();
        let record = json!({ "timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "process_id": std::process::id(), "request_id": request_id,
            "direction": direction, "transport": transport, "data": data });
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("rust-{}.jsonl", now.format("%Y-%m-%d")));
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        if direction == "summary" {
            file.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_appends_and_disabled_archive_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("cliproxy-audit-{}", uuid::Uuid::new_v4()));
        let mut cfg = Config { request_log_dir: dir.to_string_lossy().into(), ..Default::default() };
        let audit = Audit::new(&cfg);
        audit.record(1, "upstream_event", "websocket", json!({"type":"response.completed"})).unwrap();
        assert!(!dir.exists());
        cfg.request_log = true;
        audit.configure(&cfg);
        for id in [1, 2] {
            audit.record(id, "upstream_event", "websocket", json!({"type":"response.completed"})).unwrap();
        }
        let path = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["request_id"], 2);
        assert_eq!(rows[0]["transport"], "websocket");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
