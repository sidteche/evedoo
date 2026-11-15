// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fs4::FileExt;

use crate::fold::fold;
use crate::model::{Record, State};
use crate::render::render_markdown;

pub struct LockGuard {
    file: File,
}

impl LockGuard {
    pub fn acquire(lock_path: &Path, max_retries: u32, retry_delay: Duration) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;

        for _ in 0..max_retries {
            match FileExt::try_lock(&file) {
                Ok(()) => return Ok(Self { file }),
                Err(fs4::TryLockError::WouldBlock) => {
                    std::thread::sleep(retry_delay);
                }
                Err(fs4::TryLockError::Error(err)) => return Err(err),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "Failed to acquire advisory lock on {} after {} retries",
                lock_path.display(),
                max_retries
            ),
        ))
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub fn discover_state_dir(start: Option<&Path>) -> io::Result<PathBuf> {
    let mut current = if let Some(p) = start {
        p.to_path_buf()
    } else {
        std::env::current_dir()?
    };

    loop {
        let direct_state = current.join("docs").join("agent-state");
        if direct_state.is_dir() {
            return Ok(direct_state);
        }
        let git_dir = current.join(".git");
        if git_dir.exists() {
            let state_dir = current.join("docs").join("agent-state");
            if state_dir.is_dir() {
                return Ok(state_dir);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Found repository root at '{}', but 'docs/agent-state' directory does not exist",
                    current.display()
                ),
            ));
        }
        if !current.pop() {
            break;
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not find repository root (.git) or docs/agent-state directory",
    ))
}

pub fn read_all(path: &Path) -> io::Result<Vec<Record>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    "Skipping unreadable line {} in {}: {}",
                    line_idx + 1,
                    path.display(),
                    e
                );
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Record>(trimmed) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::warn!(
                    "Skipping corrupted/truncated line {} in {}: '{}'. Error: {}",
                    line_idx + 1,
                    path.display(),
                    trimmed,
                    e
                );
            }
        }
    }

    Ok(records)
}

pub struct Store {
    state_dir: PathBuf,
}

impl Store {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    pub fn discover() -> io::Result<Self> {
        let state_dir = discover_state_dir(None)?;
        Ok(Self::new(state_dir))
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn tasks_path(&self) -> PathBuf {
        self.state_dir.join("tasks.jsonl")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.state_dir.join(".lock")
    }

    pub fn current_md_path(&self) -> PathBuf {
        self.state_dir.join("CURRENT.md")
    }

    pub fn read_records(&self) -> io::Result<Vec<Record>> {
        read_all(&self.tasks_path())
    }

    pub fn fold_state(&self) -> io::Result<State> {
        let records = self.read_records()?;
        let mut state = fold(&records);
        state.store_path = Some(self.tasks_path().display().to_string());
        Ok(state)
    }

    pub fn append(&self, record: &Record) -> io::Result<State> {
        if !self.state_dir.exists() {
            std::fs::create_dir_all(&self.state_dir)?;
        }

        let _guard = LockGuard::acquire(
            &self.lock_path(),
            500,
            Duration::from_millis(15),
        )?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.tasks_path())?;

        let json_line = serde_json::to_string(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        file.write_all(json_line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        let records = read_all(&self.tasks_path())?;
        let mut state = fold(&records);
        state.store_path = Some(self.tasks_path().display().to_string());

        let md = render_markdown(&state);
        self.write_current_md(&md)?;

        Ok(state)
    }

    pub fn render_current(&self) -> io::Result<()> {
        let state = self.fold_state()?;
        let md = render_markdown(&state);
        self.write_current_md(&md)?;
        Ok(())
    }

    fn write_current_md(&self, content: &str) -> io::Result<()> {
        let current_path = self.current_md_path();
        let tmp_path = self.state_dir.join("CURRENT.md.tmp");

        std::fs::write(&tmp_path, content)?;

        // Attempt atomic rename, fallback to removing target first, then fallback to direct write
        if std::fs::rename(&tmp_path, &current_path).is_err() {
            let _ = std::fs::remove_file(&current_path);
            if std::fs::rename(&tmp_path, &current_path).is_err() {
                std::fs::write(&current_path, content)?;
                let _ = std::fs::remove_file(&tmp_path);
            }
        }

        Ok(())
    }
}

pub fn append(record: &Record) -> io::Result<()> {
    let store = Store::discover()?;
    store.append(record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::model::*;

    fn dt(s: &str) -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap()
    }

    #[test]
    fn test_read_all_skips_corrupted_lines() {
        let temp_dir = std::env::temp_dir().join(format!("test_taskstate_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("tasks.jsonl");

        let content = "{\"timestamp\":\"2026-08-28T01:00:00Z\",\"by\":{\"runtime\":\"antigravity\"},\"type\":\"phase_opened\",\"phase\":\"P20\",\"title\":\"Test\",\"goal\":\"Goal\"}\n\
                       { corrupted json line }\n\
                       {\"timestamp\":\"2026-08-28T01:05:00Z\",\"by\":{\"runtime\":\"antigravity\"},\"type\":\"task_declared\",\"task\":\"T1\",\"phase\":\"P20\",\"title\":\"T1\"}\n";
        fs::write(&file_path, content).unwrap();

        let records = read_all(&file_path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].by.runtime, "antigravity");
        assert_eq!(records[1].by.runtime, "antigravity");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_store_append_and_current_md_update() {
        let temp_dir = std::env::temp_dir().join(format!("test_taskstate_store_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let store = Store::new(temp_dir.clone());

        let r1 = Record {
            timestamp: dt("2026-08-28T01:00:00Z"),
            by: Actor::new("antigravity"),
            event: Event::PhaseOpened {
                phase: "P20".to_string(),
                title: "Test Phase".to_string(),
                goal: "Goal".to_string(),
            },
        };

        let state = store.append(&r1).unwrap();
        assert_eq!(state.active_phase.unwrap().phase, "P20");

        let current_md = fs::read_to_string(store.current_md_path()).unwrap();
        assert!(current_md.contains("## Active Phase\n\n- **Phase**: P20"));

        let r2 = Record {
            timestamp: dt("2026-08-28T01:05:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskDeclared {
                task: "T1".to_string(),
                phase: "P20".to_string(),
                title: "First Task".to_string(),
                description: None,
                depends_on: vec![],
                review_required: true,
            },
        };
        store.append(&r2).unwrap();

        let records = store.read_records().unwrap();
        assert_eq!(records.len(), 2);

        let current_md2 = fs::read_to_string(store.current_md_path()).unwrap();
        assert!(current_md2.contains("## Next Task\n\n- **T1**: First Task"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_lock_guard_contention() {
        let temp_dir = std::env::temp_dir().join(format!("test_taskstate_lock_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        fs::create_dir_all(&temp_dir).unwrap();
        let lock_path = temp_dir.join(".lock");

        let guard1 = LockGuard::acquire(&lock_path, 5, Duration::from_millis(10)).unwrap();
        let guard2_res = LockGuard::acquire(&lock_path, 2, Duration::from_millis(10));
        assert!(guard2_res.is_err());

        drop(guard1);

        let guard3 = LockGuard::acquire(&lock_path, 5, Duration::from_millis(10));
        assert!(guard3.is_ok());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
