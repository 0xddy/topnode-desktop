use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const LOG_FILE_NAME: &str = "topnode-desktop.log";
const MAX_FILE_BYTES: u64 = 4 * 1_024 * 1_024;
const MAX_TOTAL_BYTES: u64 = 32 * 1_024 * 1_024;
const MAX_LOG_FILES: usize = 7;

#[derive(Debug)]
pub struct LogGuard {
    _writer_guard: tracing_appender::non_blocking::WorkerGuard,
}

/// Installs the process-wide tracing subscriber and size-rolling file writer.
///
/// Log events are queued through `tracing_appender` and written by its worker
/// thread. The underlying writer serializes rotation and retention so cloned
/// writer handles cannot race over the active file.
///
/// # Errors
///
/// Returns an I/O error when the log directory or writer cannot be prepared,
/// or when a global subscriber was already installed.
pub fn initialize_logging(log_dir: &Path) -> Result<LogGuard, io::Error> {
    let file_writer = SizeRotatingWriter::new(log_dir, RotationPolicy::default())?;
    let (file_writer, writer_guard) = tracing_appender::non_blocking(file_writer);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,topnode_infrastructure=debug,sing_box=warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(file_writer),
        )
        .try_init()
        .map_err(io::Error::other)?;
    Ok(LogGuard {
        _writer_guard: writer_guard,
    })
}

#[derive(Clone, Copy, Debug)]
struct RotationPolicy {
    segment_bytes: u64,
    total_bytes: u64,
    file_count: usize,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            segment_bytes: MAX_FILE_BYTES,
            total_bytes: MAX_TOTAL_BYTES,
            file_count: MAX_LOG_FILES,
        }
    }
}

impl RotationPolicy {
    fn validate(self) -> io::Result<Self> {
        if self.segment_bytes == 0 || self.total_bytes == 0 || self.file_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log rotation limits must be greater than zero",
            ));
        }
        if self.segment_bytes > self.total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "active log limit cannot exceed total log limit",
            ));
        }
        Ok(self)
    }

    const fn archived_file_limit(self) -> usize {
        self.file_count.saturating_sub(1)
    }

    const fn archived_byte_limit(self) -> u64 {
        self.total_bytes.saturating_sub(self.segment_bytes)
    }
}

#[derive(Clone)]
struct SizeRotatingWriter {
    state: Arc<Mutex<WriterState>>,
}

impl std::fmt::Debug for SizeRotatingWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SizeRotatingWriter")
            .finish_non_exhaustive()
    }
}

impl SizeRotatingWriter {
    fn new(log_dir: &Path, policy: RotationPolicy) -> io::Result<Self> {
        let policy = policy.validate()?;
        fs::create_dir_all(log_dir)?;
        let active_path = log_dir.join(LOG_FILE_NAME);
        let file = open_active_file(&active_path)?;
        let current_bytes = file.metadata()?.len();
        let mut state = WriterState {
            log_dir: log_dir.to_path_buf(),
            active_path,
            file: Some(file),
            current_bytes,
            archive_sequence: 0,
            policy,
        };
        if state.current_bytes >= state.policy.segment_bytes {
            state.rotate()?;
        } else {
            state.prune_archives()?;
        }
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    fn lock_state(&self) -> io::Result<MutexGuard<'_, WriterState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log writer state lock poisoned"))
    }
}

impl Write for SizeRotatingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.lock_state()?.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lock_state()?.file_mut()?.flush()
    }
}

#[derive(Debug)]
struct WriterState {
    log_dir: PathBuf,
    active_path: PathBuf,
    file: Option<File>,
    current_bytes: u64,
    archive_sequence: u64,
    policy: RotationPolicy,
}

impl WriterState {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.current_bytes >= self.policy.segment_bytes {
            self.rotate()?;
        }

        let remaining_bytes = self.policy.segment_bytes.saturating_sub(self.current_bytes);
        let writable_bytes = usize::try_from(remaining_bytes)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let written = self.file_mut()?.write(&buffer[..writable_bytes])?;
        self.current_bytes = self
            .current_bytes
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("active log file is not open"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take()
            && let Err(error) = file.flush()
        {
            self.file = Some(file);
            return Err(error);
        }

        let archive_path = self.next_archive_path();
        if let Err(error) = fs::rename(&self.active_path, &archive_path) {
            self.reopen_after_rotation_failure();
            return Err(error);
        }

        match open_active_file(&self.active_path) {
            Ok(file) => {
                self.file = Some(file);
                self.current_bytes = 0;
            }
            Err(error) => {
                let _ = fs::rename(&archive_path, &self.active_path);
                self.reopen_after_rotation_failure();
                return Err(error);
            }
        }
        self.prune_archives()
    }

    fn next_archive_path(&mut self) -> PathBuf {
        let epoch_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        loop {
            let sequence = self.archive_sequence;
            self.archive_sequence = self.archive_sequence.wrapping_add(1);
            let name = format!(
                "{LOG_FILE_NAME}.{epoch_millis:020}.{:010}.{sequence:010}",
                std::process::id()
            );
            let path = self.log_dir.join(name);
            if !path.exists() {
                return path;
            }
        }
    }

    fn reopen_after_rotation_failure(&mut self) {
        if let Ok(file) = open_active_file(&self.active_path) {
            self.current_bytes = file.metadata().map_or(0, |metadata| metadata.len());
            self.file = Some(file);
        }
    }

    fn prune_archives(&self) -> io::Result<()> {
        prune_archived_logs(&self.log_dir, &self.active_path, self.policy)
    }
}

fn open_active_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn prune_archived_logs(
    log_dir: &Path,
    active_path: &Path,
    policy: RotationPolicy,
) -> io::Result<()> {
    let mut files = Vec::new();
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == active_path || !is_managed_log_name(&entry.file_name()) {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        let metadata = entry.metadata()?;
        files.push((
            metadata.modified().unwrap_or(UNIX_EPOCH),
            metadata.len(),
            path,
        ));
    }
    files.sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| right.2.cmp(&left.2)));

    let mut retained_files = 0_usize;
    let mut retained_bytes = 0_u64;
    for (_, size, path) in files {
        let exceeds_count = retained_files >= policy.archived_file_limit();
        let exceeds_size = retained_bytes.saturating_add(size) > policy.archived_byte_limit();
        if exceeds_count || exceeds_size {
            fs::remove_file(path)?;
        } else {
            retained_files += 1;
            retained_bytes = retained_bytes.saturating_add(size);
        }
    }
    Ok(())
}

fn is_managed_log_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name == LOG_FILE_NAME
            || name
                .strip_prefix(LOG_FILE_NAME)
                .is_some_and(|suffix| suffix.starts_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        sync::{Arc, Barrier},
        thread,
    };

    use super::{LOG_FILE_NAME, RotationPolicy, SizeRotatingWriter, is_managed_log_name};

    #[test]
    fn rotates_before_a_record_would_cross_the_file_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let policy = RotationPolicy {
            segment_bytes: 16,
            total_bytes: 64,
            file_count: 4,
        };
        let mut writer = SizeRotatingWriter::new(directory.path(), policy).expect("writer");

        writer.write_all(b"0123456789abcdef").expect("first write");
        writer.write_all(b"second!!").expect("second write");
        writer.flush().expect("flush");

        assert_eq!(
            fs::read(directory.path().join(LOG_FILE_NAME)).expect("active log"),
            b"second!!"
        );
        let archives = managed_archives(directory.path());
        assert_eq!(archives.len(), 1);
        assert_eq!(
            fs::read(&archives[0]).expect("archive"),
            b"0123456789abcdef"
        );
    }

    #[test]
    fn oversized_write_is_split_without_exceeding_any_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let policy = RotationPolicy {
            segment_bytes: 8,
            total_bytes: 24,
            file_count: 3,
        };
        let mut writer = SizeRotatingWriter::new(directory.path(), policy).expect("writer");

        writer.write_all(&[b'x'; 40]).expect("oversized write");
        writer.flush().expect("flush");

        let mut managed_files = managed_archives(directory.path());
        managed_files.push(directory.path().join(LOG_FILE_NAME));
        let sizes = managed_files
            .iter()
            .map(|path| fs::metadata(path).expect("managed log metadata").len())
            .collect::<Vec<_>>();
        assert!(sizes.iter().all(|size| *size <= policy.segment_bytes));
        assert!(managed_files.len() <= policy.file_count);
        assert!(sizes.iter().sum::<u64>() <= policy.total_bytes);
    }

    #[test]
    fn retention_enforces_file_count_and_total_byte_budget() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let unrelated = directory.path().join("keep-me.txt");
        fs::write(&unrelated, b"unrelated").expect("unrelated fixture");
        let policy = RotationPolicy {
            segment_bytes: 10,
            total_bytes: 25,
            file_count: 3,
        };
        let mut writer = SizeRotatingWriter::new(directory.path(), policy).expect("writer");

        for byte in b'a'..=b'f' {
            writer.write_all(&[byte; 10]).expect("rotating write");
        }
        writer.flush().expect("flush");

        let active = directory.path().join(LOG_FILE_NAME);
        let archives = managed_archives(directory.path());
        let archived_bytes = archives
            .iter()
            .map(|path| fs::metadata(path).expect("archive metadata").len())
            .sum::<u64>();
        assert!(archives.len() <= policy.archived_file_limit());
        assert!(archived_bytes <= policy.archived_byte_limit());
        assert!(archives.len() < policy.file_count);
        assert!(
            fs::metadata(active).expect("active metadata").len() + archived_bytes
                <= policy.total_bytes
        );
        assert_eq!(fs::read(unrelated).expect("unrelated file"), b"unrelated");
    }

    #[test]
    fn cloned_writers_serialize_concurrent_records() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let policy = RotationPolicy {
            segment_bytes: 16 * 1_024,
            total_bytes: 32 * 1_024,
            file_count: 3,
        };
        let writer = SizeRotatingWriter::new(directory.path(), policy).expect("writer");
        let barrier = Arc::new(Barrier::new(5));
        let threads = (0..4)
            .map(|worker| {
                let mut writer = writer.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for record in 0..100 {
                        writeln!(writer, "worker-{worker}-record-{record}").expect("write record");
                    }
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().expect("writer thread");
        }
        let mut writer = writer;
        writer.flush().expect("flush");

        let contents =
            fs::read_to_string(directory.path().join(LOG_FILE_NAME)).expect("active log");
        assert_eq!(contents.lines().count(), 400);
    }

    fn managed_archives(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
        fs::read_dir(directory)
            .expect("read log directory")
            .map(|entry| entry.expect("directory entry"))
            .filter(|entry| {
                entry.file_name() != LOG_FILE_NAME && is_managed_log_name(&entry.file_name())
            })
            .map(|entry| entry.path())
            .collect()
    }
}
