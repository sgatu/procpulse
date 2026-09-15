use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

pub const CSV_HEADER: &str = "timestamp,executable,args,pid,app_cpu_avg,app_cpu_peak,app_cpu_cycles,app_cpu_time_ms,app_ram_mb_avg,app_ram_mb_peak,app_priv_ram_mb_avg,app_priv_ram_mb_peak,app_priv_active_mb_avg,app_priv_active_mb_peak,app_net_rx_bytes,app_net_tx_bytes,system_cpu_avg,system_cpu_peak,system_ram_mb_avg,system_ram_mb_peak,samples\n";

/// Escapes a string for CSV according to RFC 4180.
/// Encloses in double quotes if it contains commas, quotes, line breaks,
/// or leading/trailing whitespace, and doubles up internal quotes.
pub fn escape_csv_field(field: &str) -> String {
    let needs_quotes = field.contains(',')
        || field.contains('"')
        || field.contains('\n')
        || field.contains('\r')
        || field.starts_with(' ')
        || field.ends_with(' ')
        || field.starts_with('\t')
        || field.ends_with('\t');

    if needs_quotes {
        let mut escaped = String::with_capacity(field.len() + 8);
        escaped.push('"');
        for c in field.chars() {
            if c == '"' {
                escaped.push('"');
                escaped.push('"');
            } else {
                escaped.push(c);
            }
        }
        escaped.push('"');
        escaped
    } else {
        field.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CsvRecord<'a> {
    pub timestamp: &'a str,
    pub executable: &'a str,
    pub args: &'a str,
    pub pid: u32,
    pub app_cpu_avg: f64,
    pub app_cpu_peak: f64,
    pub app_cpu_cycles: u64,
    pub app_cpu_time_ms: u64,
    pub app_ram_ws_avg_mb: f64,
    pub app_ram_ws_peak_mb: f64,
    pub app_priv_ram_avg_mb: f64,
    pub app_priv_ram_peak_mb: f64,
    pub app_priv_active_avg_mb: f64,
    pub app_priv_active_peak_mb: f64,
    pub app_net_rx_bytes: u64,
    pub app_net_tx_bytes: u64,
    pub system_cpu_avg: f64,
    pub system_cpu_peak: f64,
    pub system_ram_avg_mb: f64,
    pub system_ram_peak_mb: f64,
    pub sample_count: u32,
}

impl<'a> CsvRecord<'a> {
    pub fn format_row(&self) -> String {
        format!(
            "{timestamp},{exe},{args},{pid},{app_cpu_avg:.3},{app_cpu_peak:.3},{app_cpu_cycles},{app_cpu_time_ms},{app_ws_avg:.1},{app_ws_peak:.1},{app_priv_avg:.1},{app_priv_peak:.1},{app_priv_act_avg:.1},{app_priv_act_peak:.1},{app_net_rx},{app_net_tx},{sys_cpu_avg:.2},{sys_cpu_peak:.2},{sys_ram_avg:.1},{sys_ram_peak:.1},{samples}\n",
            timestamp = self.timestamp,
            exe = escape_csv_field(self.executable),
            args = escape_csv_field(self.args),
            pid = self.pid,
            app_cpu_avg = self.app_cpu_avg,
            app_cpu_peak = self.app_cpu_peak,
            app_cpu_cycles = self.app_cpu_cycles,
            app_cpu_time_ms = self.app_cpu_time_ms,
            app_ws_avg = self.app_ram_ws_avg_mb,
            app_ws_peak = self.app_ram_ws_peak_mb,
            app_priv_avg = self.app_priv_ram_avg_mb,
            app_priv_peak = self.app_priv_ram_peak_mb,
            app_priv_act_avg = self.app_priv_active_avg_mb,
            app_priv_act_peak = self.app_priv_active_peak_mb,
            app_net_rx = self.app_net_rx_bytes,
            app_net_tx = self.app_net_tx_bytes,
            sys_cpu_avg = self.system_cpu_avg,
            sys_cpu_peak = self.system_cpu_peak,
            sys_ram_avg = self.system_ram_avg_mb,
            sys_ram_peak = self.system_ram_peak_mb,
            samples = self.sample_count,
        )
    }
}

/// Derives the numbered backup file path for rolling file rotation.
/// E.g. `procmon_metrics.csv` with index `1` -> `procmon_metrics.1.csv`
/// E.g. `C:\logs\metrics.csv` with index `2` -> `C:\logs\metrics.2.csv`
/// E.g. `metrics` (no extension) with index `1` -> `metrics.1`
pub fn backup_path(base_path: &Path, index: u32) -> PathBuf {
    let parent = base_path.parent();
    let file_name = match base_path.file_name() {
        Some(name) => name.to_string_lossy(),
        None => return base_path.to_path_buf(),
    };

    let new_filename = match (base_path.file_stem(), base_path.extension()) {
        (Some(stem), Some(ext)) => {
            format!("{}.{}.{}", stem.to_string_lossy(), index, ext.to_string_lossy())
        }
        _ => {
            format!("{}.{}", file_name, index)
        }
    };

    if let Some(p) = parent {
        if !p.as_os_str().is_empty() {
            return p.join(new_filename);
        }
    }
    PathBuf::from(new_filename)
}

pub struct CsvWriter {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    current_bytes: u64,
    max_bytes: u64,
    max_files: u32,
}

impl CsvWriter {
    pub fn new(path: &Path, max_bytes: u64, max_files: u32) -> io::Result<Self> {
        Self::with_max_bytes(path, max_bytes, max_files)
    }

    pub fn with_max_bytes(path: &Path, max_bytes: u64, max_files: u32) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file_exists = path.is_file();
        let file_size = if file_exists {
            path.metadata().map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let mut writer = BufWriter::new(file);

        let mut current_bytes = file_size;
        // Write header only if file is newly created or empty
        if file_size == 0 {
            writer.write_all(CSV_HEADER.as_bytes())?;
            writer.flush()?;
            current_bytes = CSV_HEADER.len() as u64;
        }

        Ok(Self {
            path: path.to_path_buf(),
            writer: Some(writer),
            current_bytes,
            max_bytes,
            max_files,
        })
    }

    /// Performs rolling log rotation:
    /// Releases the active file handle, shifts existing numbered backups up (e.g. .4 -> .5, .3 -> .4),
    /// renames active file to .1, and creates a fresh active CSV with CSV_HEADER.
    pub fn rotate(&mut self) -> io::Result<()> {
        // 1. Flush and drop existing writer so Windows allows renaming the file
        if let Some(mut w) = self.writer.take() {
            let _ = w.flush();
            drop(w);
        }

        if self.max_files > 0 {
            // Delete oldest backup if it exceeds max_files
            let oldest = backup_path(&self.path, self.max_files);
            if oldest.is_file() {
                let _ = fs::remove_file(&oldest);
            }

            // Shift backups (max_files - 1 down to 1) -> (max_files down to 2)
            for i in (1..self.max_files).rev() {
                let src = backup_path(&self.path, i);
                let dst = backup_path(&self.path, i + 1);
                if src.is_file() {
                    if dst.is_file() {
                        let _ = fs::remove_file(&dst);
                    }
                    let _ = fs::rename(&src, &dst);
                }
            }

            // Rotate active file to .1
            if self.path.is_file() {
                let dst = backup_path(&self.path, 1);
                if dst.is_file() {
                    let _ = fs::remove_file(&dst);
                }
                let _ = fs::rename(&self.path, &dst);
            }
        } else if self.path.is_file() {
            // max_files == 0: no backups kept, remove active file
            let _ = fs::remove_file(&self.path);
        }

        // 2. Open fresh active CSV file and write header
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;

        let mut writer = BufWriter::new(file);
        writer.write_all(CSV_HEADER.as_bytes())?;
        writer.flush()?;

        self.current_bytes = CSV_HEADER.len() as u64;
        self.writer = Some(writer);

        Ok(())
    }

    pub fn write_record(&mut self, record: &CsvRecord) -> io::Result<()> {
        let row = record.format_row();
        let row_len = row.len() as u64;

        if self.max_bytes > 0 && self.current_bytes.saturating_add(row_len) > self.max_bytes {
            self.rotate()?;
        }

        if let Some(writer) = &mut self.writer {
            writer.write_all(row.as_bytes())?;
            self.current_bytes = self.current_bytes.saturating_add(row_len);
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = &mut self.writer {
            writer.flush()?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)]
    pub fn current_bytes(&self) -> u64 {
        self.current_bytes
    }

    #[allow(dead_code)]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[allow(dead_code)]
    pub fn max_files(&self) -> u32 {
        self.max_files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_plain_string() {
        assert_eq!(escape_csv_field("simple_arg"), "simple_arg");
    }

    #[test]
    fn test_escape_spaces() {
        assert_eq!(escape_csv_field("arg with spaces"), "arg with spaces");
        assert_eq!(escape_csv_field(" leading_space"), "\" leading_space\"");
        assert_eq!(escape_csv_field("trailing_space "), "\"trailing_space \"");
    }

    #[test]
    fn test_escape_commas() {
        assert_eq!(escape_csv_field("server,alpha"), "\"server,alpha\"");
    }

    #[test]
    fn test_escape_quotes_and_paths() {
        assert_eq!(
            escape_csv_field(r#"--config "C:\Program Files\App\cfg.ini""#),
            r#""--config ""C:\Program Files\App\cfg.ini""""#
        );
    }

    #[test]
    fn test_format_row() {
        let record = CsvRecord {
            timestamp: "2026-09-10T17:15:00Z",
            executable: "MyApplication.exe",
            args: "--server alpha --port 8001",
            pid: 4100,
            app_cpu_avg: 3.21,
            app_cpu_peak: 12.40,
            app_cpu_cycles: 4500000000,
            app_cpu_time_ms: 1250,
            app_ram_ws_avg_mb: 428.3,
            app_ram_ws_peak_mb: 451.8,
            app_priv_ram_avg_mb: 310.5,
            app_priv_ram_peak_mb: 325.0,
            app_priv_active_avg_mb: 215.2,
            app_priv_active_peak_mb: 220.0,
            app_net_rx_bytes: 1048576,
            app_net_tx_bytes: 524288,
            system_cpu_avg: 18.72,
            system_cpu_peak: 37.20,
            system_ram_avg_mb: 10342.5,
            system_ram_peak_mb: 10891.2,
            sample_count: 30,
        };

        let row = record.format_row();
        assert_eq!(
            row,
            "2026-09-10T17:15:00Z,MyApplication.exe,--server alpha --port 8001,4100,3.210,12.400,4500000000,1250,428.3,451.8,310.5,325.0,215.2,220.0,1048576,524288,18.72,37.20,10342.5,10891.2,30\n"
        );
    }

    #[test]
    fn test_backup_path_formatting() {
        assert_eq!(
            backup_path(Path::new("procpulse_metrics.csv"), 1),
            PathBuf::from("procpulse_metrics.1.csv")
        );
        assert_eq!(
            backup_path(Path::new("procpulse_metrics.csv"), 5),
            PathBuf::from("procpulse_metrics.5.csv")
        );
        assert_eq!(
            backup_path(Path::new(r"C:\logs\metrics.csv"), 2),
            PathBuf::from(r"C:\logs\metrics.2.csv")
        );
        assert_eq!(
            backup_path(Path::new("metrics"), 1),
            PathBuf::from("metrics.1")
        );
    }

    fn sample_record() -> CsvRecord<'static> {
        CsvRecord {
            timestamp: "2026-09-13T12:00:00Z",
            executable: "test.exe",
            args: "--arg 1",
            pid: 1234,
            app_cpu_avg: 1.0,
            app_cpu_peak: 2.0,
            app_cpu_cycles: 100,
            app_cpu_time_ms: 10,
            app_ram_ws_avg_mb: 10.0,
            app_ram_ws_peak_mb: 12.0,
            app_priv_ram_avg_mb: 8.0,
            app_priv_ram_peak_mb: 9.0,
            app_priv_active_avg_mb: 7.0,
            app_priv_active_peak_mb: 7.5,
            app_net_rx_bytes: 0,
            app_net_tx_bytes: 0,
            system_cpu_avg: 5.0,
            system_cpu_peak: 10.0,
            system_ram_avg_mb: 4000.0,
            system_ram_peak_mb: 4100.0,
            sample_count: 5,
        }
    }

    #[test]
    fn test_csv_rotation_threshold_and_content() {
        let temp_dir = std::env::temp_dir().join(format!("procpulse_test_rot_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let csv_path = temp_dir.join("test_metrics.csv");
        let bkp1 = temp_dir.join("test_metrics.1.csv");

        // Clean up before test
        let _ = fs::remove_file(&csv_path);
        let _ = fs::remove_file(&bkp1);

        let record = sample_record();
        let row_len = record.format_row().len() as u64;
        let header_len = CSV_HEADER.len() as u64;

        // Set max_bytes such that header fits, but writing 1 record triggers rotation
        let max_bytes = header_len + row_len / 2;

        let mut writer = CsvWriter::with_max_bytes(&csv_path, max_bytes, 3).unwrap();
        assert_eq!(writer.current_bytes(), header_len);

        // Writing record exceeds max_bytes -> rotates -> old file renamed to .1, active file gets new header + record
        writer.write_record(&record).unwrap();
        writer.flush().unwrap();

        assert!(bkp1.is_file(), "Backup file .1.csv should exist after rotation");
        let bkp1_content = fs::read_to_string(&bkp1).unwrap();
        assert_eq!(bkp1_content, CSV_HEADER);

        assert!(csv_path.is_file(), "Active CSV file should exist");
        let active_content = fs::read_to_string(&csv_path).unwrap();
        assert!(active_content.starts_with(CSV_HEADER));
        assert!(active_content.contains("test.exe,--arg 1,1234"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_csv_rotation_backup_shifting() {
        let temp_dir = std::env::temp_dir().join(format!("procpulse_test_shift_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let csv_path = temp_dir.join("shift_metrics.csv");

        let bkp1 = temp_dir.join("shift_metrics.1.csv");
        let bkp2 = temp_dir.join("shift_metrics.2.csv");
        let bkp3 = temp_dir.join("shift_metrics.3.csv");
        let bkp4 = temp_dir.join("shift_metrics.4.csv");

        // Keep at most 3 backups
        let mut writer = CsvWriter::with_max_bytes(&csv_path, 1, 3).unwrap();
        let record = sample_record();

        // Write 4 records: each write will exceed 1 byte and trigger rotation
        for _ in 0..4 {
            writer.write_record(&record).unwrap();
        }
        writer.flush().unwrap();

        assert!(csv_path.is_file(), "Active file must exist");
        assert!(bkp1.is_file(), "Backup 1 must exist");
        assert!(bkp2.is_file(), "Backup 2 must exist");
        assert!(bkp3.is_file(), "Backup 3 must exist");
        assert!(!bkp4.is_file(), "Backup 4 must NOT exist as max_files is 3");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_csv_rotation_disabled_when_zero() {
        let temp_dir = std::env::temp_dir().join(format!("procpulse_test_dis_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let csv_path = temp_dir.join("disabled_metrics.csv");
        let bkp1 = temp_dir.join("disabled_metrics.1.csv");

        // max_bytes = 0 disables rotation
        let mut writer = CsvWriter::with_max_bytes(&csv_path, 0, 5).unwrap();
        let record = sample_record();

        for _ in 0..5 {
            writer.write_record(&record).unwrap();
        }
        writer.flush().unwrap();

        assert!(csv_path.is_file());
        assert!(!bkp1.is_file(), "No backup should be created when rotation is disabled");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_csv_rotation_zero_backups() {
        let temp_dir = std::env::temp_dir().join(format!("procpulse_test_zero_bkp_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let csv_path = temp_dir.join("zero_bkp_metrics.csv");
        let bkp1 = temp_dir.join("zero_bkp_metrics.1.csv");

        // max_files = 0 means no backups kept
        let mut writer = CsvWriter::with_max_bytes(&csv_path, 1, 0).unwrap();
        let record = sample_record();

        writer.write_record(&record).unwrap();
        writer.flush().unwrap();

        assert!(csv_path.is_file());
        assert!(!bkp1.is_file(), "No backup files should exist when max_files is 0");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

