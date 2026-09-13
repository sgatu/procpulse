use std::fs;
use std::path::{Path, PathBuf};

/// Matches a string against a wildcard pattern containing `*` and `?`.
/// Case-insensitive (ASCII).
///
/// - `*` matches zero or more characters.
/// - `?` matches exactly one character.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pat_bytes = pattern.as_bytes();
    let txt_bytes = text.as_bytes();

    let mut p = 0;
    let mut t = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t < txt_bytes.len() {
        if p < pat_bytes.len()
            && (pat_bytes[p] == b'?'
                || pat_bytes[p].to_ascii_lowercase() == txt_bytes[t].to_ascii_lowercase())
        {
            p += 1;
            t += 1;
        } else if p < pat_bytes.len() && pat_bytes[p] == b'*' {
            star_idx = Some(p);
            match_idx = t;
            p += 1;
        } else if let Some(sp) = star_idx {
            p = sp + 1;
            match_idx += 1;
            t = match_idx;
        } else {
            return false;
        }
    }

    while p < pat_bytes.len() && pat_bytes[p] == b'*' {
        p += 1;
    }

    p == pat_bytes.len()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub target_patterns: Vec<String>,
    pub output_path: PathBuf,
    pub sample_interval_secs: u64,
    pub discovery_interval_secs: u64,
    pub aggregation_interval_secs: u64,
    pub max_bytes: u64,
    pub max_files: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_patterns: Vec::new(),
            output_path: PathBuf::from("procpulse_metrics.csv"),
            sample_interval_secs: 2,
            discovery_interval_secs: 6,
            aggregation_interval_secs: 60,
            max_bytes: 2_097_152, // 2 MB
            max_files: 5,
        }
    }
}

impl Config {
    /// Returns a comma-separated summary of configured target patterns.
    pub fn target_summary(&self) -> String {
        if self.target_patterns.is_empty() {
            "[none]".to_string()
        } else {
            self.target_patterns.join(", ")
        }
    }

    /// Returns the primary target pattern (first entry), or empty string if none.
    #[allow(dead_code)]
    pub fn target_executable(&self) -> &str {
        self.target_patterns.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Load configuration following precedence:
    /// 1. Default fallback settings.
    /// 2. procpulse.ini (or procmon.ini) located next to the current executable (if present).
    /// 3. Command-line arguments (override any previous setting).
    pub fn load() -> Result<Self, String> {
        let mut config = Config::default();

        // 1. Attempt to locate procpulse.ini (or legacy procmon.ini) next to the binary
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(parent) = exe_path.parent() {
                let ini_path = parent.join("procpulse.ini");
                let legacy_path = parent.join("procmon.ini");
                if ini_path.is_file() {
                    config.merge_ini_file(&ini_path)?;
                } else if legacy_path.is_file() {
                    config.merge_ini_file(&legacy_path)?;
                }
            }
        } else if Path::new("procpulse.ini").is_file() {
            config.merge_ini_file(Path::new("procpulse.ini"))?;
        } else if Path::new("procmon.ini").is_file() {
            config.merge_ini_file(Path::new("procmon.ini"))?;
        }

        // 2. Command-line arguments override config file
        let args: Vec<String> = std::env::args().collect();
        config.merge_cli_args(&args)?;

        if config.target_patterns.is_empty() {
            return Err("No target executable or pattern specified. Provide it via CLI argument or 'target = ...' in procpulse.ini.".to_string());
        }

        Ok(config)
    }

    pub fn parse_ini_content(&mut self, content: &str) -> Result<(), String> {
        for (line_num, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
                continue;
            }

            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let mut val = val.trim();
                // Strip optional surrounding quotes
                if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                    || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
                {
                    val = &val[1..val.len() - 1];
                }

                match key.as_str() {
                    "target" | "targets" | "target_executable" | "executable" => {
                        self.target_patterns.clear();
                        for part in val.split([',', ';']) {
                            let item = part.trim().trim_matches(|c| c == '"' || c == '\'');
                            if !item.is_empty() {
                                self.target_patterns.push(item.to_string());
                            }
                        }
                    }
                    "output" | "output_path" | "csv" => {
                        self.output_path = PathBuf::from(val);
                    }
                    "sample_interval_secs" | "sample_interval" => {
                        self.sample_interval_secs = val
                            .parse::<u64>()
                            .map_err(|_| format!("Invalid sample_interval_secs at line {}", line_num + 1))?
                            .max(1);
                    }
                    "discovery_interval_secs" | "discovery_interval" => {
                        self.discovery_interval_secs = val
                            .parse::<u64>()
                            .map_err(|_| format!("Invalid discovery_interval_secs at line {}", line_num + 1))?
                            .max(1);
                    }
                    "aggregation_interval_secs" | "aggregation_interval" => {
                        self.aggregation_interval_secs = val
                            .parse::<u64>()
                            .map_err(|_| format!("Invalid aggregation_interval_secs at line {}", line_num + 1))?
                            .max(1);
                    }
                    "max_bytes" | "max_size_bytes" | "max_size" => {
                        self.max_bytes = val
                            .parse::<u64>()
                            .map_err(|_| format!("Invalid max_bytes at line {}", line_num + 1))?;
                    }
                    "max_size_mb" => {
                        let mb = val
                            .parse::<u64>()
                            .map_err(|_| format!("Invalid max_size_mb at line {}", line_num + 1))?;
                        self.max_bytes = mb.saturating_mul(1024 * 1024);
                    }
                    "max_files" | "max_backups" => {
                        self.max_files = val
                            .parse::<u32>()
                            .map_err(|_| format!("Invalid max_files at line {}", line_num + 1))?;
                    }
                    _ => {
                        // Ignore unknown keys gracefully
                    }
                }
            }
        }
        Ok(())
    }

    pub fn merge_ini_file(&mut self, path: &Path) -> Result<(), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        self.parse_ini_content(&content)
    }

    pub fn merge_cli_args(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() <= 1 {
            return Ok(());
        }

        let mut idx = 1;
        let mut positional_idx = 0;
        let mut cli_target_specified = false;

        while idx < args.len() {
            let arg = &args[idx];

            if arg == "-h" || arg == "--help" {
                return Err(Self::usage_string(&args[0]));
            } else if arg == "--target" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--target requires a value".to_string());
                }
                if !cli_target_specified {
                    self.target_patterns.clear();
                    cli_target_specified = true;
                }
                for part in args[idx].split([',', ';']) {
                    let item = part.trim().trim_matches(|c| c == '"' || c == '\'');
                    if !item.is_empty() {
                        self.target_patterns.push(item.to_string());
                    }
                }
            } else if arg == "--output" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--output requires a file path".to_string());
                }
                self.output_path = PathBuf::from(&args[idx]);
            } else if arg == "--sample-interval" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--sample-interval requires seconds".to_string());
                }
                self.sample_interval_secs = args[idx]
                    .parse::<u64>()
                    .map_err(|_| "Invalid sample-interval integer".to_string())?
                    .max(1);
            } else if arg == "--flush-interval" || arg == "--aggregation-interval" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--flush-interval requires seconds".to_string());
                }
                self.aggregation_interval_secs = args[idx]
                    .parse::<u64>()
                    .map_err(|_| "Invalid flush-interval integer".to_string())?
                    .max(1);
            } else if arg == "--max-bytes" || arg == "--max-size-bytes" || arg == "--max-size" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--max-bytes requires an integer in bytes".to_string());
                }
                self.max_bytes = args[idx]
                    .parse::<u64>()
                    .map_err(|_| "Invalid max-bytes integer".to_string())?;
            } else if arg == "--max-size-mb" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--max-size-mb requires an integer in MB".to_string());
                }
                let mb = args[idx]
                    .parse::<u64>()
                    .map_err(|_| "Invalid max-size-mb integer".to_string())?;
                self.max_bytes = mb.saturating_mul(1024 * 1024);
            } else if arg == "--max-files" || arg == "--max-backups" {
                idx += 1;
                if idx >= args.len() {
                    return Err("--max-files requires an integer count".to_string());
                }
                self.max_files = args[idx]
                    .parse::<u32>()
                    .map_err(|_| "Invalid max-files integer".to_string())?;
            } else if arg.starts_with('-') {
                return Err(format!("Unknown option '{}'. Use --help for usage.", arg));
            } else {
                // Positional arguments
                if positional_idx == 0 {
                    if !cli_target_specified {
                        self.target_patterns.clear();
                        cli_target_specified = true;
                    }
                    for part in arg.split([',', ';']) {
                        let item = part.trim().trim_matches(|c| c == '"' || c == '\'');
                        if !item.is_empty() {
                            self.target_patterns.push(item.to_string());
                        }
                    }
                } else if positional_idx == 1 {
                    self.output_path = PathBuf::from(arg);
                }
                positional_idx += 1;
            }
            idx += 1;
        }

        Ok(())
    }

    pub fn usage_string(bin_name: &str) -> String {
        format!(
            "Ultra-Light Windows Process Telemetry & Load Diagnostics (procpulse)\n\n\
            Usage: {bin} [TARGET_EXE/WILDCARDS] [OUTPUT_CSV]\n\
            Usage: {bin} --target <TARGETS> [OPTIONS]\n\n\
            Options:\n\
              --target <EXE/WILDCARDS>    Executable name(s) or wildcard pattern(s) to monitor (e.g. \"worker-*.exe, server.exe\")\n\
              --output <FILE>             Output CSV file path (default: procpulse_metrics.csv)\n\
              --sample-interval <SECS>    Metric sampling interval in seconds (default: 2)\n\
              --flush-interval <SECS>     Aggregation flush interval in seconds (default: 60)\n\
              --max-bytes <BYTES>         Maximum CSV file size in bytes before rotation (default: 2097152 [2 MB], 0 to disable)\n\
              --max-files <COUNT>         Maximum number of rotated backup files to retain (default: 5)\n\
              -h, --help                  Print this help message\n\n\
            Configuration file:\n\
              If present, 'procpulse.ini' placed next to the executable is automatically loaded.\n\
              Command-line arguments override settings from the configuration file.",
            bin = bin_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_exact_match() {
        assert!(wildcard_match("dummy_workload.exe", "dummy_workload.exe"));
        assert!(wildcard_match("DUMMY_WORKLOAD.EXE", "dummy_workload.exe"));
        assert!(wildcard_match("dummy_workload.exe", "DUMMY_WORKLOAD.EXE"));
        assert!(!wildcard_match("dummy_workload.exe", "other_app.exe"));
    }

    #[test]
    fn test_wildcard_asterisk() {
        assert!(wildcard_match("worker-*.exe", "worker-alpha.exe"));
        assert!(wildcard_match("worker-*.exe", "worker-.exe"));
        assert!(wildcard_match("worker-*.exe", "WORKER-1234.EXE"));
        assert!(!wildcard_match("worker-*.exe", "server-alpha.exe"));

        assert!(wildcard_match("*.exe", "app.exe"));
        assert!(wildcard_match("*.exe", "C:\\test\\app.exe"));
        assert!(!wildcard_match("*.exe", "app.dll"));

        assert!(wildcard_match("*workload*", "dummy_workload_test.exe"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn test_wildcard_question_mark() {
        assert!(wildcard_match("node-??.exe", "node-01.exe"));
        assert!(wildcard_match("node-??.exe", "node-AB.exe"));
        assert!(!wildcard_match("node-??.exe", "node-1.exe"));
        assert!(!wildcard_match("node-??.exe", "node-123.exe"));
    }

    #[test]
    fn test_parse_ini_content_single_and_multiple_targets() {
        let mut config = Config::default();
        let ini = r#"
        # Comment line
        ; Another comment
        [General]
        target = worker-*.exe, server.exe; "session_??.exe"
        output = "C:\logs\test_metrics.csv"
        sample_interval_secs = 3
        aggregation_interval_secs = 120
        "#;
        config.parse_ini_content(ini).unwrap();

        assert_eq!(
            config.target_patterns,
            vec!["worker-*.exe", "server.exe", "session_??.exe"]
        );
        assert_eq!(config.output_path, PathBuf::from(r"C:\logs\test_metrics.csv"));
        assert_eq!(config.sample_interval_secs, 3);
        assert_eq!(config.aggregation_interval_secs, 120);
    }

    #[test]
    fn test_cli_positional_args() {
        let mut config = Config::default();
        let args = vec![
            "procpulse.exe".to_string(),
            "MyService-*.exe, Other.exe".to_string(),
            "out.csv".to_string(),
        ];
        config.merge_cli_args(&args).unwrap();
        assert_eq!(config.target_patterns, vec!["MyService-*.exe", "Other.exe"]);
        assert_eq!(config.output_path, PathBuf::from("out.csv"));
    }

    #[test]
    fn test_cli_multiple_target_flags() {
        let mut config = Config::default();
        config.target_patterns = vec!["Old.exe".to_string()];
        let args = vec![
            "procpulse.exe".to_string(),
            "--target".to_string(),
            "worker-*.exe".to_string(),
            "--target".to_string(),
            "server.exe".to_string(),
            "--flush-interval".to_string(),
            "30".to_string(),
        ];
        config.merge_cli_args(&args).unwrap();
        assert_eq!(config.target_patterns, vec!["worker-*.exe", "server.exe"]);
        assert_eq!(config.aggregation_interval_secs, 30);
    }

    #[test]
    fn test_output_path_defaults_to_procpulse_metrics() {
        let config = Config::default();
        assert_eq!(config.output_path, PathBuf::from("procpulse_metrics.csv"));
        assert_eq!(config.max_bytes, 2_097_152);
        assert_eq!(config.max_files, 5);
    }

    #[test]
    fn test_ini_rotation_settings() {
        let mut config = Config::default();
        let ini = r#"
        target = test.exe
        max_bytes = 10485760
        max_files = 3
        "#;
        config.parse_ini_content(ini).unwrap();
        assert_eq!(config.max_bytes, 10_485_760);
        assert_eq!(config.max_files, 3);

        let ini_mb = r#"
        max_size_mb = 10
        "#;
        config.parse_ini_content(ini_mb).unwrap();
        assert_eq!(config.max_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_cli_rotation_flags() {
        let mut config = Config::default();
        let args = vec![
            "procpulse.exe".to_string(),
            "--target".to_string(),
            "app.exe".to_string(),
            "--max-bytes".to_string(),
            "52428800".to_string(),
            "--max-files".to_string(),
            "10".to_string(),
        ];
        config.merge_cli_args(&args).unwrap();
        assert_eq!(config.max_bytes, 52_428_800);
        assert_eq!(config.max_files, 10);

        let args_mb = vec![
            "procpulse.exe".to_string(),
            "--max-size-mb".to_string(),
            "5".to_string(),
        ];
        config.merge_cli_args(&args_mb).unwrap();
        assert_eq!(config.max_bytes, 5 * 1024 * 1024);
    }
}
