mod config;
mod monitor;
mod output;
mod win32;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{FALSE, TRUE};
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};

use config::Config;
use monitor::ProcessMonitor;

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
            TRUE
        }
        _ => FALSE,
    }
}

fn main() {
    // 1. Register console control handler for graceful shutdown
    unsafe {
        SetConsoleCtrlHandler(Some(console_ctrl_handler), TRUE);
    }

    // 2. Enable SeDebugPrivilege if running with administrative rights
    let has_debug_priv = win32::enable_debug_privilege();

    // 3. Load configuration from INI and/or CLI arguments
    let config = match Config::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    eprintln!("============================================================");
    eprintln!(" Ultra-Light Windows Process Telemetry & Load Diagnostics (procpulse v{})", env!("CARGO_PKG_VERSION"));
    eprintln!("============================================================");
    eprintln!("Target Pattern(s) : {}", config.target_summary());
    eprintln!("Output CSV File   : {}", config.output_path.display());
    if config.max_bytes > 0 {
        let mb = config.max_bytes as f64 / (1024.0 * 1024.0);
        eprintln!("CSV Rotation      : {} bytes ({:.2} MB), {} backup files", config.max_bytes, mb, config.max_files);
    } else {
        eprintln!("CSV Rotation      : Disabled (unlimited file size)");
    }
    eprintln!("Sample Interval   : {}s", config.sample_interval_secs);
    eprintln!("Flush Interval    : {}s", config.aggregation_interval_secs);
    eprintln!("Discovery Interval: {}s", config.discovery_interval_secs);
    if has_debug_priv {
        eprintln!("Privilege Level   : Administrator (SeDebugPrivilege enabled)");
    } else {
        eprintln!("Privilege Level   : Standard User (run as Admin to monitor SYSTEM processes)");
    }
    eprintln!("============================================================");
    eprintln!("[INFO] Monitor active. Press Ctrl+C to stop.");

    // 3. Initialize Process Monitor
    let sample_interval_secs = config.sample_interval_secs;
    let mut monitor = match ProcessMonitor::new(config) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("[FATAL] Failed to initialize monitor: {}", err);
            std::process::exit(1);
        }
    };

    // 4. Main monitoring loop
    while !SHUTDOWN_FLAG.load(Ordering::SeqCst) {
        monitor.run_cycle();

        // Responsive sleep in 100ms increments
        let sleep_ms = sample_interval_secs * 1000;
        let mut elapsed_ms = 0;
        while elapsed_ms < sleep_ms && !SHUTDOWN_FLAG.load(Ordering::SeqCst) {
            let step = std::cmp::min(100, sleep_ms - elapsed_ms);
            std::thread::sleep(Duration::from_millis(step));
            elapsed_ms += step;
        }
    }

    // 5. Finalize and flush pending data on exit
    monitor.shutdown_flush();
    eprintln!("[INFO] procpulse stopped cleanly.");
}
