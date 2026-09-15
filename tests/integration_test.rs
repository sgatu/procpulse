use std::fs;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_end_to_end_monitoring() {
    let target_dir = std::env::current_exe()
        .unwrap()
        .parent() // deps
        .unwrap()
        .parent() // debug
        .unwrap()
        .to_path_buf();

    let dummy_exe = target_dir.join("dummy_workload.exe");
    let procpulse_exe = target_dir.join("procpulse.exe");
    let test_csv = target_dir.join("test_output_metrics.csv");

    // Clean up previous test CSV if present
    if test_csv.is_file() {
        let _ = fs::remove_file(&test_csv);
    }

    assert!(
        dummy_exe.is_file(),
        "dummy_workload.exe must be compiled before running test"
    );
    assert!(
        procpulse_exe.is_file(),
        "procpulse.exe must be compiled before running test"
    );

    // 1. Spawn procpulse with 1s sample, 4s flush, 1s discovery
    let mut monitor_proc: Child = Command::new(&procpulse_exe)
        .arg("--target")
        .arg("dummy_workload.exe")
        .arg("--output")
        .arg(&test_csv)
        .arg("--sample-interval")
        .arg("1")
        .arg("--flush-interval")
        .arg("4")
        .spawn()
        .expect("Failed to start procpulse.exe");

    // Let monitor start and establish initial system baseline
    sleep(Duration::from_millis(1500));

    // 2. Spawn two dummy workloads with distinct arguments
    let mut child1 = Command::new(&dummy_exe)
        .arg("--server")
        .arg("alpha")
        .arg("--port")
        .arg("8001")
        .spawn()
        .expect("Failed to start dummy instance 1");

    let mut child2 = Command::new(&dummy_exe)
        .arg("--server")
        .arg("beta")
        .arg("--port")
        .arg("8002")
        .spawn()
        .expect("Failed to start dummy instance 2");

    // Allow dummy workloads to run across discovery and at least one aggregation flush window
    sleep(Duration::from_secs(6));

    // Terminate children
    let _ = child1.kill();
    let _ = child2.kill();
    let _ = child1.wait();
    let _ = child2.wait();

    // Sleep an extra 2s to allow monitor to detect exit and flush
    sleep(Duration::from_secs(2));

    // Kill monitor
    let _ = monitor_proc.kill();
    let _ = monitor_proc.wait();

    // 3. Verify output CSV file exists and has content
    assert!(test_csv.is_file(), "Output CSV file should have been created");
    let csv_content = fs::read_to_string(&test_csv).expect("Failed to read CSV");
    println!("=== Test CSV Output Content ===\n{}", csv_content);

    let lines: Vec<&str> = csv_content.lines().collect();
    assert!(lines.len() >= 2, "CSV must contain at least header and one row");

    // Check Header
    assert_eq!(
        lines[0],
        "timestamp,executable,args,pid,app_cpu_avg,app_cpu_peak,app_cpu_cycles,app_cpu_time_ms,app_ram_mb_avg,app_ram_mb_peak,app_priv_ram_mb_avg,app_priv_ram_mb_peak,app_priv_active_mb_avg,app_priv_active_mb_peak,app_net_rx_bytes,app_net_tx_bytes,system_cpu_avg,system_cpu_peak,system_ram_mb_avg,system_ram_mb_peak,samples"
    );

    // Verify presence of monitored instances
    let has_alpha = lines.iter().any(|line| line.contains("--server alpha --port 8001"));
    let has_beta = lines.iter().any(|line| line.contains("--server beta --port 8002"));

    assert!(has_alpha, "CSV output must contain records for alpha instance");
    assert!(has_beta, "CSV output must contain records for beta instance");

    // Clean up test file
    let _ = fs::remove_file(&test_csv);
}
