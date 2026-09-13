use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::{wildcard_match, Config};
use crate::output::{CsvRecord, CsvWriter};
use crate::win32::{
    self, extract_arguments, get_process_command_line, get_process_cycle_time,
    get_process_full_path, get_process_memory, get_process_times, get_system_memory,
    get_system_time_utc_string, get_system_times, is_process_alive, open_process_for_monitoring,
    SafeHandle, SystemTimes,
};

#[derive(Debug, Clone, Default)]
pub struct MetricAccumulator {
    pub sample_count: u32,
    pub cpu_sum: f64,
    pub cpu_peak: f64,
    pub cpu_cycles_total: u64,
    pub cpu_time_100ns_total: u64,
    pub ram_ws_sum_mb: f64,
    pub ram_ws_peak_mb: f64,
    pub ram_priv_sum_mb: f64,
    pub ram_priv_peak_mb: f64,
    pub ram_priv_active_sum_mb: f64,
    pub ram_priv_active_peak_mb: f64,
}

impl MetricAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sample(
        &mut self,
        cpu_pct: f64,
        cpu_time_100ns: u64,
        cycles_delta: Option<u64>,
        ws_mb: f64,
        priv_mb: f64,
        priv_active_mb: f64,
    ) {
        self.sample_count += 1;
        self.cpu_sum += cpu_pct;
        if cpu_pct > self.cpu_peak {
            self.cpu_peak = cpu_pct;
        }

        self.cpu_time_100ns_total = self.cpu_time_100ns_total.saturating_add(cpu_time_100ns);

        if let Some(cycles) = cycles_delta {
            self.cpu_cycles_total = self.cpu_cycles_total.saturating_add(cycles);
        }

        self.ram_ws_sum_mb += ws_mb;
        if ws_mb > self.ram_ws_peak_mb {
            self.ram_ws_peak_mb = ws_mb;
        }

        self.ram_priv_sum_mb += priv_mb;
        if priv_mb > self.ram_priv_peak_mb {
            self.ram_priv_peak_mb = priv_mb;
        }

        self.ram_priv_active_sum_mb += priv_active_mb;
        if priv_active_mb > self.ram_priv_active_peak_mb {
            self.ram_priv_active_peak_mb = priv_active_mb;
        }
    }

    pub fn reset(&mut self) {
        self.sample_count = 0;
        self.cpu_sum = 0.0;
        self.cpu_peak = 0.0;
        self.cpu_cycles_total = 0;
        self.cpu_time_100ns_total = 0;
        self.ram_ws_sum_mb = 0.0;
        self.ram_ws_peak_mb = 0.0;
        self.ram_priv_sum_mb = 0.0;
        self.ram_priv_peak_mb = 0.0;
        self.ram_priv_active_sum_mb = 0.0;
        self.ram_priv_active_peak_mb = 0.0;
    }

    /// Converts accumulated 100ns units to milliseconds.
    /// Accumulating raw 100ns units and converting only at flush avoids per-sample truncation loss.
    #[inline]
    pub fn cpu_time_ms(&self) -> u64 {
        self.cpu_time_100ns_total / 10_000
    }

    #[inline]
    #[allow(dead_code)]
    pub fn app_cpu_time_ms(&self) -> u64 {
        self.cpu_time_ms()
    }

    pub fn averages(&self) -> (f64, f64, f64, f64) {
        if self.sample_count == 0 {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            let count = self.sample_count as f64;
            (
                self.cpu_sum / count,
                self.ram_ws_sum_mb / count,
                self.ram_priv_sum_mb / count,
                self.ram_priv_active_sum_mb / count,
            )
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SystemAccumulator {
    pub sample_count: u32,
    pub cpu_sum: f64,
    pub cpu_peak: f64,
    pub ram_used_sum_mb: f64,
    pub ram_used_peak_mb: f64,
}

impl SystemAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sample(&mut self, cpu_pct: f64, ram_used_mb: f64) {
        self.sample_count += 1;
        self.cpu_sum += cpu_pct;
        if cpu_pct > self.cpu_peak {
            self.cpu_peak = cpu_pct;
        }

        self.ram_used_sum_mb += ram_used_mb;
        if ram_used_mb > self.ram_used_peak_mb {
            self.ram_used_peak_mb = ram_used_mb;
        }
    }

    pub fn reset(&mut self) {
        self.sample_count = 0;
        self.cpu_sum = 0.0;
        self.cpu_peak = 0.0;
        self.ram_used_sum_mb = 0.0;
        self.ram_used_peak_mb = 0.0;
    }

    pub fn averages(&self) -> (f64, f64) {
        if self.sample_count == 0 {
            (0.0, 0.0)
        } else {
            let count = self.sample_count as f64;
            (self.cpu_sum / count, self.ram_used_sum_mb / count)
        }
    }
}

/// Calculates per-process CPU usage percentage across the entire machine over an elapsed wall-clock duration.
///
/// Formula:
///   process_cpu_pct = (proc_delta_seconds / (wall_seconds * logical_cores)) * 100.0
///
/// Returns 0.0 if elapsed duration is zero, logical_cores is zero, or delta is zero.
/// Defensively clamped to [0.0, 100.0].
pub fn calculate_process_cpu_pct(proc_delta_100ns: u64, elapsed: Duration, logical_cores: u32) -> f64 {
    let wall_secs = elapsed.as_secs_f64();
    if wall_secs <= 0.0 || logical_cores == 0 || proc_delta_100ns == 0 {
        return 0.0;
    }

    // Convert 100-nanosecond units (10^-7 seconds) to seconds
    let proc_secs = proc_delta_100ns as f64 / 10_000_000.0;
    let total_available_secs = wall_secs * logical_cores as f64;

    let pct = (proc_secs / total_available_secs) * 100.0;
    pct.clamp(0.0, 100.0)
}

pub struct TrackedInstance {
    pub pid: u32,
    pub handle: SafeHandle,
    pub executable: String,
    pub args: String,
    pub prev_proc_time: u64,
    pub prev_sample_instant: Option<Instant>,
    pub prev_cycle_count: Option<u64>,
    pub cycle_warned: bool,
    pub accumulator: MetricAccumulator,
}

pub struct ProcessMonitor {
    config: Config,
    tracked: HashMap<u32, TrackedInstance>,
    warned_pids: std::collections::HashSet<u32>,
    prev_system_times: Option<SystemTimes>,
    system_accumulator: SystemAccumulator,
    last_discovery_instant: Instant,
    last_flush_instant: Instant,
    writer: CsvWriter,
    logical_cores: u32,
}

impl ProcessMonitor {
    pub fn new(config: Config) -> Result<Self, String> {
        let writer = CsvWriter::new(&config.output_path, config.max_bytes, config.max_files)
            .map_err(|e| format!("Failed to open output CSV '{}': {}", config.output_path.display(), e))?;

        // Initialize last_discovery_instant in the past to trigger immediate initial discovery
        let past = Instant::now() - Duration::from_secs(config.discovery_interval_secs + 1);

        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);

        Ok(Self {
            config,
            tracked: HashMap::with_capacity(16),
            warned_pids: std::collections::HashSet::with_capacity(8),
            prev_system_times: None,
            system_accumulator: SystemAccumulator::new(),
            last_discovery_instant: past,
            last_flush_instant: Instant::now(),
            writer,
            logical_cores,
        })
    }

    pub fn run_cycle(&mut self) {
        // 1. Process Discovery (if due)
        let now = Instant::now();
        if now.duration_since(self.last_discovery_instant) >= Duration::from_secs(self.config.discovery_interval_secs) {
            self.discover_processes();
            self.last_discovery_instant = now;
        }

        // 2. Check process lifetime for all tracked instances
        self.check_process_exits();

        // 3. Sample System and Process Metrics
        self.sample_metrics();

        // 4. Aggregation Flush (if interval elapsed)
        if now.duration_since(self.last_flush_instant) >= Duration::from_secs(self.config.aggregation_interval_secs) {
            self.flush_aggregates();
            self.last_flush_instant = Instant::now();
        }
    }

    fn matches_any_target(&self, exe_name: &str, handle: &SafeHandle) -> bool {
        let mut full_path_memo: Option<Option<String>> = None;

        for pattern in &self.config.target_patterns {
            if pattern.contains('\\') || pattern.contains('/') {
                let full_path = full_path_memo
                    .get_or_insert_with(|| get_process_full_path(handle));
                if let Some(path) = full_path {
                    if wildcard_match(pattern, path) {
                        return true;
                    }
                }
            } else if wildcard_match(pattern, exe_name) {
                return true;
            }
        }
        false
    }

    fn discover_processes(&mut self) {
        let snapshot_entries = win32::enumerate_processes();

        for entry in snapshot_entries {
            // Avoid re-discovering already tracked PIDs
            if self.tracked.contains_key(&entry.pid) {
                continue;
            }

            // Quick check: does the exe name match any target pattern (or its filename stem)?
            let mut matches_quick = false;
            for pattern in &self.config.target_patterns {
                let pat_stem = Path::new(pattern)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(pattern);
                if wildcard_match(pat_stem, &entry.exe_name) {
                    matches_quick = true;
                    break;
                }
            }

            if !matches_quick {
                continue;
            }

            // Attempt to open the process handle
            match open_process_for_monitoring(entry.pid) {
                Ok(handle) => {
                    // Verify full path if any matching pattern specified a path
                    if !self.matches_any_target(&entry.exe_name, &handle) {
                        continue;
                    }

                    // Query command line
                    let args = match get_process_command_line(&handle) {
                        Ok(cmd) => extract_arguments(&cmd),
                        Err(_) => "[arguments_unavailable]".to_string(),
                    };

                    eprintln!(
                        "[INFO] Discovered matching process: PID {} ('{}'), args: '{}'",
                        entry.pid, entry.exe_name, args
                    );

                    self.tracked.insert(
                        entry.pid,
                        TrackedInstance {
                            pid: entry.pid,
                            handle,
                            executable: entry.exe_name,
                            args,
                            prev_proc_time: 0,
                            prev_sample_instant: None,
                            prev_cycle_count: None,
                            cycle_warned: false,
                            accumulator: MetricAccumulator::new(),
                        },
                    );
                    self.warned_pids.remove(&entry.pid);
                }
                Err(err) => {
                    if self.warned_pids.insert(entry.pid) {
                        if err == 5 {
                            eprintln!(
                                "[WARN] Found matching process PID {} ('{}'), but access was denied (ERROR_ACCESS_DENIED). Run procmon as Administrator to monitor elevated or SYSTEM processes.",
                                entry.pid, entry.exe_name
                            );
                        } else {
                            eprintln!(
                                "[WARN] Found matching process PID {} ('{}'), but failed to open process (error code {}).",
                                entry.pid, entry.exe_name, err
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_process_exits(&mut self) {
        let mut exited_pids = Vec::new();

        for (&pid, instance) in &self.tracked {
            if !is_process_alive(&instance.handle) {
                exited_pids.push(pid);
            }
        }

        if !exited_pids.is_empty() {
            let timestamp = get_system_time_utc_string();
            let (sys_cpu_avg, sys_ram_avg) = self.system_accumulator.averages();

            for pid in exited_pids {
                if let Some(instance) = self.tracked.remove(&pid) {
                    // If we accumulated any valid samples before it exited, write partial aggregate
                    if instance.accumulator.sample_count > 0 {
                        let (cpu_avg, ws_avg, priv_avg, priv_active_avg) = instance.accumulator.averages();
                        let record = CsvRecord {
                            timestamp: &timestamp,
                            executable: &instance.executable,
                            args: &instance.args,
                            pid: instance.pid,
                            app_cpu_avg: cpu_avg,
                            app_cpu_peak: instance.accumulator.cpu_peak,
                            app_cpu_cycles: instance.accumulator.cpu_cycles_total,
                            app_cpu_time_ms: instance.accumulator.cpu_time_ms(),
                            app_ram_ws_avg_mb: ws_avg,
                            app_ram_ws_peak_mb: instance.accumulator.ram_ws_peak_mb,
                            app_priv_ram_avg_mb: priv_avg,
                            app_priv_ram_peak_mb: instance.accumulator.ram_priv_peak_mb,
                            app_priv_active_avg_mb: priv_active_avg,
                            app_priv_active_peak_mb: instance.accumulator.ram_priv_active_peak_mb,
                            system_cpu_avg: sys_cpu_avg,
                            system_cpu_peak: self.system_accumulator.cpu_peak,
                            system_ram_avg_mb: sys_ram_avg,
                            system_ram_peak_mb: self.system_accumulator.ram_used_peak_mb,
                            sample_count: instance.accumulator.sample_count,
                        };

                        if let Err(e) = self.writer.write_record(&record) {
                            eprintln!("[ERROR] Failed to write CSV record for exited PID {}: {}", pid, e);
                        } else {
                            let _ = self.writer.flush();
                        }

                        eprintln!(
                            "[INFO] Process PID {} exited mid-window. Flushed {} partial samples.",
                            pid, instance.accumulator.sample_count
                        );
                    } else {
                        eprintln!("[INFO] Process PID {} exited without recorded samples.", pid);
                    }
                }
            }
        }
    }

    fn sample_metrics(&mut self) {
        // 1. Sample System Times & Memory
        let cur_sys_times = match get_system_times() {
            Some(t) => t,
            None => return,
        };

        let mut delta_sys_total: u64 = 0;
        let mut sys_cpu_pct: f64 = 0.0;

        if let Some(prev) = self.prev_system_times {
            delta_sys_total = (cur_sys_times.kernel_time.saturating_sub(prev.kernel_time))
                + (cur_sys_times.user_time.saturating_sub(prev.user_time));

            let delta_sys_idle = cur_sys_times.idle_time.saturating_sub(prev.idle_time);

            if delta_sys_total > 0 {
                let active = delta_sys_total.saturating_sub(delta_sys_idle);
                sys_cpu_pct = (active as f64 / delta_sys_total as f64) * 100.0;
                sys_cpu_pct = sys_cpu_pct.clamp(0.0, 100.0);
            }
        }
        self.prev_system_times = Some(cur_sys_times);

        let sys_ram_used_mb = if let Some(mem) = get_system_memory() {
            mem.used_phys_bytes() as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        };

        if delta_sys_total > 0 {
            self.system_accumulator.record_sample(sys_cpu_pct, sys_ram_used_mb);
        }

        // 2. Sample Each Monitored Process
        let now = Instant::now();
        for instance in self.tracked.values_mut() {
            let proc_times = match get_process_times(&instance.handle) {
                Some(pt) => pt,
                None => continue,
            };

            let proc_mem = match get_process_memory(&instance.handle) {
                Some(pm) => pm,
                None => continue,
            };

            let ws_mb = proc_mem.working_set_bytes as f64 / (1024.0 * 1024.0);
            let priv_mb = proc_mem.private_bytes as f64 / (1024.0 * 1024.0);
            let priv_active_mb = proc_mem.private_active_bytes as f64 / (1024.0 * 1024.0);

            // Query cycles independently (failure does NOT invalidate CPU or RAM)
            let cycle_delta = match get_process_cycle_time(&instance.handle) {
                Some(current_cycles) => {
                    let delta = if let Some(prev_cycles) = instance.prev_cycle_count {
                        Some(current_cycles.saturating_sub(prev_cycles))
                    } else {
                        // First sample establishes baseline, contributes no cycles
                        None
                    };
                    instance.prev_cycle_count = Some(current_cycles);
                    delta
                }
                None => {
                    if !instance.cycle_warned {
                        eprintln!(
                            "[WARN] QueryProcessCycleTime failed for PID {} ('{}'). CPU cycles will be omitted for this process.",
                            instance.pid, instance.executable
                        );
                        instance.cycle_warned = true;
                    }
                    // Do not advance baseline on failure; next successful query calculates delta from last known baseline
                    None
                }
            };

            if let Some(prev_instant) = instance.prev_sample_instant {
                let elapsed = now.duration_since(prev_instant);
                let proc_delta = proc_times.total().saturating_sub(instance.prev_proc_time);
                let proc_cpu_pct = calculate_process_cpu_pct(proc_delta, elapsed, self.logical_cores);
                instance.accumulator.record_sample(
                    proc_cpu_pct,
                    proc_delta,
                    cycle_delta,
                    ws_mb,
                    priv_mb,
                    priv_active_mb,
                );
            }

            // Only advance previous counter and timestamp after successful sample
            instance.prev_proc_time = proc_times.total();
            instance.prev_sample_instant = Some(now);
        }
    }

    fn flush_aggregates(&mut self) {
        if self.tracked.is_empty() {
            // Nothing to flush, reset system accumulator
            self.system_accumulator.reset();
            return;
        }

        let timestamp = get_system_time_utc_string();
        let (sys_cpu_avg, sys_ram_avg) = self.system_accumulator.averages();

        for instance in self.tracked.values_mut() {
            if instance.accumulator.sample_count == 0 {
                continue;
            }

            let (cpu_avg, ws_avg, priv_avg, priv_active_avg) = instance.accumulator.averages();
            let record = CsvRecord {
                timestamp: &timestamp,
                executable: &instance.executable,
                args: &instance.args,
                pid: instance.pid,
                app_cpu_avg: cpu_avg,
                app_cpu_peak: instance.accumulator.cpu_peak,
                app_cpu_cycles: instance.accumulator.cpu_cycles_total,
                app_cpu_time_ms: instance.accumulator.cpu_time_ms(),
                app_ram_ws_avg_mb: ws_avg,
                app_ram_ws_peak_mb: instance.accumulator.ram_ws_peak_mb,
                app_priv_ram_avg_mb: priv_avg,
                app_priv_ram_peak_mb: instance.accumulator.ram_priv_peak_mb,
                app_priv_active_avg_mb: priv_active_avg,
                app_priv_active_peak_mb: instance.accumulator.ram_priv_active_peak_mb,
                system_cpu_avg: sys_cpu_avg,
                system_cpu_peak: self.system_accumulator.cpu_peak,
                system_ram_avg_mb: sys_ram_avg,
                system_ram_peak_mb: self.system_accumulator.ram_used_peak_mb,
                sample_count: instance.accumulator.sample_count,
            };

            if let Err(e) = self.writer.write_record(&record) {
                eprintln!("[ERROR] Failed to write CSV row for PID {}: {}", instance.pid, e);
            }

            instance.accumulator.reset();
        }

        let _ = self.writer.flush();
        self.system_accumulator.reset();
    }

    /// Flushes any pending samples when the monitor shuts down
    pub fn shutdown_flush(&mut self) {
        eprintln!("[INFO] Graceful shutdown requested. Flushing pending measurements...");
        self.flush_aggregates();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_accumulator_math() {
        let mut acc = MetricAccumulator::new();
        assert_eq!(acc.averages(), (0.0, 0.0, 0.0, 0.0));
        assert_eq!(acc.cpu_cycles_total, 0);
        assert_eq!(acc.cpu_time_100ns_total, 0);
        assert_eq!(acc.cpu_time_ms(), 0);

        acc.record_sample(10.0, 15_000_000, Some(500_000), 100.0, 50.0, 30.0);
        acc.record_sample(20.0, 25_000_000, Some(750_000), 200.0, 70.0, 40.0);

        assert_eq!(acc.sample_count, 2);
        assert_eq!(acc.cpu_peak, 20.0);
        assert_eq!(acc.cpu_cycles_total, 1_250_000);
        assert_eq!(acc.cpu_time_100ns_total, 40_000_000);
        assert_eq!(acc.cpu_time_ms(), 4_000);
        assert_eq!(acc.app_cpu_time_ms(), 4_000);
        assert_eq!(acc.ram_ws_peak_mb, 200.0);
        assert_eq!(acc.ram_priv_peak_mb, 70.0);
        assert_eq!(acc.ram_priv_active_peak_mb, 40.0);

        let (cpu_avg, ws_avg, priv_avg, priv_act_avg) = acc.averages();
        assert_eq!(cpu_avg, 15.0);
        assert_eq!(ws_avg, 150.0);
        assert_eq!(priv_avg, 60.0);
        assert_eq!(priv_act_avg, 35.0);

        acc.reset();
        assert_eq!(acc.sample_count, 0);
        assert_eq!(acc.cpu_peak, 0.0);
        assert_eq!(acc.cpu_cycles_total, 0);
        assert_eq!(acc.cpu_time_100ns_total, 0);
        assert_eq!(acc.cpu_time_ms(), 0);
        assert_eq!(acc.averages(), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn test_system_accumulator_math() {
        let mut sys_acc = SystemAccumulator::new();
        sys_acc.record_sample(25.0, 8000.0);
        sys_acc.record_sample(35.0, 8200.0);

        assert_eq!(sys_acc.sample_count, 2);
        assert_eq!(sys_acc.cpu_peak, 35.0);
        assert_eq!(sys_acc.ram_used_peak_mb, 8200.0);

        let (cpu_avg, ram_avg) = sys_acc.averages();
        assert_eq!(cpu_avg, 30.0);
        assert_eq!(ram_avg, 8100.0);
    }

    #[test]
    fn test_calculate_process_cpu_zero() {
        // 0 CPU time over 2 seconds => 0%
        let cpu = calculate_process_cpu_pct(0, Duration::from_secs(2), 8);
        assert_eq!(cpu, 0.0);
    }

    #[test]
    fn test_calculate_process_cpu_full_core_on_8_cpus() {
        // 1 logical CPU fully busy for 2 seconds on 8 logical CPUs => 12.5%
        // 2 seconds of 100ns units = 2 * 10_000_000 = 20_000_000
        let delta_100ns = 2 * 10_000_000;
        let cpu = calculate_process_cpu_pct(delta_100ns, Duration::from_secs(2), 8);
        assert!((cpu - 12.5).abs() < 1e-6);
    }

    #[test]
    fn test_calculate_process_cpu_half_core_on_8_cpus() {
        // half of one logical CPU over 2 seconds on 8 logical CPUs => 6.25%
        // 1 second of 100ns units = 10_000_000
        let delta_100ns = 10_000_000;
        let cpu = calculate_process_cpu_pct(delta_100ns, Duration::from_secs(2), 8);
        assert!((cpu - 6.25).abs() < 1e-6);
    }

    #[test]
    fn test_calculate_process_cpu_delayed_interval() {
        // delayed sampling interval, e.g. 3.5 seconds, should still calculate correctly
        // half of one logical CPU for 3.5 seconds on 8 logical CPUs => 6.25%
        let delta_100ns = 17_500_000;
        let cpu = calculate_process_cpu_pct(delta_100ns, Duration::from_millis(3500), 8);
        assert!((cpu - 6.25).abs() < 1e-6);

        // 1 full core for 3.5 seconds on 8 logical CPUs => 12.5%
        let delta_full_100ns = 35_000_000;
        let cpu_full = calculate_process_cpu_pct(delta_full_100ns, Duration::from_millis(3500), 8);
        assert!((cpu_full - 12.5).abs() < 1e-6);
    }

    #[test]
    fn test_calculate_process_cpu_zero_elapsed_and_zero_cpus() {
        // zero elapsed duration handled safely
        let cpu = calculate_process_cpu_pct(1_000_000, Duration::ZERO, 8);
        assert_eq!(cpu, 0.0);

        // zero logical cores handled safely
        let cpu_zero_cores = calculate_process_cpu_pct(1_000_000, Duration::from_secs(2), 0);
        assert_eq!(cpu_zero_cores, 0.0);
    }

    #[test]
    fn test_first_sample_produces_no_cpu_emission() {
        // Emulate first sample behavior: prev_sample_instant is None
        let mut prev_instant: Option<Instant> = None;
        let mut accumulator = MetricAccumulator::new();

        let now = Instant::now();
        // First sample
        if let Some(prev) = prev_instant {
            let elapsed = now.duration_since(prev);
            let cpu = calculate_process_cpu_pct(10_000_000, elapsed, 8);
            accumulator.record_sample(cpu, 10_000_000, None, 100.0, 50.0, 30.0);
        }
        prev_instant = Some(now);

        // Verify accumulator has 0 samples after first call
        assert_eq!(accumulator.sample_count, 0);

        // Second sample after 2 seconds
        let later = now + Duration::from_secs(2);
        if let Some(prev) = prev_instant {
            let elapsed = later.duration_since(prev);
            let cpu = calculate_process_cpu_pct(20_000_000, elapsed, 8);
            accumulator.record_sample(cpu, 20_000_000, None, 100.0, 50.0, 30.0);
        }

        assert_eq!(accumulator.sample_count, 1);
        assert!((accumulator.cpu_sum - 12.5).abs() < 1e-6);
        assert_eq!(accumulator.cpu_time_100ns_total, 20_000_000);
        assert_eq!(accumulator.cpu_time_ms(), 2_000);
    }

    #[test]
    fn test_cycle_first_sample_establishes_baseline_and_contributes_zero() {
        let mut prev_cycles: Option<u64> = None;
        let mut accumulator = MetricAccumulator::new();

        let current_cycles = 120_000_000_000u64;
        let delta = if let Some(prev) = prev_cycles {
            Some(current_cycles.saturating_sub(prev))
        } else {
            None
        };
        prev_cycles = Some(current_cycles);

        assert_eq!(delta, None);
        assert_eq!(prev_cycles, Some(current_cycles));
        accumulator.record_sample(5.0, 0, delta, 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_cycles_total, 0);
    }

    #[test]
    fn test_cycle_subsequent_samples_accumulate_delta() {
        let mut prev_cycles: Option<u64> = Some(120_000_000_000);
        let mut accumulator = MetricAccumulator::new();

        let current_cycles = 121_250_000_000u64;
        let delta = if let Some(prev) = prev_cycles {
            Some(current_cycles.saturating_sub(prev))
        } else {
            None
        };
        prev_cycles = Some(current_cycles);

        assert_eq!(delta, Some(1_250_000_000));
        assert_eq!(prev_cycles, Some(current_cycles));
        accumulator.record_sample(5.0, 0, delta, 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_cycles_total, 1_250_000_000);
    }

    #[test]
    fn test_cycle_multiple_deltas_summed_correctly() {
        let mut accumulator = MetricAccumulator::new();
        accumulator.record_sample(1.0, 0, Some(500_000_000), 100.0, 50.0, 30.0);
        accumulator.record_sample(2.0, 0, Some(750_000_000), 100.0, 50.0, 30.0);
        accumulator.record_sample(3.0, 0, Some(250_000_000), 100.0, 50.0, 30.0);

        assert_eq!(accumulator.cpu_cycles_total, 1_500_000_000);
    }

    #[test]
    fn test_cycle_aggregation_reset_clears_total() {
        let mut accumulator = MetricAccumulator::new();
        accumulator.record_sample(5.0, 0, Some(1_000_000_000), 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_cycles_total, 1_000_000_000);

        accumulator.reset();
        assert_eq!(accumulator.cpu_cycles_total, 0);
        assert_eq!(accumulator.sample_count, 0);
    }

    #[test]
    fn test_cycle_query_failure_does_not_corrupt_baseline() {
        let mut prev_cycles: Option<u64> = Some(100_000_000);
        let mut accumulator = MetricAccumulator::new();

        // Failed query (returns None): do NOT advance baseline, pass None to accumulator
        let query_result: Option<u64> = None;
        let delta = match query_result {
            Some(curr) => {
                let d = prev_cycles.map(|p| curr.saturating_sub(p));
                prev_cycles = Some(curr);
                d
            }
            None => None,
        };

        assert_eq!(delta, None);
        assert_eq!(prev_cycles, Some(100_000_000)); // Baseline intact!
        accumulator.record_sample(2.0, 0, delta, 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_cycles_total, 0);

        // Next query succeeds at 150_000_000
        let query_result_2: Option<u64> = Some(150_000_000);
        let delta_2 = match query_result_2 {
            Some(curr) => {
                let d = prev_cycles.map(|p| curr.saturating_sub(p));
                prev_cycles = Some(curr);
                d
            }
            None => None,
        };

        assert_eq!(delta_2, Some(50_000_000));
        assert_eq!(prev_cycles, Some(150_000_000));
        accumulator.record_sample(3.0, 0, delta_2, 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_cycles_total, 50_000_000);
    }

    #[test]
    fn test_cycle_failure_does_not_prevent_cpu_ram_recording() {
        let mut accumulator = MetricAccumulator::new();
        // Cycle is None, but CPU time and RAM are present
        accumulator.record_sample(7.5, 10_000_000, None, 512.0, 256.0, 180.0);

        assert_eq!(accumulator.sample_count, 1);
        assert_eq!(accumulator.cpu_peak, 7.5);
        assert_eq!(accumulator.cpu_cycles_total, 0);
        assert_eq!(accumulator.cpu_time_100ns_total, 10_000_000);
        assert_eq!(accumulator.cpu_time_ms(), 1_000);
        let (cpu, ws, priv_m, act) = accumulator.averages();
        assert_eq!(cpu, 7.5);
        assert_eq!(ws, 512.0);
        assert_eq!(priv_m, 256.0);
        assert_eq!(act, 180.0);
    }

    #[test]
    fn test_cycle_new_process_starts_with_fresh_baseline() {
        // PID 1000 runs, exits
        let mut pid_1000_baseline: Option<u64> = Some(50_000_000_000);
        let _ = pid_1000_baseline.take(); // Process exits

        // PID 2000 starts with fresh baseline
        let mut pid_2000_baseline: Option<u64> = None;
        let pid_2000_sample_1 = 10_000_000u64;
        let delta_1 = if let Some(prev) = pid_2000_baseline {
            Some(pid_2000_sample_1.saturating_sub(prev))
        } else {
            None
        };
        pid_2000_baseline = Some(pid_2000_sample_1);

        assert_eq!(delta_1, None); // Fresh baseline, no delta against old PID
        assert_eq!(pid_2000_baseline, Some(10_000_000));
    }

    #[test]
    fn test_cycle_large_u64_preserves_precision() {
        let mut accumulator = MetricAccumulator::new();
        // e.g. 18.4 billion cycles (exceeds 32-bit integer, stays exact in u64)
        let large_delta: u64 = 18_446_744_073_000;
        accumulator.record_sample(10.0, 0, Some(large_delta), 100.0, 50.0, 30.0);

        assert_eq!(accumulator.cpu_cycles_total, 18_446_744_073_000);
    }

    #[test]
    fn test_cpu_time_multiple_deltas_summed_correctly() {
        let mut accumulator = MetricAccumulator::new();
        // Three samples: 15ms, 25ms, 10ms in 100ns units
        accumulator.record_sample(1.0, 150_000, None, 100.0, 50.0, 30.0);
        accumulator.record_sample(2.0, 250_000, None, 100.0, 50.0, 30.0);
        accumulator.record_sample(3.0, 100_000, None, 100.0, 50.0, 30.0);

        assert_eq!(accumulator.sample_count, 3);
        assert_eq!(accumulator.cpu_time_100ns_total, 500_000);
        assert_eq!(accumulator.cpu_time_ms(), 50);
        assert_eq!(accumulator.app_cpu_time_ms(), 50);
    }

    #[test]
    fn test_cpu_time_aggregation_reset_clears_total() {
        let mut accumulator = MetricAccumulator::new();
        accumulator.record_sample(5.0, 10_000_000, None, 100.0, 50.0, 30.0);
        assert_eq!(accumulator.cpu_time_100ns_total, 10_000_000);
        assert_eq!(accumulator.cpu_time_ms(), 1_000);

        accumulator.reset();
        assert_eq!(accumulator.cpu_time_100ns_total, 0);
        assert_eq!(accumulator.cpu_time_ms(), 0);
        assert_eq!(accumulator.sample_count, 0);
    }

    #[test]
    fn test_cpu_time_first_sample_establishes_baseline_and_contributes_zero() {
        let mut prev_instant: Option<Instant> = None;
        let mut prev_proc_time: u64 = 0;
        let mut accumulator = MetricAccumulator::new();

        let now = Instant::now();
        let initial_proc_time = 50_000_000_000u64; // e.g. 5000s existing CPU time

        // Sample 1 (baseline)
        if let Some(prev) = prev_instant {
            let elapsed = now.duration_since(prev);
            let proc_delta = initial_proc_time.saturating_sub(prev_proc_time);
            let proc_cpu = calculate_process_cpu_pct(proc_delta, elapsed, 8);
            accumulator.record_sample(proc_cpu, proc_delta, None, 100.0, 50.0, 30.0);
        }
        prev_proc_time = initial_proc_time;
        prev_instant = Some(now);

        // Baseline established: 0 samples and 0 CPU time in accumulator
        assert_eq!(accumulator.sample_count, 0);
        assert_eq!(accumulator.cpu_time_100ns_total, 0);
        assert_eq!(accumulator.cpu_time_ms(), 0);

        // Sample 2 (1 second later, process used 50ms = 500_000 ticks)
        let later = now + Duration::from_secs(1);
        let sample2_proc_time = initial_proc_time + 500_000;
        if let Some(prev) = prev_instant {
            let elapsed = later.duration_since(prev);
            let proc_delta = sample2_proc_time.saturating_sub(prev_proc_time);
            let proc_cpu = calculate_process_cpu_pct(proc_delta, elapsed, 8);
            accumulator.record_sample(proc_cpu, proc_delta, None, 100.0, 50.0, 30.0);
        }

        assert_eq!(accumulator.sample_count, 1);
        assert_eq!(accumulator.cpu_time_100ns_total, 500_000);
        assert_eq!(accumulator.cpu_time_ms(), 50);
    }

    #[test]
    fn test_cpu_time_failed_sample_does_not_advance_or_corrupt_baseline() {
        let mut prev_proc_time: u64 = 100_000_000;
        let mut accumulator = MetricAccumulator::new();

        // Emulate failed query (get_process_times returns None)
        let query_result: Option<u64> = None;
        if let Some(current_proc_time) = query_result {
            // This block is skipped on failure in monitor.rs
            let proc_delta = current_proc_time.saturating_sub(prev_proc_time);
            accumulator.record_sample(5.0, proc_delta, None, 100.0, 50.0, 30.0);
            prev_proc_time = current_proc_time;
        }

        // Baselines untouched, no accumulation
        assert_eq!(prev_proc_time, 100_000_000);
        assert_eq!(accumulator.sample_count, 0);
        assert_eq!(accumulator.cpu_time_100ns_total, 0);

        // Next sample succeeds: process time is now 120_000_000
        let query_result_2: Option<u64> = Some(120_000_000);
        if let Some(current_proc_time) = query_result_2 {
            let proc_delta = current_proc_time.saturating_sub(prev_proc_time);
            accumulator.record_sample(5.0, proc_delta, None, 100.0, 50.0, 30.0);
            prev_proc_time = current_proc_time;
        }

        // Correct delta computed spanning across the failed tick
        assert_eq!(accumulator.sample_count, 1);
        assert_eq!(accumulator.cpu_time_100ns_total, 20_000_000);
        assert_eq!(accumulator.cpu_time_ms(), 2_000);
        assert_eq!(prev_proc_time, 120_000_000);
    }

    #[test]
    fn test_cpu_time_100ns_to_ms_conversion_truncation_avoidance() {
        let mut accumulator = MetricAccumulator::new();

        // 10 samples of 5_000 100ns units (0.5 ms each)
        // If converted per-sample to integer ms: each sample is 5_000 / 10_000 = 0 ms -> sum = 0 ms (complete loss!)
        // By accumulating raw 100ns: sum = 50_000 100ns -> 50_000 / 10_000 = 5 ms (exact!)
        for _ in 0..10 {
            accumulator.record_sample(1.0, 5_000, None, 100.0, 50.0, 30.0);
        }

        assert_eq!(accumulator.sample_count, 10);
        assert_eq!(accumulator.cpu_time_100ns_total, 50_000);
        assert_eq!(accumulator.cpu_time_ms(), 5);
        assert_eq!(accumulator.app_cpu_time_ms(), 5);
    }
}
