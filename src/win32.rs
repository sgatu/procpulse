use std::ffi::c_void;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FILETIME, HANDLE, INVALID_HANDLE_VALUE, SYSTEMTIME, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::Win32::System::ProcessStatus::{
    K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemTime, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, GetSystemTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};

const SYNCHRONIZE: u32 = 0x00100000;
const PROCESS_NAME_WIN32: u32 = 0;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

unsafe extern "system" {
    fn NtQueryInformationProcess(
        process_handle: *mut c_void,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    fn QueryProcessCycleTime(
        process_handle: HANDLE,
        cycle_time: *mut u64,
    ) -> i32;
}

#[derive(Debug)]
pub struct SafeHandle(HANDLE);

impl SafeHandle {
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    #[inline]
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[inline]
pub fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Attempts to enable SeDebugPrivilege on the current process token.
/// If running as Administrator, this allows querying processes running under SYSTEM or other sessions.
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid = std::mem::zeroed();
        let se_debug_name: [u16; 17] = [
            'S' as u16, 'e' as u16, 'D' as u16, 'e' as u16, 'b' as u16, 'u' as u16, 'g' as u16,
            'P' as u16, 'r' as u16, 'i' as u16, 'v' as u16, 'i' as u16, 'l' as u16, 'e' as u16,
            'g' as u16, 'e' as u16, 0,
        ];

        if LookupPrivilegeValueW(std::ptr::null(), se_debug_name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        CloseHandle(token);
        ok != 0
    }
}

pub fn open_process_for_monitoring(pid: u32) -> Result<SafeHandle, u32> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            pid,
        )
    };
    if let Some(h) = SafeHandle::new(handle) {
        Ok(h)
    } else {
        let err = unsafe { GetLastError() };
        Err(err)
    }
}

pub fn is_process_alive(handle: &SafeHandle) -> bool {
    let status = unsafe { WaitForSingleObject(handle.as_raw(), 0) };
    status == WAIT_TIMEOUT
}

pub fn get_process_full_path(handle: &SafeHandle) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle.as_raw(),
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if ok != 0 && size > 0 {
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    } else {
        None
    }
}

pub fn get_process_command_line(handle: &SafeHandle) -> Result<String, ()> {
    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
    let mut return_length: u32 = 0;

    unsafe {
        NtQueryInformationProcess(
            handle.as_raw() as *mut c_void,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );
    }

    if return_length == 0 {
        return Err(());
    }

    let mut buf = vec![0u8; return_length as usize];
    let status = unsafe {
        NtQueryInformationProcess(
            handle.as_raw() as *mut c_void,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            return_length,
            &mut return_length,
        )
    };

    if status != 0 {
        return Err(());
    }

    let unicode_str = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    let char_len = (unicode_str.length / 2) as usize;
    if char_len == 0 || unicode_str.buffer.is_null() {
        return Ok(String::new());
    }

    let slice = unsafe { std::slice::from_raw_parts(unicode_str.buffer, char_len) };
    Ok(String::from_utf16_lossy(slice))
}

/// Parses and extracts normalized arguments from a full Windows command-line string.
/// Preserves argument ordering and values while separating out the executable image token.
pub fn extract_arguments(full_cmd: &str) -> String {
    let trimmed = full_cmd.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with('"') {
        // Find the matching closing quote
        if let Some(close_idx) = trimmed[1..].find('"') {
            let after_exe = &trimmed[close_idx + 2..];
            after_exe.trim().to_string()
        } else {
            // Malformed quotes, fallback to returning as is
            String::new()
        }
    } else {
        // Space-separated executable
        if let Some(space_idx) = trimmed.find(char::is_whitespace) {
            let after_exe = &trimmed[space_idx..];
            after_exe.trim().to_string()
        } else {
            // Only the executable name was passed, no arguments
            String::new()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessTimes {
    pub kernel_time: u64,
    pub user_time: u64,
}

impl ProcessTimes {
    #[inline]
    pub fn total(&self) -> u64 {
        self.kernel_time.wrapping_add(self.user_time)
    }
}

pub fn get_process_times(handle: &SafeHandle) -> Option<ProcessTimes> {
    let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };

    let ok = unsafe {
        GetProcessTimes(
            handle.as_raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };

    if ok != 0 {
        Some(ProcessTimes {
            kernel_time: filetime_to_u64(kernel),
            user_time: filetime_to_u64(user),
        })
    } else {
        None
    }
}

/// Queries the cumulative CPU cycle count consumed by all threads in the process.
/// Returns None if the call fails (e.g. process exiting or insufficient access).
pub fn get_process_cycle_time(handle: &SafeHandle) -> Option<u64> {
    let mut cycles: u64 = 0;
    let ok = unsafe { QueryProcessCycleTime(handle.as_raw(), &mut cycles) };
    if ok != 0 {
        Some(cycles)
    } else {
        None
    }
}

#[repr(C)]
struct ProcessMemoryCountersEx2 {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_usage: usize,
    private_working_set_size: usize,
    shared_commit_usage: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessMemory {
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub private_active_bytes: u64,
}

pub fn get_process_memory(handle: &SafeHandle) -> Option<ProcessMemory> {
    let mut mem2: ProcessMemoryCountersEx2 = unsafe { std::mem::zeroed() };
    mem2.cb = std::mem::size_of::<ProcessMemoryCountersEx2>() as u32;

    let ok = unsafe {
        K32GetProcessMemoryInfo(
            handle.as_raw(),
            &mut mem2 as *mut _ as *mut _,
            mem2.cb,
        )
    };

    if ok != 0 {
        let priv_active = if mem2.private_working_set_size > 0 {
            mem2.private_working_set_size as u64
        } else {
            mem2.private_usage as u64
        };

        Some(ProcessMemory {
            working_set_bytes: mem2.working_set_size as u64,
            private_bytes: mem2.private_usage as u64,
            private_active_bytes: priv_active,
        })
    } else {
        // Fallback for older Windows if EX2 fails
        let mut mem_counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS_EX>::uninit();
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let ok = unsafe {
            K32GetProcessMemoryInfo(
                handle.as_raw(),
                mem_counters.as_mut_ptr() as *mut _,
                size,
            )
        };
        if ok != 0 {
            let counters = unsafe { mem_counters.assume_init() };
            Some(ProcessMemory {
                working_set_bytes: counters.WorkingSetSize as u64,
                private_bytes: counters.PrivateUsage as u64,
                private_active_bytes: counters.PrivateUsage as u64,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemTimes {
    pub idle_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
}

impl SystemTimes {
    #[allow(dead_code)]
    #[inline]
    pub fn total(&self) -> u64 {
        // On Windows, kernel_time already includes idle_time.
        // Total scheduler time across all processors = kernel_time + user_time.
        self.kernel_time.wrapping_add(self.user_time)
    }
}

pub fn get_system_times() -> Option<SystemTimes> {
    let mut idle = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };

    let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    if ok != 0 {
        Some(SystemTimes {
            idle_time: filetime_to_u64(idle),
            kernel_time: filetime_to_u64(kernel),
            user_time: filetime_to_u64(user),
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemMemory {
    pub total_phys_bytes: u64,
    pub avail_phys_bytes: u64,
}

impl SystemMemory {
    #[inline]
    pub fn used_phys_bytes(&self) -> u64 {
        self.total_phys_bytes.saturating_sub(self.avail_phys_bytes)
    }
}

pub fn get_system_memory() -> Option<SystemMemory> {
    let mut mem_status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };

    let ok = unsafe { GlobalMemoryStatusEx(&mut mem_status) };
    if ok != 0 {
        Some(SystemMemory {
            total_phys_bytes: mem_status.ullTotalPhys,
            avail_phys_bytes: mem_status.ullAvailPhys,
        })
    } else {
        None
    }
}

pub fn get_system_time_utc_string() -> String {
    let mut st = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    unsafe { GetSystemTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

#[derive(Debug)]
pub struct ProcessSnapshotEntry {
    pub pid: u32,
    pub exe_name: String,
}

pub fn enumerate_processes() -> Vec<ProcessSnapshotEntry> {
    let mut results = Vec::with_capacity(256);
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return results;
    }

    let mut entry = std::mem::MaybeUninit::<PROCESSENTRY32W>::zeroed();
    unsafe {
        (*entry.as_mut_ptr()).dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    }

    let mut has_next = unsafe { Process32FirstW(snapshot, entry.as_mut_ptr()) };
    while has_next != 0 {
        let p_entry = unsafe { entry.assume_init() };
        let len = p_entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(p_entry.szExeFile.len());
        let name = String::from_utf16_lossy(&p_entry.szExeFile[..len]);

        results.push(ProcessSnapshotEntry {
            pid: p_entry.th32ProcessID,
            exe_name: name,
        });

        has_next = unsafe { Process32NextW(snapshot, entry.as_mut_ptr()) };
    }

    unsafe { CloseHandle(snapshot) };
    results
}

pub const MAX_TRACKED_SLOTS: usize = 32;

pub const KERNEL_NETWORK_PROVIDER_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x7dd42a49,
    data2: 0x5329,
    data3: 0x4832,
    data4: [0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88],
};

#[repr(C, align(64))]
pub struct NetCounterSlot {
    pub pid: std::sync::atomic::AtomicU32,
    pub rx_bytes: std::sync::atomic::AtomicU64,
    pub tx_bytes: std::sync::atomic::AtomicU64,
}

impl Default for NetCounterSlot {
    fn default() -> Self {
        Self {
            pid: std::sync::atomic::AtomicU32::new(0),
            rx_bytes: std::sync::atomic::AtomicU64::new(0),
            tx_bytes: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

pub struct SharedNetState {
    pub slots: [NetCounterSlot; MAX_TRACKED_SLOTS],
}

impl Default for SharedNetState {
    fn default() -> Self {
        const INIT_SLOT: NetCounterSlot = NetCounterSlot {
            pid: std::sync::atomic::AtomicU32::new(0),
            rx_bytes: std::sync::atomic::AtomicU64::new(0),
            tx_bytes: std::sync::atomic::AtomicU64::new(0),
        };
        Self {
            slots: [INIT_SLOT; MAX_TRACKED_SLOTS],
        }
    }
}

impl SharedNetState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim_slot(&self, pid: u32) -> Option<usize> {
        if pid == 0 {
            return None;
        }
        // If already claimed for this PID, return existing slot
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.pid.load(std::sync::atomic::Ordering::Relaxed) == pid {
                return Some(i);
            }
        }
        // Find first free slot (pid == 0)
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.pid.compare_exchange(
                0,
                pid,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ).is_ok() {
                slot.rx_bytes.store(0, std::sync::atomic::Ordering::Release);
                slot.tx_bytes.store(0, std::sync::atomic::Ordering::Release);
                return Some(i);
            }
        }
        None
    }

    pub fn drain_slot(&self, slot_idx: usize) -> (u64, u64) {
        if slot_idx >= MAX_TRACKED_SLOTS {
            return (0, 0);
        }
        let slot = &self.slots[slot_idx];
        let rx = slot.rx_bytes.swap(0, std::sync::atomic::Ordering::AcqRel);
        let tx = slot.tx_bytes.swap(0, std::sync::atomic::Ordering::AcqRel);
        (rx, tx)
    }

    pub fn release_slot(&self, slot_idx: usize) -> (u64, u64) {
        if slot_idx >= MAX_TRACKED_SLOTS {
            return (0, 0);
        }
        let slot = &self.slots[slot_idx];
        let rx = slot.rx_bytes.swap(0, std::sync::atomic::Ordering::AcqRel);
        let tx = slot.tx_bytes.swap(0, std::sync::atomic::Ordering::AcqRel);
        slot.pid.store(0, std::sync::atomic::Ordering::Release);
        (rx, tx)
    }

    #[inline]
    pub fn record_traffic(&self, pid: u32, rx_delta: u64, tx_delta: u64) {
        if pid == 0 || (rx_delta == 0 && tx_delta == 0) {
            return;
        }
        for slot in &self.slots {
            if slot.pid.load(std::sync::atomic::Ordering::Relaxed) == pid {
                if rx_delta > 0 {
                    slot.rx_bytes.fetch_add(rx_delta, std::sync::atomic::Ordering::Relaxed);
                }
                if tx_delta > 0 {
                    slot.tx_bytes.fetch_add(tx_delta, std::sync::atomic::Ordering::Relaxed);
                }
                return;
            }
        }
    }
}

pub fn str_to_utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_trace_properties_buf(session_name_u16: &[u16]) -> Vec<u8> {
    let name_bytes = session_name_u16.len() * std::mem::size_of::<u16>();
    let total_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + 256;
    let mut buf = vec![0u8; total_size];
    unsafe {
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).BufferSize = 64; // 64 KB buffers
        (*props).MinimumBuffers = 4;
        (*props).MaximumBuffers = 16;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*props).LogFileNameOffset = 0;
    }
    buf
}

pub fn stop_session_by_name(session_name_u16: &[u16]) {
    let mut buf = create_trace_properties_buf(session_name_u16);
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            session_name_u16.as_ptr(),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelNetIpv4Prefix {
    pub pid: u32,
    pub size: u32,
    pub daddr: [u8; 4],
    pub saddr: [u8; 4],
    pub dport: u16,
    pub sport: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelNetIpv6Prefix {
    pub pid: u32,
    pub size: u32,
    pub daddr: [u8; 16],
    pub saddr: [u8; 16],
    pub dport: u16,
    pub sport: u16,
}

#[inline]
pub fn is_ipv6_loopback(addr: &[u8]) -> bool {
    const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    if addr == IPV6_LOOPBACK {
        return true;
    }
    // Check IPv4-mapped IPv6 loopback: ::ffff:127.x.x.x
    const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    if addr.starts_with(&IPV4_MAPPED_PREFIX) && addr[12] == 127 {
        return true;
    }
    false
}

#[inline]
pub fn is_loopback(event_id: u16, user_data: *const u8, data_len: usize) -> bool {
    match event_id {
        // IPv4 events: 10 (TCP send), 11 (TCP recv), 42 (UDP send), 43 (UDP recv)
        10 | 11 | 42 | 43 => {
            if data_len < std::mem::size_of::<KernelNetIpv4Prefix>() {
                return false;
            }
            let hdr = unsafe { std::ptr::read_unaligned(user_data as *const KernelNetIpv4Prefix) };
            hdr.daddr[0] == 127 || hdr.saddr[0] == 127
        }
        // IPv6 events: 26 (TCP send), 27 (TCP recv), 58 (UDP send), 59 (UDP recv)
        26 | 27 | 58 | 59 => {
            if data_len < std::mem::size_of::<KernelNetIpv6Prefix>() {
                return false;
            }
            let hdr = unsafe { std::ptr::read_unaligned(user_data as *const KernelNetIpv6Prefix) };
            is_ipv6_loopback(&hdr.daddr) || is_ipv6_loopback(&hdr.saddr)
        }
        _ => false,
    }
}

unsafe extern "system" fn etw_event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = unsafe { &*event_record };

    // Validate schema version: Microsoft-Windows-Kernel-Network publishes Version 0.
    // If an unknown future schema version is encountered, ignore it safely.
    if record.EventHeader.EventDescriptor.Version != 0 {
        return;
    }

    let event_id = record.EventHeader.EventDescriptor.Id;

    // Send: 10 (TCPv4), 26 (TCPv6), 42 (UDPv4), 58 (UDPv6)
    // Recv: 11 (TCPv4), 27 (TCPv6), 43 (UDPv4), 59 (UDPv6)
    let is_send = match event_id {
        10 | 26 | 42 | 58 => true,
        11 | 27 | 43 | 59 => false,
        _ => return,
    };

    let user_data = record.UserData as *const u8;
    let data_len = record.UserDataLength as usize;

    if user_data.is_null() || data_len < 8 {
        return;
    }

    // Ignore loopback traffic (127.0.0.0/8, ::1, ::ffff:127.x.x.x)
    if is_loopback(event_id, user_data, data_len) {
        return;
    }

    let pid = unsafe { std::ptr::read_unaligned(user_data as *const u32) };
    let size = unsafe { std::ptr::read_unaligned(user_data.add(4) as *const u32) as u64 };

    if record.UserContext.is_null() {
        return;
    }
    let shared_net = unsafe { &*(record.UserContext as *const SharedNetState) };
    if is_send {
        shared_net.record_traffic(pid, 0, size);
    } else {
        shared_net.record_traffic(pid, size, 0);
    }
}

pub struct EtwNetworkSession {
    session_name_u16: Vec<u16>,
    trace_handle: PROCESSTRACE_HANDLE,
    worker_thread: Option<std::thread::JoinHandle<()>>,
    #[allow(dead_code)]
    shared_net: std::sync::Arc<SharedNetState>,
}

impl EtwNetworkSession {
    pub fn start(shared_net: std::sync::Arc<SharedNetState>) -> Result<Self, u32> {
        let session_name = format!("procpulse_net_{}", std::process::id());
        let session_name_u16 = str_to_utf16_null(&session_name);

        // Stop any leftover session with this name first
        stop_session_by_name(&session_name_u16);

        let mut buf = create_trace_properties_buf(&session_name_u16);
        let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };

        let status = unsafe {
            StartTraceW(
                &mut session_handle,
                session_name_u16.as_ptr(),
                buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            )
        };

        if status != 0 {
            return Err(status);
        }

        // Enable Microsoft-Windows-Kernel-Network provider
        // Keywords: 0x10 (IPv4) | 0x20 (IPv6) = 0x30
        // Level: 4 (TRACE_LEVEL_INFORMATION)
        let enable_status = unsafe {
            EnableTraceEx2(
                session_handle,
                &KERNEL_NETWORK_PROVIDER_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                4,
                0x30,
                0,
                0,
                std::ptr::null(),
            )
        };

        if enable_status != 0 {
            stop_session_by_name(&session_name_u16);
            return Err(enable_status);
        }

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = session_name_u16.as_ptr() as *mut u16;
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);
        logfile.Context = &*shared_net as *const SharedNetState as *mut c_void;

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX || trace_handle.Value == 0 {
            let err = unsafe { GetLastError() };
            stop_session_by_name(&session_name_u16);
            return Err(if err != 0 { err } else { 1 });
        }

        let worker_handle = trace_handle;
        let worker_thread = std::thread::Builder::new()
            .name("procpulse-etw".to_string())
            .spawn(move || {
                let handle = worker_handle;
                unsafe {
                    ProcessTrace(&handle, 1, std::ptr::null(), std::ptr::null());
                }
            })
            .ok();

        Ok(Self {
            session_name_u16,
            trace_handle,
            worker_thread,
            shared_net,
        })
    }

    pub fn shutdown(&mut self) {
        if self.trace_handle.Value != u64::MAX && self.trace_handle.Value != 0 {
            unsafe { CloseTrace(self.trace_handle) };
            self.trace_handle = PROCESSTRACE_HANDLE { Value: 0 };
        }

        stop_session_by_name(&self.session_name_u16);

        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EtwNetworkSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_arguments_with_quotes() {
        assert_eq!(
            extract_arguments(r#""C:\Program Files\App\MyApplication.exe" --server alpha --port 8001"#),
            "--server alpha --port 8001"
        );
        assert_eq!(
            extract_arguments(r#""MyApplication.exe""#),
            ""
        );
        assert_eq!(
            extract_arguments(r#""MyApplication.exe"   --arg 1   "#),
            "--arg 1"
        );
    }

    #[test]
    fn test_extract_arguments_without_quotes() {
        assert_eq!(
            extract_arguments("MyApplication.exe --server beta"),
            "--server beta"
        );
        assert_eq!(
            extract_arguments("MyApplication.exe"),
            ""
        );
    }

    #[test]
    fn test_utc_string_format() {
        let s = get_system_time_utc_string();
        assert_eq!(s.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
        assert!(s.ends_with('Z'));
        assert_eq!(&s[10..11], "T");
    }

    #[test]
    fn test_shared_net_state_claim_and_drain() {
        let state = SharedNetState::new();
        let slot = state.claim_slot(1234).expect("claim slot");
        assert_eq!(state.drain_slot(slot), (0, 0));

        state.record_traffic(1234, 1000, 500);
        state.record_traffic(1234, 250, 750);

        let (rx, tx) = state.drain_slot(slot);
        assert_eq!(rx, 1250);
        assert_eq!(tx, 1250);

        // After drain, should be 0
        assert_eq!(state.drain_slot(slot), (0, 0));
    }

    #[test]
    fn test_shared_net_state_untracked_ignored() {
        let state = SharedNetState::new();
        let slot = state.claim_slot(1000).expect("claim slot");

        // Traffic for PID 9999 (untracked)
        state.record_traffic(9999, 5000, 2000);

        // Tracked slot 1000 unaffected
        assert_eq!(state.drain_slot(slot), (0, 0));
    }

    #[test]
    fn test_shared_net_state_release_clears_pid() {
        let state = SharedNetState::new();
        let slot = state.claim_slot(2000).expect("claim slot");
        state.record_traffic(2000, 400, 300);

        let (rx, tx) = state.release_slot(slot);
        assert_eq!(rx, 400);
        assert_eq!(tx, 300);

        // After release, slot pid is 0, future traffic to 2000 is ignored
        state.record_traffic(2000, 100, 100);
        assert_eq!(state.drain_slot(slot), (0, 0));
    }

    #[test]
    fn test_shared_net_state_multiple_pids() {
        let state = SharedNetState::new();
        let slot1 = state.claim_slot(1001).expect("slot 1");
        let slot2 = state.claim_slot(1002).expect("slot 2");

        state.record_traffic(1001, 100, 200);
        state.record_traffic(1002, 300, 400);

        assert_eq!(state.drain_slot(slot1), (100, 200));
        assert_eq!(state.drain_slot(slot2), (300, 400));
    }

    #[test]
    fn test_shared_net_state_large_u64_preserves_precision() {
        let state = SharedNetState::new();
        let slot = state.claim_slot(3000).expect("claim slot");

        let large_rx: u64 = 100_000_000_000;
        let large_tx: u64 = 50_000_000_000;
        state.record_traffic(3000, large_rx, large_tx);

        assert_eq!(state.drain_slot(slot), (large_rx, large_tx));
    }

    #[test]
    fn test_is_loopback_ipv4() {
        // Layout: [pid: 4B, size: 4B, daddr: 4B, saddr: 4B, dport: 2B, sport: 2B, seq: 4B, connid: 4B] = 28 bytes
        let mut buf_loopback = [0u8; 28];
        buf_loopback[8] = 127; // daddr = 127.0.0.1
        buf_loopback[11] = 1;
        assert!(is_loopback(10, buf_loopback.as_ptr(), 28));
        assert!(is_loopback(11, buf_loopback.as_ptr(), 28));

        let mut buf_external = [0u8; 28];
        buf_external[8] = 192; // daddr = 192.168.1.1
        buf_external[9] = 168;
        buf_external[12] = 10;  // saddr = 10.0.0.1
        assert!(!is_loopback(10, buf_external.as_ptr(), 28));
        assert!(!is_loopback(11, buf_external.as_ptr(), 28));
        assert!(!is_loopback(42, buf_external.as_ptr(), 28));
        assert!(!is_loopback(43, buf_external.as_ptr(), 28));
    }

    #[test]
    fn test_is_loopback_ipv6() {
        // Layout: [pid: 4B, size: 4B, daddr: 16B, saddr: 16B, dport: 2B, sport: 2B, seq: 4B, connid: 4B] = 52 bytes
        let mut buf_loopback = [0u8; 52];
        buf_loopback[23] = 1; // daddr = ::1
        assert!(is_loopback(26, buf_loopback.as_ptr(), 52));
        assert!(is_loopback(27, buf_loopback.as_ptr(), 52));
        assert!(is_loopback(58, buf_loopback.as_ptr(), 52));
        assert!(is_loopback(59, buf_loopback.as_ptr(), 52));

        let mut buf_external = [0u8; 52];
        buf_external[8] = 0x20; // 2001:db8::
        buf_external[9] = 0x01;
        assert!(!is_loopback(26, buf_external.as_ptr(), 52));
        assert!(!is_loopback(27, buf_external.as_ptr(), 52));
    }

    #[test]
    fn test_schema_offsets_match_manifest() {
        use std::mem::offset_of;
        // IPv4 layout matches manifest: PID(0), size(4), daddr(8), saddr(12), dport(16), sport(18)
        assert_eq!(offset_of!(KernelNetIpv4Prefix, pid), 0);
        assert_eq!(offset_of!(KernelNetIpv4Prefix, size), 4);
        assert_eq!(offset_of!(KernelNetIpv4Prefix, daddr), 8);
        assert_eq!(offset_of!(KernelNetIpv4Prefix, saddr), 12);
        assert_eq!(offset_of!(KernelNetIpv4Prefix, dport), 16);
        assert_eq!(offset_of!(KernelNetIpv4Prefix, sport), 18);
        assert_eq!(std::mem::size_of::<KernelNetIpv4Prefix>(), 20);

        // IPv6 layout matches manifest: PID(0), size(4), daddr(8), saddr(24), dport(40), sport(42)
        assert_eq!(offset_of!(KernelNetIpv6Prefix, pid), 0);
        assert_eq!(offset_of!(KernelNetIpv6Prefix, size), 4);
        assert_eq!(offset_of!(KernelNetIpv6Prefix, daddr), 8);
        assert_eq!(offset_of!(KernelNetIpv6Prefix, saddr), 24);
        assert_eq!(offset_of!(KernelNetIpv6Prefix, dport), 40);
        assert_eq!(offset_of!(KernelNetIpv6Prefix, sport), 42);
        assert_eq!(std::mem::size_of::<KernelNetIpv6Prefix>(), 44);
    }
}

