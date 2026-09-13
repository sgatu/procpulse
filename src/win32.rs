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
}
