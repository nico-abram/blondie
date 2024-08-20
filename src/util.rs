use std::ffi::OsString;
use std::ptr::addr_of;

use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES,
};
use windows::Win32::System::SystemServices::SE_SYSTEM_PROFILE_NAME;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject, PROCESS_ALL_ACCESS,
};

use crate::{get_last_error, Error, Result};

/// A wrapper around `OpenProcess` that returns a handle with all access rights
pub(crate) fn handle_from_process_id(process_id: u32) -> Result<HANDLE> {
    match unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) } {
        Ok(handle) => Ok(handle),
        Err(_) => Err(get_last_error("handle_from_process_id")),
    }
}

/// Waits for the process for `handle` to end.
///
/// # Safety
///
/// `handle` must not be closed, before or during execution.
pub(crate) unsafe fn wait_for_process_by_handle(handle: HANDLE) -> Result<()> {
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    let ret = WaitForSingleObject(handle, 0xffffffff);
    match ret.0 {
        0 => Ok(()),
        0x00000080 => Err(Error::WaitOnChildErrAbandoned),
        0x00000102 => Err(Error::WaitOnChildErrTimeout),
        _ => Err(get_last_error("wait_for_process_by_handle")),
    }
}

pub(crate) fn acquire_privileges() -> Result<()> {
    let mut privs = TOKEN_PRIVILEGES::default();
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if unsafe {
        LookupPrivilegeValueW(None, SE_SYSTEM_PROFILE_NAME, &mut privs.Privileges[0].Luid).0 == 0
    } {
        return Err(get_last_error("acquire_privileges LookupPrivilegeValueA"));
    }
    let mut pt = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut pt).0 == 0 } {
        return Err(get_last_error("OpenProcessToken"));
    }
    let adjust = unsafe { AdjustTokenPrivileges(pt, false, Some(addr_of!(privs)), 0, None, None) };
    if adjust.0 == 0 {
        let err = Err(get_last_error("AdjustTokenPrivileges"));
        unsafe {
            CloseHandle(pt);
        }
        return err;
    }
    let ret = unsafe { CloseHandle(pt) };
    if ret.0 == 0 {
        return Err(get_last_error("acquire_privileges CloseHandle"));
    }
    let status = unsafe { GetLastError() };
    if status != ERROR_SUCCESS {
        return Err(Error::NotAnAdmin);
    }
    Ok(())
}

/// Returns a sequence of (image_file_path, image_base, image_size)
pub(crate) fn list_kernel_modules() -> Vec<(OsString, u64, u64)> {
    // kernel module enumeration code based on http://www.rohitab.com/discuss/topic/40696-list-loaded-drivers-with-ntquerysysteminformation/
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *mut (),
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    const BUF_LEN: usize = 1024 * 1024;
    let mut out_buf = vec![0u8; BUF_LEN];
    let mut out_size = 0u32;
    // 11 = SystemModuleInformation
    let retcode = unsafe {
        NtQuerySystemInformation(
            11,
            out_buf.as_mut_ptr().cast(),
            BUF_LEN as u32,
            &mut out_size,
        )
    };
    if retcode < 0 {
        // println!("Failed to load kernel modules");
        return vec![];
    }
    let number_of_modules = unsafe { out_buf.as_ptr().cast::<u32>().read_unaligned() as usize };
    #[repr(C)]
    #[derive(Debug)]
    #[allow(non_snake_case)]
    #[allow(non_camel_case_types)]
    struct _RTL_PROCESS_MODULE_INFORMATION {
        Section: *mut std::ffi::c_void,
        MappedBase: *mut std::ffi::c_void,
        ImageBase: *mut std::ffi::c_void,
        ImageSize: u32,
        Flags: u32,
        LoadOrderIndex: u16,
        InitOrderIndex: u16,
        LoadCount: u16,
        OffsetToFileName: u16,
        FullPathName: [u8; 256],
    }
    let modules = unsafe {
        let modules_ptr = out_buf
            .as_ptr()
            .cast::<u32>()
            .offset(2)
            .cast::<_RTL_PROCESS_MODULE_INFORMATION>();
        std::slice::from_raw_parts(modules_ptr, number_of_modules)
    };

    let kernel_module_paths = modules
        .iter()
        .filter_map(|module| {
            std::ffi::CStr::from_bytes_until_nul(&module.FullPathName)
                .unwrap()
                .to_str()
                .ok()
                .map(|mod_str_filepath| {
                    let verbatim_path_osstring: OsString = mod_str_filepath
                        .replacen("\\SystemRoot\\", "\\\\?\\C:\\Windows\\", 1)
                        .into();
                    (
                        verbatim_path_osstring,
                        module.ImageBase as u64,
                        module.ImageSize as u64,
                    )
                })
        })
        .collect();
    kernel_module_paths
}
