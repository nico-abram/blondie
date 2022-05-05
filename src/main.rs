use windows::core::{GUID, PCSTR, PSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, CHAR, DBG_CONTINUE, DUPLICATE_SAME_ACCESS,
    ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES,
};
use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleA, FILE_NAME};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcessStop, SymFromAddr, SymGetModuleInfo64, SymGetOptions,
    SymInitialize, SymLoadModuleEx, SymRefreshModuleList, SymSetOptions, WaitForDebugEvent,
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, DEBUG_SYMBOL_IS_ARGUMENT, EXIT_PROCESS_DEBUG_EVENT,
    IMAGEHLP_MODULE64, LOAD_DLL_DEBUG_EVENT, SYMBOL_INFO, SYMBOL_INFO_FLAGS, SYMOPT_DEBUG,
    SYM_LOAD_FLAGS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA, SystemTraceControlGuid,
    TraceSampledProfileIntervalInfo, TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_LOGFILEA,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, KERNEL_LOGGER_NAMEA,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_PROFILE_INTERVAL, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::SystemServices::{SE_DEBUG_NAME, SE_SYSTEM_PROFILE_NAME};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, OpenProcess,
    OpenProcessToken, SetThreadPriority, CREATE_SUSPENDED, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS,
    PROCESS_ALL_ACCESS, THREAD_PRIORITY_TIME_CRITICAL,
};
use windows::Win32::System::WindowsProgramming::INFINITE;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::mem::size_of;
use std::os::windows::prelude::AsRawHandle;
use std::ptr::{addr_of, addr_of_mut, null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static TARGET_PROC: AtomicU32 = AtomicU32::new(0);
static TRACE_RUNNING: AtomicBool = AtomicBool::new(false);
//const MAX_STACK_DEPTH: usize = 192;
const MAX_STACK_DEPTH: usize = 200;

unsafe fn panic_with_err() {
    use windows::Win32::System::Diagnostics::Debug::{
        FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    let mut buf = [0u8; 1024];
    let code = GetLastError();
    let chars_written = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        null_mut(),
        code.0,
        0,
        PSTR(buf.as_mut_ptr()),
        buf.len() as u32,
        null_mut(),
    );
    assert!(chars_written != 0);
    panic!("{:X?}:{}", code.0, std::str::from_utf8(&buf).unwrap());
}
unsafe fn CloneHandle(h: HANDLE) -> HANDLE {
    let mut target_h = HANDLE::default();
    let ret = DuplicateHandle(
        GetCurrentProcess(),
        h,
        GetCurrentProcess(),
        &mut target_h,
        0,
        false,
        DUPLICATE_SAME_ACCESS,
    );
    if ret.0 == 0 {
        panic_with_err();
    }
    target_h
}
unsafe fn create_suspended() -> (u32, HANDLE, std::process::Child) {
    use std::os::windows::process::CommandExt;

    let mut args = std::env::args_os().skip(1);
    let arg1 = args
        .next()
        .expect("Expected command to run.\nUSAGE: winstack.exe [command] [command args...]");

    // Create the target process suspended
    let mut proc = std::process::Command::new(arg1)
        .args(&args.collect::<Vec<_>>())
        .creation_flags(
            //CREATE_SUSPENDED.0,
            DEBUG_PROCESS.0 | DEBUG_ONLY_THIS_PROCESS.0,
        )
        .spawn()
        .unwrap();
    let target_pid = proc.id();
    // std Child closes the handle when it drops so we clone it
    let target_p_h = CloneHandle(HANDLE(proc.as_raw_handle() as isize));
    (target_pid, target_p_h, proc)
}
unsafe fn unmain() {
    // First we adjust our privileges to the ones we need

    #[repr(C)]
    #[derive(Default)]
    pub struct TOKEN_PRIVILEGES2 {
        pub PrivilegeCount: u32,
        pub Privileges: [LUID_AND_ATTRIBUTES; 2],
    }
    let mut privs = TOKEN_PRIVILEGES2::default();
    privs.PrivilegeCount = 2;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    privs.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    if LookupPrivilegeValueA(
        PCSTR(null_mut()),
        PCSTR(
            SE_SYSTEM_PROFILE_NAME
                .as_bytes()
                .iter()
                .cloned()
                .chain(Some(0))
                .collect::<Vec<u8>>()
                .as_ptr()
                .into(),
        ),
        &mut privs.Privileges[0].Luid,
    )
    .0 == 0
    {
        panic_with_err();
    }
    if LookupPrivilegeValueA(
        PCSTR(null_mut()),
        PCSTR(
            SE_DEBUG_NAME
                .as_bytes()
                .iter()
                .cloned()
                .chain(Some(0))
                .collect::<Vec<u8>>()
                .as_ptr()
                .into(),
        ),
        &mut privs.Privileges[1].Luid,
    )
    .0 == 0
    {
        panic_with_err();
    }

    let mut pt = HANDLE::default();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut pt).0 == 0 {
        panic_with_err();
    }
    let adjust =
        AdjustTokenPrivileges(pt, false, addr_of!(privs).cast(), 0, null_mut(), null_mut());
    CloseHandle(pt);
    if adjust.0 == 0 {
        panic_with_err();
    }
    let status = GetLastError();
    if status != ERROR_SUCCESS {
        println!("ERROR: winstacks requires running as administrator.");
        std::process::exit(-1);
    }

    // Set the sampling interval
    let mut interval = TRACE_PROFILE_INTERVAL::default();
    interval.Interval = (1000000000 / 8000) / 100;
    TraceSetInformation(
        0,
        TraceSampledProfileIntervalInfo,
        addr_of!(interval).cast(),
        size_of::<TRACE_PROFILE_INTERVAL>() as u32,
    );

    let mut kernel_logger_name_with_nul = KERNEL_LOGGER_NAMEA
        .as_bytes()
        .iter()
        .cloned()
        .chain(Some(0))
        .collect::<Vec<u8>>();
    // Build the trace properties, we want EVENT_TRACE_FLAG_PROFILE for the "SampledProfile" event
    // https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile
    // In https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes that event is listed as a "kernel event"
    // And https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants says
    // "The NT Kernel Logger session is the only session that can accept events from kernel event providers."
    // Therefore we must use GUID SystemTraceControlGuid/KERNEL_LOGGER_NAME as the session
    // EVENT_TRACE_REAL_TIME_MODE:
    //  Events are delivered when the buffers are flushed (https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() + KERNEL_LOGGER_NAMEA.len() + 1;
    #[derive(Clone)]
    #[repr(C, packed)]
    struct EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: EVENT_TRACE_PROPERTIES,
        s: [u8; KERNEL_LOGGER_NAMEA.len() + 1],
    }
    let mut event_trace_props = EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: std::mem::zeroed(),
        s: [0u8; KERNEL_LOGGER_NAMEA.len() + 1],
    };
    event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE;
    event_trace_props.data.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    event_trace_props.data.Wnode.BufferSize = PROPS_SIZE as u32;
    event_trace_props.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    event_trace_props.data.Wnode.ClientContext = 1; //Or 3?
    event_trace_props.data.Wnode.Guid = SystemTraceControlGuid;
    event_trace_props.data.BufferSize = 1024;
    let core_count = std::thread::available_parallelism().unwrap();
    event_trace_props.data.MinimumBuffers = core_count.get() as u32 * 4;
    event_trace_props.data.MaximumBuffers = core_count.get() as u32 * 6;
    event_trace_props.data.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    event_trace_props
        .s
        .copy_from_slice(&kernel_logger_name_with_nul[..]);

    let kernel_logger_name_with_nul_pcstr = PCSTR(kernel_logger_name_with_nul.as_ptr());
    // Stop an existing session with the kernel logger, if it exists
    // We use a copy since ControlTrace overwrites it
    let mut event_trace_props_copy = event_trace_props.clone();
    let control_stop_retcode = ControlTraceA(
        0,
        kernel_logger_name_with_nul_pcstr,
        addr_of_mut!(event_trace_props_copy) as *mut _,
        EVENT_TRACE_CONTROL_STOP,
    );
    if control_stop_retcode != ERROR_SUCCESS.0
        && control_stop_retcode != ERROR_WMI_INSTANCE_NOT_FOUND.0
    {
        panic_with_err();
    }

    let mut trace_session_handle = 0;
    let start_retcode = StartTraceA(
        &mut trace_session_handle,
        kernel_logger_name_with_nul_pcstr,
        addr_of_mut!(event_trace_props) as *mut _,
    );
    if start_retcode != ERROR_SUCCESS.0 {
        panic_with_err();
    }

    // Enable stack tracing
    let mut stackId = CLASSIC_EVENT_ID::default();
    // GUID from https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
    let perfinfo_guid = GUID {
        data1: 0xce1dbfb4,
        data2: 0x137e,
        data3: 0x4da6,
        data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
    };
    stackId.EventGuid = perfinfo_guid;
    stackId.Type = 46; // Sampled profile event
    let enable_stacks_retcode = TraceSetInformation(
        trace_session_handle,
        TraceStackTracingInfo,
        addr_of!(stackId).cast(),
        size_of::<CLASSIC_EVENT_ID>() as u32,
    );
    if enable_stacks_retcode != ERROR_SUCCESS.0 {
        panic_with_err();
    }

    type StackMap = rustc_hash::FxHashMap<[u64; MAX_STACK_DEPTH], u64>;
    let mut stack_counts = StackMap::default();
    let mut log = EVENT_TRACE_LOGFILEA::default();
    log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.Context = addr_of_mut!(stack_counts).cast();

    // Create target process
    let (target_pid, target_p_h, mut proc) = create_suspended();
    TARGET_PROC.store(target_pid, Ordering::Relaxed);

    unsafe extern "system" fn EventRecordCallback(record: *mut EVENT_RECORD) {
        TRACE_RUNNING.store(true, Ordering::Relaxed);

        let provider_guid_data1 = (*record).EventHeader.ProviderId.data1;
        let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;
        // From https://docs.microsoft.com/en-us/windows/win32/etw/stackwalk
        let stackwalk_guid_data1 = 0xdef2fe46;
        let stackwalk_event_type = 32;
        if event_opcode != stackwalk_event_type || stackwalk_guid_data1 != provider_guid_data1 {
            return;
        }
        let ud_p = (*record).UserData;
        let _timestamp = ud_p.cast::<u64>().read_unaligned();
        let proc = ud_p.cast::<u32>().offset(2).read_unaligned();
        let _thread = ud_p.cast::<u32>().offset(3).read_unaligned();
        if proc != TARGET_PROC.load(Ordering::Relaxed) {
            return;
        }

        let stack_depth_32 = ((*record).UserDataLength - 16) / 4;
        let stack_depth_64 = stack_depth_32 / 2;
        let mut stack = [0u64; MAX_STACK_DEPTH];
        let mut stack_addrs =
            std::slice::from_raw_parts(ud_p.cast::<u64>().offset(2), stack_depth_64 as usize);
        if stack_addrs.len() > MAX_STACK_DEPTH {
            stack_addrs = &stack_addrs[(stack_addrs.len() - MAX_STACK_DEPTH)..];
        }
        stack[..(stack_depth_64 as usize).min(MAX_STACK_DEPTH)].copy_from_slice(stack_addrs);

        let stack_map = &mut *(*record).UserContext.cast::<StackMap>();
        let entry = stack_map.entry(stack);
        *entry.or_insert(0) += 1;
    }
    log.Anonymous2.EventRecordCallback = Some(EventRecordCallback);

    let trace_processing_handle = OpenTraceA(&mut log);
    if trace_processing_handle == INVALID_HANDLE_VALUE.0 as u64 {
        panic_with_err();
    }

    let (sender, recvr) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // This blocks
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        ProcessTrace(&[trace_processing_handle], null_mut(), null_mut());

        let ret = CloseTrace(trace_processing_handle);
        if ret != ERROR_SUCCESS.0 {
            panic_with_err();
        }
        sender.send(()).unwrap();
    });

    // Wait until we know for sure the trace is running
    while !TRACE_RUNNING.load(Ordering::Relaxed) {
        std::hint::spin_loop();
    }
    // This resumes the process
    /*
     */
    let mut debug_event = DEBUG_EVENT::default();
    let ret = WaitForDebugEvent(&mut debug_event, INFINITE);
    if ret.0 == 0 {
        panic_with_err();
    }
    assert!(debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT);
    SymSetOptions(SymGetOptions() | SYMOPT_DEBUG);
    let ret = SymInitialize(target_p_h, PCSTR(null_mut()), false);
    if ret.0 != 1 {
        panic_with_err();
    }
    let image_file_h = debug_event.u.CreateProcessInfo.hFile;

    let mut buf = [0u8; 1024];
    let ret = GetFinalPathNameByHandleA(image_file_h, &mut buf[..], FILE_NAME(0));
    let filename_p = PCSTR(if ret != 0 && (ret as usize) < buf.len() {
        buf.as_ptr()
    } else {
        null()
    });
    let ret = SymLoadModuleEx(
        target_p_h,
        image_file_h,
        filename_p,
        PCSTR(null_mut()),
        debug_event.u.CreateProcessInfo.lpBaseOfImage as u64,
        0,
        null_mut(),
        SYM_LOAD_FLAGS(0),
    );
    let base = debug_event.u.CreateProcessInfo.lpBaseOfImage;
    println!("lpBaseOfImage:{base:?}");
    if ret == 0 {
        panic_with_err();
    }
    SymRefreshModuleList(target_p_h);
    CloseHandle(image_file_h);
    let ret = ContinueDebugEvent(
        debug_event.dwProcessId,
        debug_event.dwThreadId,
        DBG_CONTINUE.0 as u32,
    );
    if ret.0 == 0 {
        panic_with_err();
    }
    loop {
        let mut debug_event = DEBUG_EVENT::default();
        let ret = WaitForDebugEvent(&mut debug_event, INFINITE);
        if ret.0 == 0 {
            panic_with_err();
        }
        match debug_event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => panic!(),
            LOAD_DLL_DEBUG_EVENT => {
                let image_file_h = debug_event.u.LoadDll.hFile;

                let mut buf = [0u8; 1024];
                let ret = GetFinalPathNameByHandleA(image_file_h, &mut buf[..], FILE_NAME(0));
                let filename_p = PCSTR(if ret != 0 && (ret as usize) < buf.len() {
                    buf.as_ptr()
                } else {
                    null()
                });
                let ret = SymLoadModuleEx(
                    target_p_h,
                    image_file_h,
                    filename_p,
                    PCSTR(null_mut()),
                    debug_event.u.LoadDll.lpBaseOfDll as u64,
                    0,
                    null_mut(),
                    SYM_LOAD_FLAGS(0),
                );
                let base = debug_event.u.LoadDll.lpBaseOfDll;
                println!("lpBaseOfDll:{base:?}");
                if ret == 0 {
                    panic_with_err();
                }
                SymRefreshModuleList(target_p_h);
                CloseHandle(image_file_h);
            }
            EXIT_PROCESS_DEBUG_EVENT => break,
            _ => {}
        }

        let ret = ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            DBG_CONTINUE.0 as u32,
        );
        if ret.0 == 0 {
            panic_with_err();
        }
    }
    let ret = DebugActiveProcessStop(target_pid);
    if ret.0 == 0 {
        panic_with_err();
    }
    // Resume the suspended process
    // TODO: Do something less gross here
    // std Command/Child do not expose the main thread handle or id, so we can't easily call ResumeThread
    // Therefore, we call the undocumented NtResumeProcess. We should probably manually call CreateProcess.
    /*
    let ntdll =
        windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()))
            .unwrap();
    let NtResumeProcess = windows::Win32::System::LibraryLoader::GetProcAddress(
        ntdll,
        PCSTR("NtResumeProcess\0".as_ptr()),
    )
    .unwrap();
    let NtResumeProcess: extern "system" fn(isize) -> i32 = std::mem::transmute(NtResumeProcess);
    NtResumeProcess(target_p_h.0);
    SymSetOptions(SymGetOptions() | SYMOPT_DEBUG);
    let ret = SymInitialize(target_p_h, PCSTR(null_mut()), true);
    if ret.0 != 1 {
        panic_with_err();
    }
     */
    // Wait for it to end
    proc.wait().unwrap();
    // This unblocks ProcessTrace
    let ret = ControlTraceA(
        0,
        PCSTR(kernel_logger_name_with_nul.as_ptr()),
        addr_of_mut!(event_trace_props) as *mut _,
        EVENT_TRACE_CONTROL_STOP,
    );
    if ret != ERROR_SUCCESS.0 {
        panic_with_err();
    }
    // Block until processing thread is done
    recvr.recv().unwrap();

    println!("stackmap: {:?}", stack_counts.len());

    SymRefreshModuleList(target_p_h);
    const MAX_SYM_LEN: usize = 8 * 1024;
    #[derive(Clone)]
    #[repr(C)]
    pub struct SYMBOL_INFO_WITH_STRING {
        pub SizeOfStruct: u32,
        pub TypeIndex: u32,
        pub Reserved: [u64; 2],
        pub Index: u32,
        pub Size: u32,
        pub ModBase: u64,
        pub Flags: SYMBOL_INFO_FLAGS,
        pub Value: u64,
        pub Address: u64,
        pub Register: u32,
        pub Scope: u32,
        pub Tag: u32,
        pub NameLen: u32,
        pub MaxNameLen: u32,
        pub Name: [u8; MAX_SYM_LEN],
    }
    #[repr(C)]
    pub struct ASD {
        pub SizeOfStruct: u32,
        pub TypeIndex: u32,
        pub Reserved: [u64; 2],
        pub Index: u32,
        pub Size: u32,
        pub ModBase: u64,
        pub Flags: SYMBOL_INFO_FLAGS,
        pub Value: u64,
        pub Address: u64,
        pub Register: u32,
        pub Scope: u32,
        pub Tag: u32,
        pub NameLen: u32,
        pub MaxNameLen: u32,
        pub Name: [u8; 8],
    }
    let f = File::create("./out.stacks").expect("Unable to create file");
    let mut f = BufWriter::new(f);
    let mut sym_info: SYMBOL_INFO_WITH_STRING = std::mem::zeroed();
    dbg!(size_of::<SYMBOL_INFO>() as u32);
    dbg!(size_of::<SYMBOL_INFO_WITH_STRING>() as u32);
    dbg!(size_of::<[u8; MAX_SYM_LEN]>() as u32);
    dbg!(size_of::<ASD>() as u32);
    sym_info.MaxNameLen = MAX_SYM_LEN as u32 - 4;
    let offset_name2 = addr_of!(sym_info.Name) as usize - addr_of!(sym_info) as usize;
    sym_info.SizeOfStruct = offset_name2 as u32 + 4;
    for (addrs, count) in stack_counts {
        if count == 1 {
            //continue;
        }
        for addr in addrs.iter().filter(|addr| addr != &&0) {
            let mut displacement = 0u64;
            let ret = SymFromAddr(
                target_p_h,
                *addr,
                &mut displacement,
                //null_mut(),
                addr_of_mut!(sym_info).cast(),
            );
            if ret.0 == 1 {
                //let name_addr = addr_of!(sym_info).cast::<u8>().offset(offset_name as isize);
                let name_len = sym_info.NameLen;
                let name_addr = addr_of!(sym_info.Name);
                let sym_str = std::ffi::CStr::from_ptr(name_addr.cast()).to_str().unwrap();
                //println!("addr:0x{addr:X}");
                //println!("sym len:{} res: {sym_str}", sym_str.len());
                //write!(&mut f, "\t\t0x{addr:X}:{name_len}{sym_str}\n").unwrap();

                let mut image_info = IMAGEHLP_MODULE64::default();
                image_info.SizeOfStruct = size_of::<IMAGEHLP_MODULE64>() as u32;
                SymGetModuleInfo64(target_p_h, *addr, &mut image_info);
                if ret.0 != 1 {
                    if displacement != 0 {
                        write!(&mut f, "\t\t{sym_str}+0x{displacement:X}\n").unwrap();
                    } else {
                        write!(&mut f, "\t\t{sym_str}\n").unwrap();
                    }
                } else {
                    let dll_name = std::ffi::CStr::from_ptr(addr_of!(image_info.ModuleName).cast())
                        .to_str()
                        .unwrap();

                    if displacement != 0 {
                        write!(&mut f, "\t\t{dll_name}`{sym_str}+0x{displacement:X}\n").unwrap();
                    } else {
                        write!(&mut f, "\t\t{dll_name}`{sym_str}\n").unwrap();
                    }
                }
            } else {
                //panic_with_err();
                //println!("addr:0x{addr:X}");
                write!(&mut f, "\t\t{addr:X}\n").unwrap();
            };
        }
        write!(&mut f, "\t\t{count}\n\n").unwrap();
    }
    let ret = CloseHandle(target_p_h);
    if ret.0 == 0 {
        panic_with_err();
    }
}
fn main() {
    unsafe {
        unmain();
    }

    println!("Hello, world!");
}
