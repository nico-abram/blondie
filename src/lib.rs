use windows::core::{GUID, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_SUCCESS,
    ERROR_WMI_INSTANCE_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES,
};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageA, SymCleanup, SymFromAddr, SymGetModuleInfo64, SymGetOptions, SymInitialize,
    SymLoadModuleExW, SymRefreshModuleList, SymSetOptions, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS, IMAGEHLP_MODULE64, SYMBOL_INFO_FLAGS, SYMOPT_DEBUG,
    SYM_LOAD_FLAGS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA, SystemTraceControlGuid,
    TraceSampledProfileIntervalInfo, TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_IMAGE_LOAD, EVENT_TRACE_FLAG_PROFILE,
    EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, KERNEL_LOGGER_NAMEA,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_PROFILE_INTERVAL, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::SystemServices::SE_SYSTEM_PROFILE_NAME;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadPriority, CREATE_SUSPENDED,
    THREAD_PRIORITY_TIME_CRITICAL,
};

use std::ffi::OsString;
use std::io::Write;
use std::mem::size_of;
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    prelude::AsRawHandle,
};
use std::ptr::{addr_of, addr_of_mut, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};

/// map[array_of_stacktrace_addrs] = sample_count
type StackMap = rustc_hash::FxHashMap<[u64; MAX_STACK_DEPTH], u64>;
pub struct TraceContext {
    target_process_handle: HANDLE,
    stack_counts_hashmap: StackMap,
    target_proc_pid: u32,
    trace_running: AtomicBool,
}
impl TraceContext {
    /// The Context takes ownership of the handle.
    /// SAFETY:
    ///  - target_process_handle must be a valid process handle.
    ///  - target_proc_id must be the id of the process.
    unsafe fn new(target_process_handle: HANDLE, target_proc_pid: u32) -> Result<Self> {
        SymSetOptions(SymGetOptions() | SYMOPT_DEBUG);
        let ret = SymInitialize(target_process_handle, PCSTR(null_mut()), false);
        if ret.0 != 1 {
            return Err(get_last_error());
        }

        Ok(Self {
            target_process_handle: target_process_handle,
            stack_counts_hashmap: Default::default(),
            target_proc_pid,
            trace_running: AtomicBool::new(false),
        })
    }
}
impl Drop for TraceContext {
    fn drop(&mut self) {
        // SAFETY: TraceContext invariants ensure these are valid
        unsafe {
            let ret = SymCleanup(self.target_process_handle);
            if ret.0 != 1 {
                panic!("TraceContext::SymCleanup error:{:?}", get_last_error());
            }
            let ret = CloseHandle(self.target_process_handle);
            if ret.0 == 0 {
                panic!("TraceContext::CloseHandle error:{:?}", get_last_error());
            }
        }
    }
}
// msdn says 192 but I got some that were bigger
//const MAX_STACK_DEPTH: usize = 192;
const MAX_STACK_DEPTH: usize = 200;

#[derive(Debug)]
pub enum Error {
    /// Winstacks requires admin priviledges
    NotAnAdmin,
    /// The processing thread panicked and we don't know why
    UnknownError,
    /// Error spawning a suspended process
    SpawnErr(std::io::Error, OsString, Vec<OsString>),
    /// Error waiting for child
    WaitOnChildErr(std::io::Error),
    Other(WIN32_ERROR, String),
}
type Result<T> = std::result::Result<T, Error>;

fn get_last_error() -> Error {
    const BUF_LEN: usize = 1024;
    let mut buf = [0u8; BUF_LEN];
    let code = unsafe { GetLastError() };
    let chars_written = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            code.0,
            0,
            PSTR(buf.as_mut_ptr()),
            BUF_LEN as u32,
            null_mut(),
        )
    };
    assert!(chars_written != 0);
    let code_str = unsafe {
        std::ffi::CStr::from_ptr(buf.as_ptr().cast())
            .to_str()
            .unwrap()
    };
    Error::Other(code, code_str.to_string())
}

/// `h` must be a valid handle
unsafe fn clone_handle(h: HANDLE) -> Result<HANDLE> {
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
        return Err(get_last_error());
    }
    Ok(target_h)
}
fn create_suspended(arg0: OsString, args: &[OsString]) -> Result<std::process::Child> {
    use std::os::windows::process::CommandExt;

    // Create the target process suspended
    let proc = std::process::Command::new(&arg0)
        .args(args)
        .creation_flags(CREATE_SUSPENDED.0)
        .spawn()
        .map_err(|err| Error::SpawnErr(err, arg0, args.iter().cloned().collect::<Vec<_>>()))?;
    Ok(proc)
}
fn acquire_priviledges() -> Result<()> {
    let mut privs = TOKEN_PRIVILEGES::default();
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if unsafe {
        LookupPrivilegeValueA(
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
    } {
        return Err(get_last_error());
    }
    let mut pt = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut pt).0 == 0 } {
        return Err(get_last_error());
    }
    let adjust = unsafe {
        AdjustTokenPrivileges(pt, false, addr_of!(privs).cast(), 0, null_mut(), null_mut())
    };
    if adjust.0 == 0 {
        let err = Err(get_last_error());
        unsafe {
            CloseHandle(pt);
        }
        return err;
    }
    let ret = unsafe { CloseHandle(pt) };
    if ret.0 == 0 {
        return Err(get_last_error());
    }
    let status = unsafe { GetLastError() };
    if status != ERROR_SUCCESS {
        return Err(Error::NotAnAdmin);
    }
    Ok(())
}
/// SAFETY: is_suspended must only be true if `target_process` is suspended
unsafe fn trace_from_process(
    mut target_process: std::process::Child,
    is_suspended: bool,
) -> Result<TraceContext> {
    acquire_priviledges()?;

    // Set the sampling interval
    {
        let mut interval = TRACE_PROFILE_INTERVAL::default();
        // TODO: Parameter?
        interval.Interval = (1000000000 / 8000) / 100;
        let ret = TraceSetInformation(
            0,
            TraceSampledProfileIntervalInfo,
            addr_of!(interval).cast(),
            size_of::<TRACE_PROFILE_INTERVAL>() as u32,
        );
        if ret != ERROR_SUCCESS.0 {
            return Err(get_last_error());
        }
    }

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
    // We also use Image_Load events to know which dlls to load debug information from for symbol resolution
    // Which is enabled by the EVENT_TRACE_FLAG_IMAGE_LOAD flag
    const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() + KERNEL_LOGGER_NAMEA.len() + 1;
    #[derive(Clone)]
    #[repr(C)]
    struct EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: EVENT_TRACE_PROPERTIES,
        s: [u8; KERNEL_LOGGER_NAMEA.len() + 1],
    }
    let mut event_trace_props = EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: EVENT_TRACE_PROPERTIES::default(),
        s: [0u8; KERNEL_LOGGER_NAMEA.len() + 1],
    };
    event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_IMAGE_LOAD;
    event_trace_props.data.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    event_trace_props.data.Wnode.BufferSize = PROPS_SIZE as u32;
    event_trace_props.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    event_trace_props.data.Wnode.ClientContext = 3;
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
    // We use a copy of `event_trace_props` since ControlTrace overwrites it
    {
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
            return Err(get_last_error());
        }
    }

    // Start kernel trace session
    let mut trace_session_handle = 0;
    {
        let start_retcode = StartTraceA(
            &mut trace_session_handle,
            kernel_logger_name_with_nul_pcstr,
            addr_of_mut!(event_trace_props) as *mut _,
        );
        if start_retcode != ERROR_SUCCESS.0 {
            return Err(get_last_error());
        }
    }

    // Enable stack tracing
    {
        let mut stack_event_id = CLASSIC_EVENT_ID::default();
        // GUID from https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
        let perfinfo_guid = GUID {
            data1: 0xce1dbfb4,
            data2: 0x137e,
            data3: 0x4da6,
            data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
        };
        stack_event_id.EventGuid = perfinfo_guid;
        stack_event_id.Type = 46; // Sampled profile event
        let enable_stacks_retcode = TraceSetInformation(
            trace_session_handle,
            TraceStackTracingInfo,
            addr_of!(stack_event_id).cast(),
            size_of::<CLASSIC_EVENT_ID>() as u32,
        );
        if enable_stacks_retcode != ERROR_SUCCESS.0 {
            return Err(get_last_error());
        }
    }

    let target_pid = target_process.id();
    // std Child closes the handle when it drops so we clone it
    let target_proc_handle = clone_handle(HANDLE(target_process.as_raw_handle() as isize))?;
    let mut context = TraceContext::new(target_proc_handle, target_pid)?;
    //TODO: Do we need to Box the context?

    let mut log = EVENT_TRACE_LOGFILEA::default();
    log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.Context = addr_of_mut!(context).cast();

    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        let provider_guid_data1 = (*record).EventHeader.ProviderId.data1;
        let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;
        let context = &mut *(*record).UserContext.cast::<TraceContext>();
        context.trace_running.store(true, Ordering::Relaxed);

        const EVENT_TRACE_TYPE_LOAD: u8 = 10;
        if event_opcode == EVENT_TRACE_TYPE_LOAD {
            let event = (*record).UserData.cast::<ImageLoadEvent>().read_unaligned();
            if event.ProcessId != context.target_proc_pid {
                // Ignore dlls for other processes
                return;
            }
            let filename_p = (*record)
                .UserData
                .cast::<ImageLoadEvent>()
                .offset(1)
                .cast::<u16>();
            let filename_str = OsString::from_wide(std::slice::from_raw_parts(
                filename_p,
                ((*record).UserDataLength as usize - size_of::<ImageLoadEvent>()) / 2,
            ));
            let filename_str = filename_str.to_str().unwrap();
            let image_base = event.ImageBase;

            // Convert the \Device\HardDiskVolume path to a verbatim path \\?\HardDiskVolume
            let verbatim_path: OsString = filename_str.replacen("\\Device\\", "\\\\?\\", 1).into();
            let verbatim_path = verbatim_path
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();

            let ret = SymLoadModuleExW(
                context.target_process_handle,
                HANDLE(0),
                PCWSTR(verbatim_path.as_ptr()),
                PCWSTR(null_mut()),
                image_base as u64,
                0,
                null_mut(),
                SYM_LOAD_FLAGS(0),
            );
            if ret == 0 {
                println!("Error loading module {}", filename_str);
                return;
            }
            SymRefreshModuleList(context.target_process_handle);

            return;
        }

        // From https://docs.microsoft.com/en-us/windows/win32/etw/stackwalk
        let stackwalk_guid_data1 = 0xdef2fe46;
        let stackwalk_event_type = 32;
        if event_opcode != stackwalk_event_type || stackwalk_guid_data1 != provider_guid_data1 {
            // Ignore events other than stackwalk or dll load
            return;
        }
        let ud_p = (*record).UserData;
        let _timestamp = ud_p.cast::<u64>().read_unaligned();
        let proc = ud_p.cast::<u32>().offset(2).read_unaligned();
        let _thread = ud_p.cast::<u32>().offset(3).read_unaligned();
        if proc != context.target_proc_pid {
            // Ignore stackwalks for other processes
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

        let entry = context.stack_counts_hashmap.entry(stack);
        *entry.or_insert(0) += 1;
    }
    log.Anonymous2.EventRecordCallback = Some(event_record_callback);

    let trace_processing_handle = OpenTraceA(&mut log);
    if trace_processing_handle == INVALID_HANDLE_VALUE.0 as u64 {
        return Err(get_last_error());
    }

    let (sender, recvr) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // This blocks
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        ProcessTrace(&[trace_processing_handle], null_mut(), null_mut());

        let ret = CloseTrace(trace_processing_handle);
        if ret != ERROR_SUCCESS.0 {
            println!("Error closing trace");
        }
        sender.send(()).unwrap();
    });

    // Wait until we know for sure the trace is running
    while !context.trace_running.load(Ordering::Relaxed) {
        std::hint::spin_loop();
    }
    // Resume the suspended process
    if is_suspended {
        // TODO: Do something less gross here
        // std Command/Child do not expose the main thread handle or id, so we can't easily call ResumeThread
        // Therefore, we call the undocumented NtResumeProcess. We should probably manually call CreateProcess.
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()))
                .unwrap();
        #[allow(non_snake_case)]
        let NtResumeProcess = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            PCSTR("NtResumeProcess\0".as_ptr()),
        )
        .unwrap();
        #[allow(non_snake_case)]
        let NtResumeProcess: extern "system" fn(isize) -> i32 =
            std::mem::transmute(NtResumeProcess);
        NtResumeProcess(context.target_process_handle.0);
    }
    // Wait for it to end
    target_process
        .wait()
        .map_err(|err| Error::WaitOnChildErr(err))?;
    // This unblocks ProcessTrace
    let ret = ControlTraceA(
        0,
        PCSTR(kernel_logger_name_with_nul.as_ptr()),
        addr_of_mut!(event_trace_props) as *mut _,
        EVENT_TRACE_CONTROL_STOP,
    );
    if ret != ERROR_SUCCESS.0 {
        return Err(get_last_error());
    }
    // Block until processing thread is done
    // (Safeguard to make sure we don't deallocate the context before the other thread finishes using it)
    if let Err(_) = recvr.recv() {
        return Err(Error::UnknownError);
    }

    SymRefreshModuleList(context.target_process_handle);
    Ok(context)
}
/// Trace an existing process.
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_process(process: std::process::Child) -> Result<TraceContext> {
    unsafe { trace_from_process(process, false) }
}
/// Execute "arg0 args[0] args[1] ...." and trace it, periodically collecting call stacks.
/// The trace also tracks dlls and exes loaded by the process and loads the debug info for
/// them, if it can find it. It is unloaded on TraceContext Drop.
pub fn trace_command(arg0: OsString, args: &[OsString]) -> Result<TraceContext> {
    unsafe { trace_from_process(create_suspended(arg0, args)?, true) }
}
/// A distinct callstack and the count of samples it was found in
pub struct TraceCallStack<'a> {
    ctx: &'a TraceContext,
    stack: &'a [u64; MAX_STACK_DEPTH],
    sample_count: u64,
}
pub struct ResolvedAddress {
    /// Sample Address
    pub addr: u64,
    /// Displacement into the symbol
    pub displacement: u64,
    /// Symbol name
    pub symbol_name: Option<String>,
    /// Imager (Exe or Dll) name
    pub image_name: Option<String>,
}
impl<'a> TraceCallStack<'a> {
    pub fn iter_resolved_addresses(
        &'a self,
    ) -> impl std::iter::Iterator<Item = ResolvedAddress> + 'a {
        self.stack
            .iter()
            .take_while(|&&addr| addr != 0)
            .map(|&addr| {
                let mut symbol_name = None;
                let mut image_name = None;

                // Translate the address to a symbols string
                let mut sym_info: SYMBOL_INFO_WITH_STRING = unsafe { std::mem::zeroed() };
                sym_info.MaxNameLen = MAX_SYM_LEN as u32 - 4;
                let offset_name2 = addr_of!(sym_info.Name) as usize - addr_of!(sym_info) as usize;
                sym_info.SizeOfStruct = offset_name2 as u32 + 4;
                let mut displacement = 0u64;
                // SAFETY: sym_info is correctly initialized and TraceContext ensures target_process_handle is valid
                let ret = unsafe {
                    SymFromAddr(
                        self.ctx.target_process_handle,
                        addr,
                        &mut displacement,
                        addr_of_mut!(sym_info).cast(),
                    )
                };
                if ret.0 == 1 {
                    let name_addr = addr_of!(sym_info.Name);
                    let sym_str =
                        unsafe { std::ffi::CStr::from_ptr(name_addr.cast()).to_str().unwrap() };
                    // TODO: Figure out a way to not allocate here? Might need GATs and LendingIterator
                    symbol_name = Some(sym_str.to_string());

                    // Get image(exe/dll) name
                    let mut image_info = IMAGEHLP_MODULE64::default();
                    image_info.SizeOfStruct = size_of::<IMAGEHLP_MODULE64>() as u32;
                    // SAFETY: image_info is correctly initialized and TraceContext ensures target_process_handle is valid
                    let ret = unsafe {
                        SymGetModuleInfo64(self.ctx.target_process_handle, addr, &mut image_info)
                    };
                    if ret.0 == 1 {
                        // SAFETY: image_info.ModuleName is initialized to all zeros and SymGetModuleInfo64 stores a null terminated string
                        let image_name_str = unsafe {
                            std::ffi::CStr::from_ptr(addr_of!(image_info.ModuleName).cast())
                                .to_str()
                                .unwrap()
                        };
                        image_name = Some(image_name_str.to_string());
                    }
                };
                ResolvedAddress {
                    addr,
                    displacement,
                    symbol_name,
                    image_name,
                }
            })
    }
}
impl TraceContext {
    pub fn iter_callstacks<'a>(
        &'a self,
    ) -> impl std::iter::Iterator<Item = TraceCallStack<'a>> + 'a {
        self.stack_counts_hashmap.iter().map(|x| TraceCallStack {
            ctx: self,
            stack: x.0,
            sample_count: *x.1,
        })
    }
    /// Resolve call stack symbols and write a dtrace-like sampling report to `w`
    pub fn write_dtrace<W: Write>(&self, mut w: W) -> Result<()> {
        for callstack in self.iter_callstacks() {
            for resolved_addr in callstack.iter_resolved_addresses() {
                let displacement = resolved_addr.displacement;
                let address = resolved_addr.addr;
                if let Some(symbol_name) = resolved_addr.symbol_name {
                    if let Some(image_name) = resolved_addr.image_name {
                        if displacement != 0 {
                            write!(w, "\t\t{image_name}`{symbol_name}+0x{displacement:X}\n")
                                .unwrap();
                        } else {
                            write!(w, "\t\t{image_name}`{symbol_name}\n").unwrap();
                        }
                    } else {
                        // Image name not found
                        if displacement != 0 {
                            write!(w, "\t\t{symbol_name}+0x{displacement:X}\n").unwrap();
                        } else {
                            write!(w, "\t\t{symbol_name}\n").unwrap();
                        }
                    }
                } else {
                    // Symbol not found
                    write!(w, "\t\t{address:X}\n").unwrap();
                }
            }
            let count = callstack.sample_count;
            write!(w, "\t\t{count}\n\n").unwrap();
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct ImageLoadEvent {
    ImageBase: u64,
    ImageSize: u64,
    ProcessId: u32,
    ImageCheckSum: u32,
    TimeDateStamp: u32,
    Reserved0: u32,
    DefaultBase: u64,
    Reserved1: u32,
    Reserved2: u32,
    Reserved3: u32,
    Reserved4: u32,
}

const MAX_SYM_LEN: usize = 8 * 1024;
#[allow(non_snake_case)]
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
