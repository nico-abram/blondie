//! blondie is a rust library to do callstack sampling of a process on windows.
//!
//! You can use [`trace_command`] to execute and sample an [`std::process::Command`].
//!
//! Or you can use [`trace_child`] to start tracing an [`std::process::Child`].
//! You can also trace an arbitrary process using [`trace_pid`].

#![warn(missing_docs)]
#![allow(clippy::field_reassign_with_default)]

mod error;
mod util;

use std::collections::hash_map::Entry;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, Weak};

use object::Object;
use pdb_addr2line::pdb::PDB;
use pdb_addr2line::ContextPdbData;
use rustc_hash::FxHashMap;
use windows::core::{GUID, PCSTR, PSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA, SystemTraceControlGuid,
    TraceSampledProfileIntervalInfo, TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, KERNEL_LOGGER_NAMEA, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, TRACE_PROFILE_INTERVAL,
    WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA};
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, CREATE_SUSPENDED, THREAD_PRIORITY_TIME_CRITICAL,
};

use crate::error::get_last_error;
pub use crate::error::{Error, Result};

/// Maximum stack depth/height of traces.
// msdn says 192 but I got some that were bigger
// const MAX_STACK_DEPTH: usize = 192;
const MAX_STACK_DEPTH: usize = 200;

/// Context for a specific process's trace.
struct TraceContext {
    target_process_handle: HANDLE,
    target_proc_pid: u32,
    show_kernel_samples: bool,

    /// map[array_of_stacktrace_addrs] = sample_count
    stack_counts_hashmap: FxHashMap<[u64; MAX_STACK_DEPTH], u64>,
    /// (image_path, image_base, image_size)
    image_paths: Vec<(OsString, u64, u64)>,
}
impl TraceContext {
    /// The Context takes ownership of the handle.
    ///
    /// # Safety
    ///
    /// - `target_process_handle` must be a valid process handle.
    /// - `target_proc_id` must be the id of the same process as the handle.
    unsafe fn new(
        target_process_handle: HANDLE,
        target_proc_pid: u32,
        kernel_stacks: bool,
    ) -> Result<Self> {
        Ok(Self {
            target_process_handle,
            stack_counts_hashmap: Default::default(),
            target_proc_pid,
            show_kernel_samples: std::env::var("BLONDIE_KERNEL")
                .map(|value| {
                    let upper = value.to_uppercase();
                    ["Y", "YES", "TRUE"].iter().any(|truthy| &upper == truthy)
                })
                .unwrap_or(kernel_stacks),
            image_paths: Vec::with_capacity(1024),
        })
    }
}
impl Drop for TraceContext {
    fn drop(&mut self) {
        // SAFETY: TraceContext invariants ensure these are valid
        unsafe {
            let ret = CloseHandle(self.target_process_handle);
            if ret.0 == 0 {
                panic!("TraceContext::CloseHandle error:{:?}", get_last_error(""));
            }
        }
    }
}

/// Stateful context provided to `event_record_callback`, containing multiple [`TraceContext`]s.
struct Context {
    /// Keys are process IDs. `Weak` deallocates when tracing should stop.
    traces: FxHashMap<u32, Weak<TraceContext>>,
    /// Receive new processes to subscribe to tracing.
    subscribe_recv: Receiver<Weak<TraceContext>>,
    /// Set to true once the trace starts running.
    trace_running: Arc<AtomicBool>,
}
impl Context {
    /// SAFETY: May only be called by `event_record_callback`, while tracing.
    unsafe fn get_trace_context(&mut self, pid: u32) -> Option<Arc<TraceContext>> {
        // TODO: handle PID reuse???
        let Entry::Occupied(entry) = self.traces.entry(pid) else {
            // Ignore dlls for other processes
            return None;
        };
        if let Some(trace_context) = Weak::upgrade(entry.get()) {
            Some(trace_context)
        } else {
            // Tracing just stopped, remove deallocated `Weak`.
            entry.remove();
            return None;
        }
    }
}

/// Global tracing session.
///
/// When this is dropped, the tracing session will be stopped.
struct Session {
    /// Send new processes to subscribe to tracing.
    subscribe_send: SyncSender<Weak<TraceContext>>,
    /// Box allocation for [`UserContext`].
    context: *mut Context,
    /// Box allocation for event trace props, need deallocation after.
    event_trace_props: *mut EVENT_TRACE_PROPERTIES_WITH_STRING,
    /// Box allocation for Logfile.
    log: *mut EVENT_TRACE_LOGFILEA,
}
unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Session {
    fn start(self: &Arc<Self>, trace_context: TraceContext) -> TraceGuard {
        let trace_context = Arc::new(trace_context);
        self.subscribe_send
            .send(Arc::downgrade(&trace_context))
            .unwrap();
        TraceGuard {
            trace_context,
            _session: Arc::clone(&self),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let ret = unsafe {
            // This unblocks ProcessTrace
            ControlTraceA(
                <CONTROLTRACE_HANDLE as Default>::default(),
                KERNEL_LOGGER_NAMEA,
                self.event_trace_props.cast(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        unsafe {
            drop(Box::from_raw(self.context));
            drop(Box::from_raw(self.event_trace_props));
            drop(Box::from_raw(self.log));
        }
        if ret != ERROR_SUCCESS {
            eprintln!(
                "Error dropping GlobalContext: {:?}",
                get_last_error("ControlTraceA STOP ProcessTrace")
            );
        }
    }
}

struct TraceGuard {
    trace_context: Arc<TraceContext>,
    /// Ensure session stays alive while `TraceGuard` is alive.
    _session: Arc<Session>,
}
impl TraceGuard {
    fn stop(self) -> TraceContext {
        Arc::try_unwrap(self.trace_context)
            .map_err(drop)
            .expect("TraceContext Arc count should never have been incremented.")
    }
}

/// Gets the global context. Begins tracing if not already running.
fn get_global_context() -> Result<Arc<Session>> {
    static GLOBAL_CONTEXT: Mutex<Weak<Session>> = Mutex::new(Weak::new());

    let mut unlocked = GLOBAL_CONTEXT.lock().unwrap();
    if let Some(global_context) = unlocked.upgrade() {
        return Ok(global_context);
    }

    let mut winver_info = OSVERSIONINFOA::default();
    winver_info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOA>() as u32;
    let ret = unsafe { GetVersionExA(addr_of_mut!(winver_info)) };
    if ret.0 == 0 {
        return Err(get_last_error("GetVersionExA"));
    }
    // If we're not win7 or more, return unsupported
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
    if winver_info.dwMajorVersion < 6
        || (winver_info.dwMajorVersion == 6 && winver_info.dwMinorVersion == 0)
    {
        return Err(Error::UnsupportedOsVersion);
    }
    util::acquire_privileges()?;

    // Set the sampling interval
    // Only for Win8 or more
    if winver_info.dwMajorVersion > 6
        || (winver_info.dwMajorVersion == 6 && winver_info.dwMinorVersion >= 2)
    {
        let mut interval = TRACE_PROFILE_INTERVAL::default();
        // TODO: Parameter?
        interval.Interval = (1000000000 / 8000) / 100;
        let ret = unsafe {
            TraceSetInformation(
                None,
                // The value is supported on Windows 8, Windows Server 2012, and later.
                TraceSampledProfileIntervalInfo,
                addr_of!(interval).cast(),
                size_of::<TRACE_PROFILE_INTERVAL>() as u32,
            )
        };
        if ret != ERROR_SUCCESS {
            return Err(get_last_error("TraceSetInformation interval"));
        }
    }

    let mut kernel_logger_name_with_nul = unsafe { KERNEL_LOGGER_NAMEA.as_bytes() }.to_vec();
    kernel_logger_name_with_nul.push(b'\0');
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
    const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() + KERNEL_LOGGER_NAMEA_LEN + 1;
    let mut event_trace_props = Box::new(EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: EVENT_TRACE_PROPERTIES::default(),
        s: [0u8; KERNEL_LOGGER_NAMEA_LEN + 1],
    });
    event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_IMAGE_LOAD;
    event_trace_props.data.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    event_trace_props.data.Wnode.BufferSize = PROPS_SIZE as u32;
    event_trace_props.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    event_trace_props.data.Wnode.ClientContext = 3;
    event_trace_props.data.Wnode.Guid = SystemTraceControlGuid;
    event_trace_props.data.BufferSize = 1024;
    let core_count = std::thread::available_parallelism()
        .unwrap_or(std::num::NonZeroUsize::new(1usize).unwrap());
    event_trace_props.data.MinimumBuffers = core_count.get() as u32 * 4;
    event_trace_props.data.MaximumBuffers = core_count.get() as u32 * 6;
    event_trace_props.data.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    event_trace_props
        .s
        .copy_from_slice(&kernel_logger_name_with_nul[..]);

    // let kernel_logger_name_with_nul_pcstr = PCSTR(kernel_logger_name_with_nul.as_ptr());
    // Stop an existing session with the kernel logger, if it exists
    // We use a copy of `event_trace_props` since ControlTrace overwrites it
    {
        let mut event_trace_props_copy = (*event_trace_props).clone();
        let control_stop_retcode = unsafe {
            ControlTraceA(
                None,
                KERNEL_LOGGER_NAMEA,
                addr_of_mut!(event_trace_props_copy).cast(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if control_stop_retcode != ERROR_SUCCESS
            && control_stop_retcode != ERROR_WMI_INSTANCE_NOT_FOUND
        {
            return Err(get_last_error("ControlTraceA STOP"));
        }
    }

    // Start kernel trace session
    let mut trace_session_handle: CONTROLTRACE_HANDLE = Default::default();
    {
        let start_retcode = unsafe {
            StartTraceA(
                addr_of_mut!(trace_session_handle),
                KERNEL_LOGGER_NAMEA,
                addr_of_mut!(*event_trace_props).cast(),
            )
        };
        if start_retcode != ERROR_SUCCESS {
            return Err(get_last_error("StartTraceA"));
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
        let enable_stacks_retcode = unsafe {
            TraceSetInformation(
                trace_session_handle,
                TraceStackTracingInfo,
                addr_of!(stack_event_id).cast(),
                size_of::<CLASSIC_EVENT_ID>() as u32,
            )
        };
        if enable_stacks_retcode != ERROR_SUCCESS {
            return Err(get_last_error("TraceSetInformation stackwalk"));
        }
    }

    let mut log = Box::new(EVENT_TRACE_LOGFILEA::default());
    log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;

    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        let provider_guid_data1 = (*record).EventHeader.ProviderId.data1;
        let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;

        let context = &mut *(*record).UserContext.cast::<Context>();
        context.trace_running.store(true, Ordering::Relaxed);
        // Subscribe any new processes.
        context
            .traces
            .extend(context.subscribe_recv.try_iter().filter_map(|weak| {
                let pid = Weak::upgrade(&weak)?.target_proc_pid;
                Some((pid, weak))
            }));

        const EVENT_TRACE_TYPE_LOAD: u8 = 10;
        if event_opcode == EVENT_TRACE_TYPE_LOAD {
            let event = (*record).UserData.cast::<ImageLoadEvent>().read_unaligned();

            let Some(trace_context) = context.get_trace_context(event.ProcessId) else {
                // Ignore dlls for other processes
                return;
            };
            // TODO: use `Arc::get_mut_unchecked` once stable.
            // SAFETY: Only the callback may modify the `TraceContext` while running.
            let trace_context = Arc::into_raw(trace_context).cast_mut();

            let filename_p = (*record)
                .UserData
                .cast::<ImageLoadEvent>()
                .offset(1)
                .cast::<u16>();
            let filename_os_string = OsString::from_wide(std::slice::from_raw_parts(
                filename_p,
                ((*record).UserDataLength as usize - size_of::<ImageLoadEvent>()) / 2,
            ));
            (*trace_context).image_paths.push((
                filename_os_string,
                event.ImageBase as u64,
                event.ImageSize as u64,
            ));

            // SAFETY: De-increments Arc from above.
            drop(Arc::from_raw(trace_context));

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

        // TODO: handle PID reuse???
        let Some(trace_context) = context.get_trace_context(proc) else {
            // Ignore stackwalks for other processes
            return;
        };
        // TODO: use `Arc::get_mut_unchecked` once stable.
        // SAFETY: Only the callback may modify the `TraceContext` while running.
        let trace_context = Arc::into_raw(trace_context).cast_mut();

        let stack_depth_32 = ((*record).UserDataLength - 16) / 4;
        let stack_depth_64 = stack_depth_32 / 2;
        let stack_depth = if size_of::<usize>() == 8 {
            stack_depth_64
        } else {
            stack_depth_32
        };

        let mut tmp = vec![];
        let mut stack_addrs = if size_of::<usize>() == 8 {
            std::slice::from_raw_parts(ud_p.cast::<u64>().offset(2), stack_depth as usize)
        } else {
            tmp.extend(
                std::slice::from_raw_parts(
                    ud_p.cast::<u64>().offset(2).cast::<u32>(),
                    stack_depth as usize,
                )
                .iter()
                .map(|x| *x as u64),
            );
            &tmp
        };
        if stack_addrs.len() > MAX_STACK_DEPTH {
            stack_addrs = &stack_addrs[(stack_addrs.len() - MAX_STACK_DEPTH)..];
        }

        let mut stack = [0u64; MAX_STACK_DEPTH];
        stack[..(stack_depth as usize).min(MAX_STACK_DEPTH)].copy_from_slice(stack_addrs);

        let entry = (*trace_context).stack_counts_hashmap.entry(stack);
        *entry.or_insert(0) += 1;

        // SAFETY: De-increments Arc from above.
        drop(Arc::from_raw(trace_context));

        const DEBUG_OUTPUT_EVENTS: bool = false;
        if DEBUG_OUTPUT_EVENTS {
            #[repr(C)]
            #[derive(Debug)]
            #[allow(non_snake_case)]
            #[allow(non_camel_case_types)]
            struct EVENT_HEADERR {
                Size: u16,
                HeaderType: u16,
                Flags: u16,
                EventProperty: u16,
                ThreadId: u32,
                ProcessId: u32,
                TimeStamp: i64,
                ProviderId: ::windows::core::GUID,
                EventDescriptor: windows::Win32::System::Diagnostics::Etw::EVENT_DESCRIPTOR,
                KernelTime: u32,
                UserTime: u32,
                ProcessorTime: u64,
                ActivityId: ::windows::core::GUID,
            }
            #[repr(C)]
            #[derive(Debug)]
            #[allow(non_snake_case)]
            #[allow(non_camel_case_types)]
            struct EVENT_RECORDD {
                EventHeader: EVENT_HEADERR,
                BufferContextAnonymousProcessorNumber: u8,
                BufferContextAnonymousAlignment: u8,
                BufferContextAnonymousProcessorIndex: u16,
                BufferContextLoggerId: u16,
                ExtendedDataCount: u16,
                UserDataLength: u16,
                ExtendedData:
                    *mut windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM,
                UserData: *mut ::core::ffi::c_void,
                UserContext: *mut ::core::ffi::c_void,
            }
            eprintln!(
                "record {:?} {:?} proc:{proc} thread:{_thread}",
                (*record.cast::<EVENT_RECORDD>()),
                stack
            );
        }
    }
    log.Anonymous2.EventRecordCallback = Some(event_record_callback);

    let (subscribe_send, subscribe_recv) = sync_channel(16);
    let trace_running = Arc::new(AtomicBool::new(false));
    let context = Box::into_raw(Box::new(Context {
        traces: Default::default(),
        subscribe_recv,
        trace_running: Arc::clone(&trace_running),
    }));
    log.Context = context.cast();

    let trace_processing_handle = unsafe { OpenTraceA(addr_of_mut!(*log)) };
    if trace_processing_handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
        return Err(get_last_error("OpenTraceA processing"));
    }

    let _ = std::thread::spawn(move || {
        unsafe {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            // This blocks until `EVENT_TRACE_CONTROL_STOP` on `GlobalContext::drop`.
            ProcessTrace(&[trace_processing_handle], None, None)
        };

        let ret = unsafe { CloseTrace(trace_processing_handle) };
        if ret != ERROR_SUCCESS {
            return Err(get_last_error("Error closing trace"));
        }
        Ok(())
    });

    // Wait until we know for sure the trace is running
    while !trace_running.load(Ordering::Relaxed) {
        std::hint::spin_loop();
    }

    // Store the session.
    let session = Arc::new(Session {
        subscribe_send,
        context,
        event_trace_props: Box::into_raw(event_trace_props),
        // TODO: does log need to survive past the `OpenTraceA` call? Maybe not
        log: Box::into_raw(log),
    });
    *unlocked = Arc::downgrade(&session);
    Ok(session)
}

const KERNEL_LOGGER_NAMEA_LEN: usize = unsafe {
    let mut ptr = KERNEL_LOGGER_NAMEA.0;
    let mut len = 0;
    while *ptr != 0 {
        len += 1;
        ptr = ptr.add(1);
    }
    len
};

#[derive(Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct EVENT_TRACE_PROPERTIES_WITH_STRING {
    data: EVENT_TRACE_PROPERTIES,
    s: [u8; KERNEL_LOGGER_NAMEA_LEN + 1],
}

/// The main tracing logic. Traces the process with the given `target_process_id`.
///
/// # Safety
///
/// `is_suspended` may only be true if `target_process` is suspended
unsafe fn trace_from_process_id(
    target_process_id: u32,
    is_suspended: bool,
    kernel_stacks: bool,
) -> Result<TraceContext> {
    let target_proc_handle = util::handle_from_process_id(target_process_id)?;
    let trace_context =
        unsafe { TraceContext::new(target_proc_handle, target_process_id, kernel_stacks)? };
    let trace_guard = get_global_context()?.start(trace_context);

    // Resume the suspended process
    if is_suspended {
        // TODO: Do something less gross here
        // std Command/Child do not expose the main thread handle or id, so we can't easily call ResumeThread
        // Therefore, we call the undocumented NtResumeProcess. We should probably manually call CreateProcess.
        // Now that https://github.com/rust-lang/rust/issues/96723 is merged, we could use that on nightly
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()))
                .expect("Could not find ntdll.dll");
        #[allow(non_snake_case)]
        let NtResumeProcess = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            PCSTR("NtResumeProcess\0".as_ptr()),
        )
        .expect("Could not find NtResumeProcess in ntdll.dll");
        #[allow(non_snake_case)]
        let NtResumeProcess: extern "system" fn(isize) -> i32 =
            std::mem::transmute(NtResumeProcess);
        NtResumeProcess(target_proc_handle.0);
    }

    // Wait for it to end
    util::wait_for_process_by_handle(target_proc_handle)?;

    let mut trace_context = trace_guard.stop();
    if trace_context.show_kernel_samples {
        let kernel_module_paths = util::list_kernel_modules();
        trace_context.image_paths.extend(kernel_module_paths);
    }
    Ok(trace_context)
}

/// The sampled results from a process execution
pub struct CollectionResults(TraceContext);
/// Trace an existing child process based only on its process ID (pid).
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_pid(process_id: u32, kernel_stacks: bool) -> Result<CollectionResults> {
    let res = unsafe { trace_from_process_id(process_id, false, kernel_stacks) };
    res.map(CollectionResults)
}
/// Trace an existing child process.
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_child(process: std::process::Child, kernel_stacks: bool) -> Result<CollectionResults> {
    let res = unsafe { trace_from_process_id(process.id(), false, kernel_stacks) };
    res.map(CollectionResults)
}
/// Execute `command` and trace it, periodically collecting call stacks.
/// The trace also tracks dlls and exes loaded by the process and loads the debug info for
/// them, if it can find it. The debug info is used to resolve addresses to symbol names and
/// is unloaded on TraceContext Drop.
pub fn trace_command(
    mut command: std::process::Command,
    kernel_stacks: bool,
) -> Result<CollectionResults> {
    use std::os::windows::process::CommandExt;

    // Create the target process suspended
    // TODO: Preserve existing flags instead of stomping them
    let mut proc = command
        .creation_flags(CREATE_SUSPENDED.0)
        .spawn()
        .map_err(Error::SpawnErr)?;
    let res = unsafe { trace_from_process_id(proc.id(), true, kernel_stacks) };
    if res.is_err() {
        // Kill the suspended process if we had some kind of error
        let _ = proc.kill();
    }
    res.map(CollectionResults)
}
/// A callstack and the count of samples it was found in
///
/// You can get them using [`CollectionResults::iter_callstacks`]
pub struct CallStack<'a> {
    stack: &'a [u64; MAX_STACK_DEPTH],
    sample_count: u64,
}

/// An address from a callstack
///
/// You can get them using [`CallStack::iter_resolved_addresses`]
pub struct Address {
    /// Sample Address
    pub addr: u64,
    /// Displacement into the symbol
    pub displacement: u64,
    /// Symbol names
    pub symbol_names: Vec<String>,
    /// Imager (Exe or Dll) name
    pub image_name: Option<String>,
}
type OwnedPdb = ContextPdbData<'static, 'static, std::io::Cursor<Vec<u8>>>;
type PdbDb<'a, 'b> =
    std::collections::BTreeMap<u64, (u64, u64, OsString, pdb_addr2line::Context<'a, 'b>)>;

/// Returns Vec<(image_base, image_size, image_name, addr2line pdb context)>
fn find_pdbs(images: &[(OsString, u64, u64)]) -> Vec<(u64, u64, OsString, OwnedPdb)> {
    let mut pdb_db = Vec::new();

    fn owned_pdb(pdb_file_bytes: Vec<u8>) -> Option<OwnedPdb> {
        let pdb = PDB::open(std::io::Cursor::new(pdb_file_bytes)).ok()?;
        pdb_addr2line::ContextPdbData::try_from_pdb(pdb).ok()
    }

    // Only download symbols from symbol servers if the env var is set
    let use_symsrv = std::env::var("_NT_SYMBOL_PATH").is_ok();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    for (path, image_base, image_size) in images {
        let path_str = match path.to_str() {
            Some(x) => x,
            _ => continue,
        };
        // Convert the \Device\HardDiskVolume path to a verbatim path \\?\HardDiskVolume
        let verbatim_path_os: OsString = path_str
            .trim_end_matches('\0')
            .replacen("\\Device\\", "\\\\?\\", 1)
            .into();

        let path = PathBuf::from(verbatim_path_os);

        let image_contents = match std::fs::read(&path) {
            Ok(x) => x,
            _ => continue,
        };
        let image_name = path.file_name().unwrap();
        let pe_file = match object::File::parse(&image_contents[..]) {
            Ok(x) => x,
            _ => continue,
        };

        let (pdb_path, pdb_guid, pdb_age) = match pe_file.pdb_info() {
            Ok(Some(x)) => (x.path(), x.guid(), x.age()),
            _ => continue,
        };
        let pdb_path = match std::str::from_utf8(pdb_path) {
            Ok(x) => x,
            _ => continue,
        };
        let mut pdb_path = PathBuf::from(pdb_path);
        if pdb_path.is_relative() {
            pdb_path = path.parent().unwrap().join(pdb_path);
        }
        if pdb_path.exists() {
            let mut file = match std::fs::File::open(pdb_path) {
                Err(_) => continue,
                Ok(x) => x,
            };
            let mut file_bytes = Vec::with_capacity(0);
            if file.read_to_end(&mut file_bytes).is_err() {
                continue;
            }
            let pdb_ctx = match owned_pdb(file_bytes) {
                Some(x) => x,
                _ => continue,
            };

            pdb_db.push((*image_base, *image_size, image_name.to_owned(), pdb_ctx));
        } else if use_symsrv {
            let pdb_filename = match pdb_path.file_name() {
                Some(x) => x,
                _ => continue,
            };

            let symbol_cache =
                symsrv::SymbolCache::new(symsrv::get_symbol_path_from_environment(""), false);

            let mut guid_string = String::new();
            use std::fmt::Write;
            for byte in pdb_guid[..4].iter().rev() {
                write!(&mut guid_string, "{byte:02X}").unwrap();
            }
            write!(&mut guid_string, "{:02X}", pdb_guid[5]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[4]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[7]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[6]).unwrap();
            for byte in &pdb_guid[8..] {
                write!(&mut guid_string, "{byte:02X}").unwrap();
            }
            write!(&mut guid_string, "{pdb_age:X}").unwrap();
            let guid_str = std::ffi::OsStr::new(&guid_string);

            let relative_path: PathBuf = [pdb_filename, guid_str, pdb_filename].iter().collect();

            if let Ok(rt) = &rt {
                if let Ok(file_contents) = rt.block_on(symbol_cache.get_file(&relative_path)) {
                    let pdb_ctx = match owned_pdb(file_contents.to_vec()) {
                        Some(x) => x,
                        _ => continue,
                    };
                    pdb_db.push((*image_base, *image_size, image_name.to_owned(), pdb_ctx));
                }
            }
        }
    }
    pdb_db
}
impl<'a> CallStack<'a> {
    /// Iterate addresses in this callstack
    ///
    /// This also performs symbol resolution if possible, and tries to find the image (DLL/EXE) it comes from
    fn iter_resolved_addresses<
        F: for<'b> FnMut(u64, u64, &'b [&'b str], Option<&'b str>) -> std::io::Result<()>,
    >(
        &'a self,
        pdb_db: &'a PdbDb,
        v: &mut Vec<&'_ str>,
        mut f: F,
    ) -> Result<()> {
        fn reuse_vec<T, U>(mut v: Vec<T>) -> Vec<U> {
            // See https://users.rust-lang.org/t/pattern-how-to-reuse-a-vec-str-across-loop-iterations/61657/3
            assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<U>());
            assert_eq!(std::mem::align_of::<T>(), std::mem::align_of::<U>());
            v.clear();
            v.into_iter().map(|_| unreachable!()).collect()
        }
        let displacement = 0u64;
        let mut symbol_names_storage = reuse_vec(std::mem::take(v));
        for &addr in self.stack {
            if addr == 0 {
                *v = symbol_names_storage;
                return Ok(());
            }
            let mut symbol_names = symbol_names_storage;

            let module = pdb_db.range(..addr).next_back();
            let module = match module {
                None => {
                    (f)(addr, 0, &[], None).map_err(Error::Write)?;
                    symbol_names_storage = reuse_vec(symbol_names);
                    continue;
                }
                Some(x) => x.1,
            };
            let image_name = module.2.to_str();
            let addr_in_module = addr - module.0;

            let procedure_frames = match module.3.find_frames(addr_in_module as u32) {
                Ok(Some(x)) => x,
                _ => {
                    (f)(addr, 0, &[], image_name).map_err(Error::Write)?;
                    symbol_names_storage = reuse_vec(symbol_names);
                    continue;
                }
            };
            for frame in &procedure_frames.frames {
                symbol_names.push(frame.function.as_deref().unwrap_or("Unknown"));
            }
            (f)(addr, displacement, &symbol_names, image_name).map_err(Error::Write)?;
            symbol_names_storage = reuse_vec(symbol_names);
        }
        *v = symbol_names_storage;
        Ok(())
    }
}

impl CollectionResults {
    /// Iterate the distinct callstacks sampled in this execution
    pub fn iter_callstacks(&self) -> impl std::iter::Iterator<Item = CallStack<'_>> {
        self.0.stack_counts_hashmap.iter().map(|x| CallStack {
            stack: x.0,
            sample_count: *x.1,
        })
    }
    /// Resolve call stack symbols and write a dtrace-like sampling report to `w`
    pub fn write_dtrace<W: Write>(&self, mut w: W) -> Result<()> {
        let pdbs = find_pdbs(&self.0.image_paths);
        let pdb_db: PdbDb = pdbs
            .iter()
            .filter_map(|(a, b, c, d)| d.make_context().ok().map(|d| (*a, (*a, *b, c.clone(), d))))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut v = vec![];

        for callstack in self.iter_callstacks() {
            let mut empty_callstack = true;
            callstack.iter_resolved_addresses(
                &pdb_db,
                &mut v,
                |address, displacement, symbol_names, image_name| {
                    if !self.0.show_kernel_samples {
                        // kernel addresses have the highest bit set on windows
                        if address & (1 << 63) != 0 {
                            return Ok(());
                        }
                    }
                    let mut printed = false;
                    for symbol_name in symbol_names {
                        if let Some(image_name) = image_name {
                            printed = true;
                            if displacement != 0 {
                                writeln!(w, "\t\t{image_name}`{symbol_name}+0x{displacement:X}")?;
                            } else {
                                writeln!(w, "\t\t{image_name}`{symbol_name}")?;
                            }
                        } else {
                            // Image name not found
                            if displacement != 0 {
                                printed = true;
                                writeln!(w, "\t\t{symbol_name}+0x{displacement:X}")?;
                            } else if !symbol_name.is_empty() {
                                printed = true;
                                writeln!(w, "\t\t{symbol_name}")?;
                            }
                        }
                    }
                    if symbol_names.is_empty() || !printed {
                        // Symbol not found
                        writeln!(w, "\t\t`0x{address:X}")?;
                    }
                    empty_callstack = false;
                    Ok(())
                },
            )?;

            if !empty_callstack {
                let count = callstack.sample_count;
                write!(w, "\t\t{count}\n\n").map_err(Error::Write)?;
            }
        }
        Ok(())
    }
}

// https://docs.microsoft.com/en-us/windows/win32/etw/image-load
#[allow(non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct ImageLoadEvent {
    ImageBase: usize,
    ImageSize: usize,
    ProcessId: u32,
    ImageCheckSum: u32,
    TimeDateStamp: u32,
    Reserved0: u32,
    DefaultBase: usize,
    Reserved1: u32,
    Reserved2: u32,
    Reserved3: u32,
    Reserved4: u32,
}
