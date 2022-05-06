# winstacks

Collect CPU call stack samplles from a windows process.

Since the ["SampledProfile"](https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile) ETW events we use come from a ["kernel event provider"](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes)(PerfInfo) we must use the ETW ["Kernel Logger session"](https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants), which requires elevated priviledges. Therefore, **you must run winstack as administrator in order for it to work**.

The `winferno` binary can be used to generate a flamegraph using the [`inferno` library](https://github.com/jonhoo/inferno).

The `winstacks` binary can be used to generate a text file with the sample count of each call stack.

The `winstacks_dtrace` binary can be used as a dtrace replacement in [cargo-flamegraph](https://github.com/flamegraph-rs) via the DTRACE environment variable.

Examples:

    ./winferno.exe ./target/debug/x86-64-windows-msvc/some_binary_with_debuginfo.exe arg1 arg2 ; ./winferno_flamegraph.svg

    cargo build --release --bin winstacks_dtrace
    $ENV:DTRACE = "current_dir/target/release/winstacks_dtrace.exe" # Or set DTRACE="current_dir/target/release/winstacks_dtrace.exe" in cmd.exe
    cd some/other/project
    cargo flamegraph ; ./flamegraph.svg

I wrote this to be able to get flamegraphs using https://github.com/flamegraph-rs on windows.

This is built using the ETW(Event Tracing for Windows)]() API to collect CPU samples and DLL/EXE load events, and the [DbgHelp Symbol Handler API](https://docs.microsoft.com/en-us/windows/win32/debug/dbghelp-functions#symbol-handler) to translate the virtual addresses ETW gives us to symbol names.

# Future work?

- Test on windows 7 and probably fix the things that don't work.
- Make it possible to trace a pre-existing pid instead of requiring a command to launch.
- Use ETW filters to only receive events for the target process (We currently filter ourselves and discard events from other processes). See https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracea https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2 https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor specifically EVENT_FILTER_TYPE_PID (note: Does not work on Win7 via StartTrace, would need to use EnableTraceEx2 if we care about Win7)
- Write a general ETW rust library.
