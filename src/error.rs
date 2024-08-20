use windows::core::PSTR;
use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};

/// The errors that may occur in blondie.
#[derive(Debug)]
pub enum Error {
    /// Blondie requires administrator privileges
    NotAnAdmin,
    /// Error writing to the provided Writer
    Write(std::io::Error),
    /// Error spawning a suspended process
    SpawnErr(std::io::Error),
    /// Error waiting for child, abandoned
    WaitOnChildErrAbandoned,
    /// Error waiting for child, timed out
    WaitOnChildErrTimeout,
    /// A call to a windows API function returned an error and we didn't know how to handle it
    Other(WIN32_ERROR, String, &'static str),
    /// We require Windows 7 or greater
    UnsupportedOsVersion,
    /// This should never happen
    UnknownError,
}
/// A [`std::result::Result`] alias where the `Err` case is [`blondie::Error`](Error).
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn get_last_error(extra: &'static str) -> Error {
    const BUF_LEN: usize = 1024;
    let mut buf = [0u8; BUF_LEN];
    let code = unsafe { GetLastError() };
    let chars_written = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code.0,
            0,
            PSTR(buf.as_mut_ptr()),
            BUF_LEN as u32,
            None,
        )
    };
    assert!(chars_written != 0);
    let code_str = std::ffi::CStr::from_bytes_until_nul(&buf)
        .unwrap()
        .to_str()
        .unwrap_or("Invalid utf8 in error");
    Error::Other(code, code_str.to_string(), extra)
}
