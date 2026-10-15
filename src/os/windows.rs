//! Windows.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, STILL_ACTIVE, SYSTEMTIME, SetHandleInformation,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW, CredWriteW,
};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    SetConsoleMode,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetExitCodeProcess, OpenProcess,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

pub const KEYRING: &str = "Windows Credential Manager";
const CRED_TARGET: &str = "iitg-connect";

pub fn spawn_detached(cmd: &mut Command) -> io::Result<Child> {
    // Keep our console/pipe handles out of the background process, or it would hold the
    // terminal (or whoever is reading our output) open until it exits.
    for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe { SetHandleInformation(GetStdHandle(std_handle), HANDLE_FLAG_INHERIT, 0) };
    }
    // No console and its own process group (so Ctrl+C and closing the terminal don't reach
    // it); also leave the terminal's job object when the job allows it.
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    cmd.creation_flags(flags | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
        .or_else(|_| cmd.creation_flags(flags).spawn())
}

/// Whether `pid` is alive and is our background process, not a recycled pid.
pub fn is_daemon(pid: u32) -> bool {
    if pid == std::process::id() {
        return false;
    }
    let Some(process) = open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid) else {
        return false;
    };
    let mut code = 0;
    let alive = unsafe { GetExitCodeProcess(process, &mut code) } != 0 && code == STILL_ACTIVE as u32;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let named = unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } != 0;
    unsafe { CloseHandle(process) };

    // Windows has no simple way to read another process's arguments; the executable name
    // is enough to tell a recycled pid apart.
    let image = PathBuf::from(OsString::from_wide(&buf[..len as usize]));
    alive && named && std::env::current_exe().is_ok_and(|ours| same_file_name(&ours, &image))
}

fn same_file_name(a: &Path, b: &Path) -> bool {
    match (a.file_name(), b.file_name()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

pub fn terminate(pid: u32) {
    if let Some(process) = open_process(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, pid) {
        unsafe {
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 2500);
            CloseHandle(process);
        }
    }
}

fn open_process(access: u32, pid: u32) -> Option<HANDLE> {
    let process = unsafe { OpenProcess(access, 0, pid) };
    (!process.is_null()).then_some(process)
}

/// Runs `f` (which reads from stdin) with console echo turned off.
pub fn without_echo<T>(f: impl FnOnce() -> T) -> T {
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    let is_console = unsafe { GetConsoleMode(input, &mut mode) } != 0;
    if is_console {
        unsafe { SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT) };
    }
    let result = f();
    if is_console {
        unsafe { SetConsoleMode(input, mode) };
        println!();
    }
    result
}

// %LOCALAPPDATA% is already private to the user, so no extra permissions are needed.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

pub fn private_file(opts: &mut OpenOptions) -> &mut OpenOptions {
    opts
}

fn app_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("iitg-connect")
}

pub fn runtime_dir() -> PathBuf {
    app_dir()
}

pub fn config_dir() -> PathBuf {
    app_dir()
}

pub fn state_dir() -> PathBuf {
    app_dir()
}

/// [year, month, day, hour, minute, second] in local time.
pub fn local_time(secs: u64) -> [i64; 6] {
    // FILETIME counts 100 ns ticks since 1601-01-01.
    let ticks = (secs + 11_644_473_600) * 10_000_000;
    let file_time = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe {
        FileTimeToSystemTime(&file_time, &mut utc);
        if SystemTimeToTzSpecificLocalTime(ptr::null(), &utc, &mut local) == 0 {
            local = utc;
        }
    }
    [local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond].map(i64::from)
}

// ---------------------------------------------------------------- keyring

pub fn keyring_load() -> Option<String> {
    let target = wide(CRED_TARGET);
    let mut cred: *mut CREDENTIALW = ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
        return None;
    }
    let blob = unsafe { std::slice::from_raw_parts((*cred).CredentialBlob, (*cred).CredentialBlobSize as usize) }.to_vec();
    unsafe { CredFree(cred as *const _) };
    String::from_utf8(blob).ok()
}

pub fn keyring_store(secret: &str) -> bool {
    let mut target = wide(CRED_TARGET);
    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target.as_mut_ptr();
    cred.CredentialBlobSize = secret.len() as u32;
    cred.CredentialBlob = secret.as_ptr() as *mut u8;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    unsafe { CredWriteW(&cred, 0) != 0 }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
