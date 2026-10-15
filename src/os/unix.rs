//! Linux and macOS.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

pub fn spawn_detached(cmd: &mut Command) -> io::Result<Child> {
    // New session: detach from the terminal so closing it doesn't kill us.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Whether `pid` is alive and is our background process, not a recycled pid.
#[cfg(target_os = "linux")]
pub fn is_daemon(pid: u32) -> bool {
    fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c.split(|&b| b == 0).any(|a| a == b"__daemon"))
}

/// Whether `pid` is alive and is our background process, not a recycled pid.
#[cfg(not(target_os = "linux"))]
pub fn is_daemon(pid: u32) -> bool {
    Command::new("ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .output()
        .is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).split_whitespace().any(|a| a == "__daemon")
        })
}

pub fn terminate(pid: u32) {
    let pid = pid as libc::pid_t;
    unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..50 {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs `f` (which reads from stdin) with terminal echo turned off.
pub fn without_echo<T>(f: impl FnOnce() -> T) -> T {
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let is_tty = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } == 0;
    if is_tty {
        let mut silent = term;
        silent.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &silent) };
    }
    let result = f();
    if is_tty {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };
        println!();
    }
    result
}

pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

pub fn private_file(opts: &mut OpenOptions) -> &mut OpenOptions {
    opts.mode(0o600)
}

/// For the pid and session files: the per-user tmpfs on Linux (cleared on reboot, never
/// hits disk), the per-user $TMPDIR on macOS.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("iitg-connect"),
        None => std::env::temp_dir().join(format!("iitg-connect-{}", unsafe { libc::getuid() })),
    }
}

pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config")
}

pub fn state_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state")
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    let base = std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        home.join(fallback)
    });
    base.join("iitg-connect")
}

/// [year, month, day, hour, minute, second] in local time.
pub fn local_time(secs: u64) -> [i64; 6] {
    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    [tm.tm_year as i64 + 1900, tm.tm_mon as i64 + 1, tm.tm_mday as i64, tm.tm_hour as i64, tm.tm_min as i64, tm.tm_sec as i64]
}

// ---------------------------------------------------------------- keyring

/// GNOME Keyring / KWallet, through the Secret Service CLI (avoids linking D-Bus ourselves).
#[cfg(not(target_os = "macos"))]
mod keyring {
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub const KEYRING: &str = "the system keyring";
    const ATTRS: [&str; 2] = ["service", "iitg-connect"];

    pub fn keyring_load() -> Option<String> {
        Command::new("secret-tool")
            .arg("lookup")
            .args(ATTRS)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    }

    pub fn keyring_store(secret: &str) -> bool {
        Command::new("secret-tool")
            .args(["store", "--label=IITG internet login (iitg-connect)"])
            .args(ATTRS)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().expect("piped stdin").write_all(secret.as_bytes())?;
                child.wait()
            })
            .is_ok_and(|s| s.success())
    }
}

#[cfg(target_os = "macos")]
mod keyring {
    use security_framework::passwords::{get_generic_password, set_generic_password};

    pub const KEYRING: &str = "the macOS Keychain";
    const SERVICE: &str = "iitg-connect";
    const ACCOUNT: &str = "credentials";

    pub fn keyring_load() -> Option<String> {
        String::from_utf8(get_generic_password(SERVICE, ACCOUNT).ok()?).ok()
    }

    pub fn keyring_store(secret: &str) -> bool {
        set_generic_password(SERVICE, ACCOUNT, secret.as_bytes()).is_ok()
    }
}

pub use keyring::{KEYRING, keyring_load, keyring_store};
