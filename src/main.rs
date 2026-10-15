//! iitg-connect: keeps you logged in to the IIT Guwahati FortiGate captive portal
//! (https://agnigarh.iitg.ac.in:1442) from a tiny background process — no browser needed.
//! Runs on Linux, macOS and Windows; the OS-specific bits live in `os/`.
//!
//! One binary, dispatched on the name it is invoked as (or on its first argument):
//!   iitg-connect   log in now and keep the session alive in the background
//!   iitg-stop      stop the background process and log out of the portal
//!   iitg-update    change the saved username/password
//!   iitg-status    show whether the background process is running

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg_attr(unix, path = "os/unix.rs")]
#[cfg_attr(windows, path = "os/windows.rs")]
mod os;

const PORTAL_URL: &str = "https://agnigarh.iitg.ac.in:1442";
const DEFAULT_INTERVAL_MIN: u64 = 10;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);
const LOG_MAX_BYTES: u64 = 64 * 1024;

type Result<T, E = String> = std::result::Result<T, E>;

fn main() {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let name = Path::new(&argv0).file_stem().and_then(|n| n.to_str()).unwrap_or_default();
    let cmd = match name {
        "iitg-stop" => "stop".to_string(),
        "iitg-update" => "update".to_string(),
        "iitg-status" => "status".to_string(),
        _ => args.next().unwrap_or_else(|| "connect".to_string()),
    };

    let result = match cmd.as_str() {
        "connect" | "start" => connect(),
        "stop" => stop(),
        "update" => update(),
        "status" => status(),
        "__daemon" => daemon(),
        "help" | "-h" | "--help" => {
            print!("{}", HELP);
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{HELP}")),
    };
    if let Err(e) = result {
        eprintln!("iitg: {e}");
        process::exit(1);
    }
}

const HELP: &str = "\
Usage:
  iitg-connect   log in to the IITG network and stay logged in (runs in background)
  iitg-stop      stop the background process and log out
  iitg-update    change the saved username/password
  iitg-status    show whether it is running

Environment:
  IITG_INTERVAL  minutes between session refreshes (default 10)
";

// ---------------------------------------------------------------- commands

fn connect() -> Result<()> {
    if let Some(pid) = running_pid() {
        println!("Already running in the background (pid {pid}). Use iitg-stop to stop it.");
        return Ok(());
    }

    let creds = match load_creds() {
        Some(c) => c,
        None => {
            println!("No saved IITG credentials found. They will be stored securely on this device.");
            let c = prompt_creds()?;
            println!("Saved to {}.", save_creds(&c)?);
            c
        }
    };

    print!("Logging in as {}... ", creds.user);
    let _ = io::stdout().flush();
    let session = match Portal::new().login(&creds) {
        Ok(url) => {
            println!("connected.");
            Some(url)
        }
        Err(LoginError::BadCredentials) => {
            println!("failed.");
            return Err("wrong username or password. Run iitg-update to change them.".into());
        }
        Err(LoginError::Other(e)) => {
            println!("failed ({e}).\nWill keep retrying in the background.");
            write_state(None, &format!("login failed: {e}"));
            None
        }
    };
    if session.is_some() {
        write_state(session.as_deref(), "logged in");
    }

    let pid = spawn_daemon(&creds, session.as_deref())?;
    println!(
        "Running in the background (pid {pid}), refreshing the session every {} min. Stop with iitg-stop.",
        interval().as_secs() / 60
    );
    Ok(())
}

fn stop() -> Result<()> {
    let state = read_state();
    match running_pid() {
        Some(pid) => {
            kill_and_wait(pid);
            println!("Stopped the background process.");
        }
        None => println!("Background process was not running."),
    }
    let _ = fs::remove_file(pid_file());
    let _ = fs::remove_file(state_file());

    if let Some(url) = state.and_then(|s| s.session) {
        match Portal::new().logout(&url) {
            Ok(()) => println!("Logged out of the IITG portal."),
            Err(e) => println!("Could not log out of the portal ({e})."),
        }
    }
    Ok(())
}

fn update() -> Result<()> {
    println!("Enter your new IITG credentials.");
    let creds = prompt_creds()?;
    println!("Saved to {}.", save_creds(&creds)?);

    if let Some(pid) = running_pid() {
        println!("Restarting the background process with the new credentials.");
        kill_and_wait(pid);
        let _ = fs::remove_file(pid_file());
        return connect();
    }
    Ok(())
}

fn status() -> Result<()> {
    match running_pid() {
        Some(pid) => println!("Running in the background (pid {pid})."),
        None => println!("Not running."),
    }
    if let Some(s) = read_state() {
        println!("Last update {}: {}", format_time(s.time), s.message);
    }
    println!("Log: {}", log_file().display());
    Ok(())
}

// ---------------------------------------------------------------- background loop

fn spawn_daemon(creds: &Creds, session: Option<&str>) -> Result<u32> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own executable: {e}"))?;
    let log = open_log().map_err(|e| format!("cannot open log file: {e}"))?;

    let mut cmd = Command::new(exe);
    cmd.arg("__daemon")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(log);
    let mut child = os::spawn_detached(&mut cmd).map_err(|e| format!("cannot start background process: {e}"))?;

    // Credentials go over a pipe, never via argv/env (both are visible to other processes).
    let mut stdin = child.stdin.take().expect("piped stdin");
    write!(stdin, "{}\n{}\n{}\n", creds.user, creds.pass, session.unwrap_or(""))
        .map_err(|e| format!("cannot hand over to background process: {e}"))?;
    drop(stdin);

    fs::write(pid_file(), child.id().to_string()).map_err(|e| format!("cannot write pid file: {e}"))?;
    Ok(child.id())
}

fn daemon() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
    let mut lines = input.split('\n');
    let creds = Creds {
        user: lines.next().unwrap_or_default().to_string(),
        pass: lines.next().unwrap_or_default().to_string(),
    };
    let mut session = lines.next().filter(|s| !s.is_empty()).map(str::to_string);
    drop(input);

    let portal = Portal::new();
    let every = interval();
    let mut failures = 0u32;
    let mut next = SystemTime::now();

    log(&format!("started (pid {}), refreshing every {} min", process::id(), every.as_secs() / 60));
    if session.is_some() {
        next += every;
    }

    loop {
        // Sleep in short steps against the wall clock: monotonic sleeps don't advance
        // while the laptop is suspended, so we'd otherwise wake up late after a resume.
        while let Ok(left) = next.duration_since(SystemTime::now()) {
            thread::sleep(left.min(Duration::from_secs(20)));
        }

        if let Some(url) = &session {
            match portal.keepalive(url) {
                Ok(()) => {
                    failures = 0;
                    write_state(session.as_deref(), "session refreshed");
                    next = SystemTime::now() + every;
                    continue;
                }
                Err(e) => log(&format!("keepalive failed ({e}), logging in again")),
            }
        }

        match portal.login(&creds) {
            Ok(url) => {
                log("logged in");
                failures = 0;
                session = Some(url);
                write_state(session.as_deref(), "logged in");
                next = SystemTime::now() + every;
            }
            Err(LoginError::BadCredentials) => {
                log("portal rejected the username/password; stopping. Run iitg-update.");
                write_state(None, "stopped: wrong username or password (run iitg-update)");
                let _ = fs::remove_file(pid_file());
                process::exit(1);
            }
            Err(LoginError::Other(e)) => {
                failures += 1;
                // Off campus or Wi-Fi down: back off, and don't flood the log.
                if failures == 1 || failures.is_multiple_of(50) {
                    log(&format!("login failed ({e}), retrying (attempt {failures})"));
                }
                write_state(session.as_deref(), &format!("login failed: {e}"));
                let delay = Duration::from_secs(15 << failures.min(5)).min(MAX_RETRY_DELAY);
                next = SystemTime::now() + delay;
            }
        }
    }
}

fn portal() -> String {
    // Debug builds can be pointed at a local mock portal for testing.
    #[cfg(debug_assertions)]
    if let Ok(url) = std::env::var("IITG_PORTAL") {
        return url;
    }
    PORTAL_URL.to_string()
}

/// Debug builds only: keep every file in this directory and skip the keyring (for tests).
fn test_dir() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("IITG_TEST_DIR") {
        return Some(dir.into());
    }
    None
}

fn interval() -> Duration {
    let min = std::env::var("IITG_INTERVAL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&m| (1..=120).contains(&m))
        .unwrap_or(DEFAULT_INTERVAL_MIN);
    Duration::from_secs(min * 60)
}

fn running_pid() -> Option<u32> {
    let pid: u32 = fs::read_to_string(pid_file()).ok()?.trim().parse().ok()?;
    os::is_daemon(pid).then_some(pid)
}

fn kill_and_wait(pid: u32) {
    os::terminate(pid);
}

// ---------------------------------------------------------------- portal client

enum LoginError {
    BadCredentials,
    Other(String),
}

impl From<String> for LoginError {
    fn from(e: String) -> Self {
        LoginError::Other(e)
    }
}

// Uses ureq 2 on purpose: ureq 3 sends lowercase header names ("host:", "content-length:"),
// which the portal's FortiGate HTTP parser doesn't recognise, so it drops the login POST.
struct Portal {
    agent: ureq::Agent,
    base: String,
}

impl Portal {
    fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .redirects(0)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
            .build();
        Portal { agent, base: portal() }
    }

    /// Returns (status, Location header, body).
    fn get(&self, url: &str) -> Result<(u16, Option<String>, String)> {
        read_response(self.agent.get(url).call())
    }

    /// Does what the browser does: fetch the login form for a fresh `magic` token, then
    /// post the credentials. Returns the keepalive URL of the new session.
    fn login(&self, creds: &Creds) -> Result<String, LoginError> {
        // The portal only serves the form with a query string present ("/login" gets an empty
        // reply), and ureq drops an empty "?", so ask for "/login?1".
        let (_, _, page) = self.get(&format!("{}/login?1", self.base))?;
        let magic = hidden_input(&page, "magic")
            .ok_or_else(|| format!("login page has no token: {}", snippet(&page)))?;
        let redir = hidden_input(&page, "4Tredir").unwrap_or_else(|| format!("{}/login?", self.base));

        let resp = self.agent.post(&format!("{}/", self.base)).send_form(&[
                ("4Tredir", redir.as_str()),
                ("magic", magic.as_str()),
                ("username", creds.user.as_str()),
                ("password", creds.pass.as_str()),
        ]);
        let (status, location, body) = read_response(resp)?;

        if let Some(url) = location.filter(|l| l.contains("keepalive?")).or_else(|| find_keepalive(&body)) {
            return Ok(if url.starts_with("http") { url } else { format!("{}{url}", self.base) });
        }
        if body.to_ascii_lowercase().contains("authentication failed") {
            return Err(LoginError::BadCredentials);
        }
        Err(LoginError::Other(format!("unexpected portal reply (HTTP {status}): {}", snippet(&body))))
    }

    fn keepalive(&self, url: &str) -> Result<()> {
        let (status, _, body) = self.get(url)?;
        // A live session answers with the keepalive page itself; a dead one gets the login form.
        if status == 200 && body.contains("keepalive") && !body.contains("name=\"magic\"") {
            Ok(())
        } else {
            Err(format!("HTTP {status}: {}", snippet(&body)))
        }
    }

    fn logout(&self, keepalive_url: &str) -> Result<()> {
        let (status, _, _) = self.get(&keepalive_url.replacen("/keepalive?", "/logout?", 1))?;
        if status < 400 { Ok(()) } else { Err(format!("HTTP {status}")) }
    }
}

/// Returns (status, Location header, body); HTTP error statuses are returned, not raised.
fn read_response(result: Result<ureq::Response, ureq::Error>) -> Result<(u16, Option<String>, String)> {
    let resp = match result {
        Ok(resp) | Err(ureq::Error::Status(_, resp)) => resp,
        Err(ureq::Error::Transport(e)) => return Err(format!("cannot reach portal: {e}")),
    };
    let status = resp.status();
    let location = resp.header("location").map(str::to_string);
    let body = resp.into_string().map_err(|e| format!("cannot reach portal: {e}"))?;
    Ok((status, location, body))
}

/// Value of `<input ... name="NAME" value="...">`.
fn hidden_input(page: &str, name: &str) -> Option<String> {
    let start = page.find(&format!("name=\"{name}\""))?;
    let tag = &page[start..start + page[start..].find('>')?];
    let v = tag.find("value=\"")? + "value=\"".len();
    let len = tag[v..].find('"')?;
    Some(tag[v..v + len].to_string())
}

/// The keepalive URL the portal redirects to after a successful login.
fn find_keepalive(body: &str) -> Option<String> {
    let idx = body.find("keepalive?")?;
    let start = body[..idx].rfind(['"', '\'']).map_or(0, |i| i + 1);
    let end = idx + body[idx..].find(['"', '\'', '<', ' '])?;
    Some(body[start..end].to_string())
}

/// Short plain-text excerpt of an HTML page, for error messages.
fn snippet(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    let body = html.find("<body").map_or(html, |i| &html[i..]);
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() { "(empty)".into() } else { text.chars().take(160).collect() }
}

// ---------------------------------------------------------------- credentials

struct Creds {
    user: String,
    pass: String,
}

impl Creds {
    fn parse(blob: &str) -> Option<Creds> {
        let (user, pass) = blob.split_once('\n')?;
        let pass = pass.strip_suffix('\n').unwrap_or(pass);
        (!user.is_empty() && !pass.is_empty()).then(|| Creds { user: user.into(), pass: pass.into() })
    }
}

/// The OS keyring (GNOME Keyring/KWallet, macOS Keychain, Windows Credential Manager)
/// first, then the fallback file.
fn load_creds() -> Option<Creds> {
    let from_keyring = if test_dir().is_none() { os::keyring_load() } else { None };
    from_keyring
        .and_then(|blob| Creds::parse(&blob))
        .or_else(|| Creds::parse(&fs::read_to_string(creds_file()).ok()?))
}

/// Returns a human description of where the credentials were stored.
fn save_creds(creds: &Creds) -> Result<String> {
    let blob = format!("{}\n{}", creds.user, creds.pass);

    if test_dir().is_none() && os::keyring_store(&blob) {
        let _ = fs::remove_file(creds_file());
        return Ok(os::KEYRING.into());
    }

    // No keyring available: a file only you can read.
    let path = creds_file();
    if let Some(dir) = path.parent() {
        os::create_private_dir(dir).map_err(|e| e.to_string())?;
    }
    let _ = fs::remove_file(&path);
    os::private_file(OpenOptions::new().write(true).create_new(true))
        .open(&path)
        .and_then(|mut f| f.write_all(blob.as_bytes()))
        .map_err(|e| format!("cannot save credentials: {e}"))?;
    Ok(format!("{} (readable only by you; no system keyring found)", path.display()))
}

fn prompt_creds() -> Result<Creds> {
    print!("IITG username: ");
    let _ = io::stdout().flush();
    let mut user = String::new();
    io::stdin().lock().read_line(&mut user).map_err(|e| e.to_string())?;
    let user = user.trim().to_string();

    let pass = read_password("IITG password: ").map_err(|e| e.to_string())?;
    if user.is_empty() || pass.is_empty() {
        return Err("username and password must not be empty".into());
    }
    Ok(Creds { user, pass })
}

/// Reads a line from the terminal with echo turned off.
fn read_password(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    os::without_echo(|| io::stdin().lock().read_line(&mut line))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

// ---------------------------------------------------------------- files

fn runtime_dir() -> PathBuf {
    let dir = test_dir().unwrap_or_else(os::runtime_dir);
    let _ = os::create_private_dir(&dir);
    dir
}

fn pid_file() -> PathBuf {
    runtime_dir().join("pid")
}

fn state_file() -> PathBuf {
    runtime_dir().join("state")
}

fn creds_file() -> PathBuf {
    test_dir().unwrap_or_else(os::config_dir).join("credentials")
}

fn log_file() -> PathBuf {
    test_dir().unwrap_or_else(os::state_dir).join("iitg-connect.log")
}

struct State {
    session: Option<String>,
    time: u64,
    message: String,
}

fn write_state(session: Option<&str>, message: &str) {
    let path = state_file();
    let tmp = path.with_extension("tmp");
    let data = format!("{}\n{}\n{}\n", session.unwrap_or(""), unix_now(), message);
    let ok = os::private_file(OpenOptions::new().write(true).create(true).truncate(true))
        .open(&tmp)
        .and_then(|mut f| f.write_all(data.as_bytes()));
    if ok.is_ok() {
        let _ = fs::rename(&tmp, &path);
    }
}

fn read_state() -> Option<State> {
    let data = fs::read_to_string(state_file()).ok()?;
    let mut lines = data.lines();
    Some(State {
        session: lines.next().filter(|s| !s.is_empty()).map(str::to_string),
        time: lines.next()?.parse().ok()?,
        message: lines.next().unwrap_or_default().to_string(),
    })
}

fn open_log() -> io::Result<fs::File> {
    let path = log_file();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
        let _ = fs::write(&path, "");
    }
    OpenOptions::new().create(true).append(true).open(path)
}

fn log(msg: &str) {
    if let Ok(mut f) = open_log() {
        let _ = writeln!(f, "{} {msg}", format_time(unix_now()));
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn format_time(secs: u64) -> String {
    let [y, mo, d, h, mi, s] = os::local_time(secs);
    format!("{y}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_login_page() {
        let page = include_str!("../tests/fixtures/login_page.html");
        let magic = hidden_input(page, "magic").unwrap();
        assert!(magic.len() >= 8 && magic.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hidden_input(page, "4Tredir").unwrap(), "https://agnigarh.iitg.ac.in:1442/login?");
        assert!(find_keepalive(page).is_none());
    }

    #[test]
    fn finds_keepalive_url() {
        let body = r#"<html><script language="JavaScript">window.location="https://agnigarh.iitg.ac.in:1442/keepalive?0f0e0d0c0b0a0908";</script></html>"#;
        assert_eq!(
            find_keepalive(body).unwrap(),
            "https://agnigarh.iitg.ac.in:1442/keepalive?0f0e0d0c0b0a0908"
        );
    }

    #[test]
    fn parses_creds() {
        let c = Creds::parse("alice\np@ss word\n").unwrap();
        assert_eq!((c.user.as_str(), c.pass.as_str()), ("alice", "p@ss word"));
        assert!(Creds::parse("alice\n").is_none());
        assert!(Creds::parse("").is_none());
    }
}
