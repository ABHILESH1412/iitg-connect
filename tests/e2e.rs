//! End-to-end run of the real binary against a mock FortiGate portal: wrong password,
//! update, connect, the background process, status and stop/logout. Runs on every OS in CI.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default)]
struct Portal {
    magics: Vec<String>,
    sessions: Vec<String>,
    logouts: usize,
    counter: u64,
}

fn start_portal() -> (String, Arc<Mutex<Portal>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(Portal::default()));
    let shared = state.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, &shared);
        }
    });
    (base, state)
}

fn handle(stream: TcpStream, state: &Mutex<Portal>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.trim_end().is_empty() {
            break;
        }
        headers.push(line.trim_end().to_string());
    }
    // Like the real portal: header names are matched case-sensitively, and a request it
    // can't parse just gets the connection dropped.
    let header = |name: &str| headers.iter().find_map(|h| h.strip_prefix(&format!("{name}: ")).map(str::to_string));
    if header("Host").is_none() {
        return;
    }
    let mut body = vec![0; header("Content-Length").and_then(|l| l.parse().ok()).unwrap_or(0)];
    reader.read_exact(&mut body).unwrap();
    let body = String::from_utf8(body).unwrap();

    let target = request_line.split(' ').nth(1).unwrap_or_default().to_string();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let mut st = state.lock().unwrap();
    let reply = match (request_line.split(' ').next().unwrap(), path) {
        ("GET", "/login") if !query.is_empty() => {
            st.counter += 1;
            let magic = format!("{:016x}", st.counter);
            st.magics.push(magic.clone());
            format!(
                r#"<form action="/" method="post"><input type="hidden" name="4Tredir" value="x/login?"><input type="hidden" name="magic" value="{magic}"><input name="username"></form>"#
            )
        }
        ("POST", "/") => {
            let field = |k: &str| body.split('&').find_map(|kv| kv.strip_prefix(&format!("{k}="))).unwrap_or("");
            if st.magics.iter().any(|m| m == field("magic")) && field("username") == "test" && field("password") == "s3cret" {
                st.counter += 1;
                let id = format!("{:016x}", st.counter);
                st.sessions.push(id.clone());
                format!(r#"<html><script>window.location="{}/keepalive?{id}";</script></html>"#, header("Host").map(|h| format!("http://{h}")).unwrap())
            } else {
                "<html><body>Firewall authentication failed. Please try again.</body></html>".into()
            }
        }
        ("GET", "/keepalive") if st.sessions.iter().any(|s| s == query) => "<html>Authentication Keepalive</html>".into(),
        ("GET", "/logout") => {
            st.sessions.retain(|s| s != query);
            st.logouts += 1;
            "logged out".into()
        }
        _ => return,
    };
    let mut stream = stream;
    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len());
}

/// Runs the binary with `args`, feeding `input` on stdin; returns (success, output).
fn run(dir: &Path, portal: &str, args: &[&str], input: &str) -> (bool, String) {
    // Output goes to a file, not a pipe: the background process is spawned from the
    // command under test and must not keep our end of a pipe open.
    let out_path = dir.join("out.txt");
    let out = File::create(&out_path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_iitg-connect"))
        .args(args)
        .env("IITG_PORTAL", portal)
        .env("IITG_TEST_DIR", dir)
        .stdin(Stdio::piped())
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let ok = child.wait().unwrap().success();
    let output = fs::read_to_string(&out_path).unwrap();
    println!("$ iitg-connect {}\n{output}", args.join(" "));
    (ok, output)
}

#[test]
fn connect_status_stop() {
    let dir: PathBuf = std::env::temp_dir().join(format!("iitg-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (portal, state) = start_portal();
    let run = |args: &[&str], input: &str| run(&dir, &portal, args, input);

    let (ok, out) = run(&["connect"], "test\nwrong\n");
    assert!(!ok && out.contains("wrong username or password"), "{out}");
    assert!(run(&["status"], "").1.contains("Not running"));

    let (ok, out) = run(&["update"], "test\ns3cret\n");
    assert!(ok && out.contains("Saved to"), "{out}");

    let (ok, out) = run(&["connect"], "");
    assert!(ok && out.contains("connected.") && out.contains("Running in the background"), "{out}");

    let (_, out) = run(&["status"], "");
    assert!(out.contains("Running in the background") && out.contains("logged in"), "{out}");

    let (ok, out) = run(&["connect"], "");
    assert!(ok && out.contains("Already running"), "{out}");

    let (ok, out) = run(&["stop"], "");
    assert!(ok && out.contains("Stopped the background process") && out.contains("Logged out"), "{out}");
    assert_eq!(state.lock().unwrap().logouts, 1);
    assert!(state.lock().unwrap().sessions.is_empty());

    assert!(run(&["status"], "").1.contains("Not running"));
    let _ = fs::remove_dir_all(&dir);
}
