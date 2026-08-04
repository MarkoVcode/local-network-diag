//! Command execution.
//!
//! Every external command in the engine goes through here, and the same two
//! rules apply as in the original TypeScript engine:
//!
//! 1. **argv arrays only** — `tokio::process::Command` never invokes a shell, so
//!    an IP or CIDR arriving from the UI cannot be interpreted as shell syntax.
//! 2. **every call is time-boxed** — one hung probe must not stall a scan.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct ExecResult {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    /// Killed by the timeout. Some probes (a fixed-window mDNS browse) expect this.
    pub timed_out: bool,
    /// The binary does not exist on this system.
    pub missing: bool,
}

impl ExecResult {
    /// True when the command produced usable output, even if it was killed by the
    /// timeout — a fixed-window browse is the normal case for that.
    pub fn has_output(&self) -> bool {
        !self.stdout.trim().is_empty()
    }
}

pub async fn run(program: &str, args: &[&str], timeout: Duration) -> ExecResult {
    let mut command = Command::new(program);
    command.args(args);
    command.kill_on_drop(true);
    command.stdin(std::process::Stdio::null());

    // Keep child console windows from flashing on Windows during a scan.
    // `tokio::process::Command` provides `creation_flags` directly, so importing
    // std's `CommandExt` here would be an unused import.
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    match tokio::time::timeout(timeout, command.output()).await {
        Ok(Ok(out)) => ExecResult {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            timed_out: false,
            missing: false,
        },
        Ok(Err(err)) => {
            let missing = err.kind() == std::io::ErrorKind::NotFound;
            ExecResult {
                ok: false,
                stdout: String::new(),
                stderr: err.to_string(),
                timed_out: false,
                missing,
            }
        }
        // `kill_on_drop` reaps the child when the future is dropped here.
        Err(_) => ExecResult {
            ok: false,
            stdout: String::new(),
            stderr: "timed out".into(),
            timed_out: true,
            missing: false,
        },
    }
}

/// Runs a command for a fixed window, returning whatever it emitted before being
/// stopped. Used by probes that stream results until killed (mDNS browsing).
pub async fn run_windowed(program: &str, args: &[&str], window: Duration) -> ExecResult {
    let mut command = Command::new(program);
    command
        .args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            let missing = err.kind() == std::io::ErrorKind::NotFound;
            return ExecResult {
                ok: false,
                stdout: String::new(),
                stderr: err.to_string(),
                timed_out: false,
                missing,
            };
        }
    };

    let mut stdout_pipe = child.stdout.take();
    let mut buffer = Vec::new();

    let collect = async {
        if let Some(pipe) = stdout_pipe.as_mut() {
            use tokio::io::AsyncReadExt;
            let _ = pipe.read_to_end(&mut buffer).await;
        }
    };

    let timed_out = tokio::time::timeout(window, collect).await.is_err();
    let _ = child.start_kill();
    let _ = child.wait().await;

    ExecResult {
        ok: !buffer.is_empty(),
        stdout: String::from_utf8_lossy(&buffer).into_owned(),
        stderr: String::new(),
        timed_out,
        missing: false,
    }
}

/// Cached `which`-style lookup. Availability does not change during a run, and
/// the doctor and several probes all ask the same questions.
static TOOL_CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, bool>> {
    TOOL_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolves a bare command name against `PATH` without spawning a helper process.
fn find_on_path(name: &str) -> bool {
    if name.contains(std::path::MAIN_SEPARATOR) {
        return std::path::Path::new(name).is_file();
    }

    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };

    // On Windows a bare name needs an executable extension appended.
    #[cfg(windows)]
    let extensions: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| e.to_ascii_lowercase())
        .collect();
    #[cfg(not(windows))]
    let extensions: Vec<String> = vec![String::new()];

    for dir in std::env::split_paths(&paths) {
        for ext in &extensions {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

pub async fn has_tool(name: &str) -> bool {
    let cache = cache();
    {
        let guard = cache.lock().await;
        if let Some(found) = guard.get(name) {
            return *found;
        }
    }

    let found = find_on_path(name);
    cache.lock().await.insert(name.to_string(), found);
    found
}

/// Clears the availability cache. The doctor calls this on an explicit re-check
/// so a tool installed while the app is running is picked up without a restart.
pub async fn clear_tool_cache() {
    cache().lock().await.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_binary_is_reported_not_panicked() {
        let result = run(
            "definitely-not-a-real-binary-xyz",
            &[],
            Duration::from_secs(2),
        )
        .await;
        assert!(result.missing);
        assert!(!result.ok);
    }

    #[tokio::test]
    async fn has_tool_finds_a_ubiquitous_binary() {
        // `ping` ships with every supported OS.
        assert!(has_tool("ping").await);
        assert!(!has_tool("definitely-not-a-real-binary-xyz").await);
    }
}
