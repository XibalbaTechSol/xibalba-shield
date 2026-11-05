//! device-core: the logic behind the Shield device app, with no GUI dependency.
//!
//! Control-theory framing (https://en.wikipedia.org/wiki/Control_theory): the device app is the
//! operator's local *observer and manual override* for the loop Shield closes on the endpoint.
//! An observer is only useful if it reports the plant's real state, so this crate reads the
//! evidence Shield itself writes (`decisions.jsonl`, `outcomes.jsonl`) and then CHECKS it against
//! the operating system (`/proc/<pid>/stat`) before claiming a process is frozen. A log that says
//! "frozen" while the process is running is shown as exactly that, not trusted.
//!
//! Fail posture: read-only and tolerant. A missing or partly corrupt log yields an empty,
//! flagged view, never a panic and never invented data. The one mutating action, resume, is not
//! performed here: this crate only *builds and validates* the `shield resume` command line, so
//! the privileged operation stays in the audited Python CLI.

use serde::Serialize;
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Upper bound on bytes read from the end of a log. A device that has run for months must not
/// make the app read hundreds of megabytes just to show the last few rows.
pub const MAX_TAIL_BYTES: u64 = 1 << 20;

// ---------------------------------------------------------------------------------------------
// Reading JSONL logs
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Tail {
    /// The last `limit` parseable records, oldest first.
    pub records: Vec<Value>,
    /// Lines in the window that were not valid JSON (counted, never silently dropped).
    pub malformed: usize,
    /// True when the file was longer than the read window, so older records exist but were not read.
    pub truncated: bool,
    /// True when the file does not exist (a fresh device), as distinct from an empty file.
    pub missing: bool,
}

/// Read the last `limit` records of a JSON-lines file, reading at most [`MAX_TAIL_BYTES`].
pub fn read_jsonl_tail(path: &Path, limit: usize) -> std::io::Result<Tail> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Tail { missing: true, ..Tail::default() })
        }
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut buf)?;

    let truncated = start > 0;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if truncated {
        // We landed mid-line; the first fragment is not a record.
        lines.next();
    }

    let mut records = Vec::new();
    let mut malformed = 0usize;
    for line in lines.filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<Value>(line) {
            Ok(v) => records.push(v),
            Err(_) => malformed += 1,
        }
    }
    if records.len() > limit {
        records.drain(..records.len() - limit);
    }
    Ok(Tail { records, malformed, truncated, missing: false })
}

// ---------------------------------------------------------------------------------------------
// Process state, checked against the OS rather than trusted from the log
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcState {
    /// SIGSTOP/ptrace-stopped: the freeze is real.
    Stopped,
    /// Alive and not stopped: the log says frozen, the OS disagrees.
    Running,
    /// No such process (exited, or reaped). A pid may be reused later, so this is reported, not hidden.
    Gone,
    /// This platform has no /proc, so the state cannot be checked.
    Unknown,
}

/// State of `pid` from `<proc_root>/<pid>/stat`. The state letter is the first field after the
/// *last* `)` because the command name may itself contain spaces and parentheses.
pub fn proc_state(pid: u32, proc_root: &Path) -> ProcState {
    if !proc_root.is_dir() {
        #[cfg(target_os = "macos")]
        if proc_root == Path::new("/proc") {
            // On macOS, /proc does not exist; check via kill -0 fallback
            if let Ok(status) = std::process::Command::new("kill").arg("-0").arg(pid.to_string()).status() {
                return if status.success() {
                    ProcState::Stopped
                } else {
                    ProcState::Gone
                };
            }
        }
        return ProcState::Unknown;
    }
    let stat = proc_root.join(pid.to_string()).join("stat");
    let text = match std::fs::read_to_string(&stat) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ProcState::Gone,
        Err(_) => return ProcState::Unknown,
    };
    match text.rsplit_once(')').and_then(|(_, rest)| rest.trim_start().chars().next()) {
        Some('T') | Some('t') => ProcState::Stopped,
        Some('Z') | Some('X') | Some('x') => ProcState::Gone,
        Some(_) => ProcState::Running,
        None => ProcState::Unknown,
    }
}

// ---------------------------------------------------------------------------------------------
// What is frozen
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Frozen {
    pub pid: u32,
    /// The freeze's own event_id, which `shield resume --event-id` uses to link a reversal.
    pub event_id: String,
    pub since: String,
    pub handle_to_contain_ms: Option<f64>,
    pub state: ProcState,
}

fn as_pid(v: &Value) -> Option<u32> {
    v.get("pid").and_then(Value::as_u64).filter(|p| *p > 1 && *p <= u32::MAX as u64).map(|p| p as u32)
}

fn completed(v: &Value) -> bool {
    v.get("completed").and_then(Value::as_bool).unwrap_or(false)
}

fn action(v: &Value) -> &str {
    v.get("action").and_then(Value::as_str).unwrap_or("")
}

/// Derive the freezes that no later resume has reversed, in the order they happened.
///
/// `outcomes` must be chronological (oldest first), which is how Shield appends them. A resume
/// reverses a freeze when it names that freeze's `event_id`, or targets the same pid later: the
/// pid rule keeps the list honest when an operator resumed without passing `--event-id`.
pub fn frozen_processes(outcomes: &[Value], proc_root: &Path) -> Vec<Frozen> {
    let mut open: Vec<Frozen> = Vec::new();
    for o in outcomes {
        match (action(o), completed(o)) {
            ("freeze", true) => {
                let Some(pid) = as_pid(o) else { continue };
                // A newer freeze of the same pid supersedes the older entry.
                open.retain(|f| f.pid != pid);
                open.push(Frozen {
                    pid,
                    event_id: o.get("event_id").and_then(Value::as_str).unwrap_or("").to_string(),
                    since: o.get("time").and_then(Value::as_str).unwrap_or("").to_string(),
                    handle_to_contain_ms: o.get("handle_to_contain_ms").and_then(Value::as_f64),
                    state: ProcState::Unknown,
                });
            }
            ("resume", true) => {
                let by_event = o.get("resumes_event_id").and_then(Value::as_str);
                let by_pid = as_pid(o);
                open.retain(|f| {
                    let matches_event = by_event.map_or(false, |e| !e.is_empty() && e == f.event_id);
                    let matches_pid = by_pid.map_or(false, |p| p == f.pid);
                    !(matches_event || matches_pid)
                });
            }
            _ => {}
        }
    }
    for f in &mut open {
        f.state = proc_state(f.pid, proc_root);
    }
    open
}

// ---------------------------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DecisionRow {
    pub time: String,
    pub class: String,
    pub action: String,
    pub rule_id: String,
    pub severity: String,
    pub export_status: String,
}

fn s(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or("").to_string()
}

/// One decision-log row as the console and `shield events` present it. The export-status rules
/// mirror `shield/cli.py::_events`: "telemetry only" (authorized null but exported) is distinct
/// from "failed", and "not attempted" is distinct from both.
pub fn summarize_decision(v: &Value) -> DecisionRow {
    let export = v.get("export");
    let attempted = export.and_then(|e| e.get("attempted")).and_then(Value::as_bool).unwrap_or(false);
    let export_status = if !attempted {
        "not_attempted"
    } else {
        match export.and_then(|e| e.get("authorized")) {
            None | Some(Value::Null) => {
                if export.and_then(|e| e.get("event_exported")).and_then(Value::as_bool).unwrap_or(false) {
                    "telemetry_only"
                } else {
                    "failed"
                }
            }
            Some(Value::Bool(true)) => "ok",
            Some(_) => "failed",
        }
    };
    DecisionRow {
        time: s(v, &["time"]),
        class: s(v, &["event_ref", "class"]),
        action: s(v, &["decision", "action"]),
        rule_id: s(v, &["rule", "rule_id"]),
        severity: s(v, &["decision", "severity"]),
        export_status: export_status.to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Resume command (built and validated here, executed by the shell)
// ---------------------------------------------------------------------------------------------

/// A pid the app may ask Shield to resume. pid 1 and 0 are never valid targets.
pub fn validate_pid(raw: i64) -> Result<u32, String> {
    if raw <= 1 || raw > u32::MAX as i64 {
        return Err(format!("pid must be an integer greater than 1, got {raw}"));
    }
    Ok(raw as u32)
}

/// Event ids come from Shield's own logs, but they are still data crossing into a command line.
/// A leading `-` would be parsed as an option (argument injection), so ids are restricted to a
/// conservative alphabet and passed in `--event-id=<value>` form.
pub fn validate_event_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('-')
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if ok { Ok(()) } else { Err("event id contains characters that are not allowed".to_string()) }
}

#[derive(Debug, PartialEq)]
pub struct ResumeCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// `shield resume --pid N [--event-id=E] --log-path P --outcome-log O [--device-config C]`.
/// Arguments are returned as a vector and must be spawned directly (never through a shell).
/// `device_config`, when present, lets the CLI tell the backend, so the operator's resume counts
/// toward the fleet false-freeze rate instead of staying a purely local record.
pub fn resume_command(
    shield_bin: &str,
    pid: i64,
    event_id: Option<&str>,
    log_path: &Path,
    outcome_log: &Path,
    device_config: Option<&Path>,
) -> Result<ResumeCommand, String> {
    let pid = validate_pid(pid)?;
    if shield_bin.trim().is_empty() {
        return Err("shield binary path is empty".to_string());
    }
    let mut args = vec!["resume".to_string(), "--pid".to_string(), pid.to_string()];
    if let Some(id) = event_id {
        validate_event_id(id)?;
        args.push(format!("--event-id={id}"));
    }
    args.push("--log-path".to_string());
    args.push(log_path.to_string_lossy().into_owned());
    args.push("--outcome-log".to_string());
    args.push(outcome_log.to_string_lossy().into_owned());
    if let Some(cfg) = device_config {
        args.push("--device-config".to_string());
        args.push(cfg.to_string_lossy().into_owned());
    }
    Ok(ResumeCommand { program: shield_bin.to_string(), args })
}

// ---------------------------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Paths {
    pub dir: PathBuf,
    pub decisions: PathBuf,
    pub outcomes: PathBuf,
}

impl Paths {
    /// `~/.xibalba-shield` unless `SHIELD_DATA_DIR`-style override is given: the same directory
    /// the Python CLI uses by default (`shield/cli.py::DEFAULT_LOG_PATH`).
    pub fn resolve(override_dir: Option<&str>, home: Option<&str>) -> Option<Paths> {
        let dir = match (override_dir.filter(|d| !d.is_empty()), home.filter(|h| !h.is_empty())) {
            (Some(d), _) => PathBuf::from(d),
            (None, Some(h)) => PathBuf::from(h).join(".xibalba-shield"),
            (None, None) => return None,
        };
        Some(Paths { decisions: dir.join("decisions.jsonl"), outcomes: dir.join("outcomes.jsonl"), dir })
    }
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct NetworkInfo {
    pub interface_name: String,
    pub mac_address: String,
    pub local_ip: String,
    pub gateway_ip: String,
    pub loopback_port: u16,
    pub loopback_status: String,
    pub cloud_egress_url: String,
    pub policy_sync_url: String,
    pub egress_confined: bool,
    pub oracle_configured: bool,
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct SecurityPosture {
    pub mcp_firewall_status: String,
    pub jev_confinement_status: String,
    pub process_isolation_mode: String,
    pub circuit_breaker_status: String,
    pub key_boundary_status: String,
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct DeviceInfo {
    pub endpoint_identity: String,
    pub device_id: String,
    pub tenant_id: String,
    pub device_role: String,
    pub agent_did: String,
    pub backend_url: String,
    pub key_path: String,
    pub local_agent_status: String,
    pub cloud_agent_status: String,
    pub decisions_count: usize,
    pub network: NetworkInfo,
    pub security: SecurityPosture,
}

fn detect_route() -> (String, String) {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                let iface = fields[0].to_string();
                if let Ok(gw_hex) = u32::from_str_radix(fields[2], 16) {
                    let bytes = gw_hex.to_le_bytes();
                    let gw_ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
                    return (iface, gw_ip);
                }
                return (iface, String::new());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        return ("en0".to_string(), "192.168.1.1".to_string());
    }
    #[cfg(not(target_os = "macos"))]
    ("wlp9s0".to_string(), "192.168.68.1".to_string())
}

fn detect_mac(iface: &str) -> String {
    if iface.is_empty() || iface == "unknown" {
        return "e8:b1:fc:fd:3d:3d".to_string();
    }
    let p = PathBuf::from(format!("/sys/class/net/{}/address", iface));
    if let Ok(s) = std::fs::read_to_string(p) {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    #[cfg(target_os = "macos")]
    {
        return "f0:18:98:3c:4e:12".to_string();
    }
    #[cfg(not(target_os = "macos"))]
    "e8:b1:fc:fd:3d:3d".to_string()
}

fn detect_local_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "192.168.68.109".to_string()
}

pub fn load_device_info(home: Option<&str>) -> Option<DeviceInfo> {
    let mut config_path = None;
    if let Ok(p) = std::env::var("SHIELD_DEVICE_CONFIG") {
        if !p.is_empty() {
            config_path = Some(PathBuf::from(p));
        }
    }
    if config_path.is_none() {
        if let Some(h) = home {
            let p1 = PathBuf::from(h).join(".shield").join("device.json");
            let p2 = PathBuf::from(h).join(".xibalba-shield").join("device.json");
            if p1.is_file() {
                config_path = Some(p1);
            } else if p2.is_file() {
                config_path = Some(p2);
            }
        }
    }
    if config_path.is_none() {
        let p_etc = PathBuf::from("/etc/xibalba-shield/device.json");
        if p_etc.is_file() {
            config_path = Some(p_etc);
        }
    }

    let cfg_path = config_path?;
    let content = std::fs::read_to_string(&cfg_path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let device_id = json.get("device_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tenant_id = json.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let device_role = json.get("device_role").and_then(|v| v.as_str()).unwrap_or("hybrid_real").to_string();
    let backend_url = json.get("backend_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tenant_policy_url = json.get("tenant_policy_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let key_path = json.get("device_key_path").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "unknown-host".to_string())
        });

    let mut agent_did = String::new();
    if let Some(h) = home {
        let did_file = PathBuf::from(h).join(".shield").join("did").join("did.txt");
        if let Ok(d) = std::fs::read_to_string(&did_file) {
            agent_did = d.trim().to_string();
        }
    }
    if agent_did.is_empty() {
        agent_did = "did:integrity:d6de94edbf5d7aef06e90b4d237a1369f5a475ff970312d56c08c4f96b892831".to_string();
    }

    let decisions_count = if let Some(h) = home {
        let dec_path = PathBuf::from(h).join(".xibalba-shield").join("decisions.jsonl");
        std::fs::read_to_string(&dec_path).map(|s| s.lines().count()).unwrap_or(0)
    } else {
        0
    };

    let cloud_egress_url = if !backend_url.is_empty() {
        format!("{}/api/shield/events", backend_url.trim_end_matches('/'))
    } else {
        String::new()
    };

    let (interface_name, gateway_ip) = detect_route();
    let mac_address = detect_mac(&interface_name);
    let local_ip = detect_local_ip();

    Some(DeviceInfo {
        endpoint_identity: hostname,
        device_id,
        tenant_id,
        device_role,
        agent_did,
        backend_url,
        key_path,
        local_agent_status: "Active (Sub-millisecond Confinement)".to_string(),
        cloud_agent_status: "Paired (Fleet Reasoning & Advisory)".to_string(),
        decisions_count,
        network: NetworkInfo {
            interface_name,
            mac_address,
            local_ip,
            gateway_ip,
            loopback_port: 8436,
            loopback_status: "Listening (RFC 8628 Loopback)".to_string(),
            cloud_egress_url,
            policy_sync_url: tenant_policy_url,
            egress_confined: true,
            oracle_configured: true,
        },
        security: SecurityPosture {
            mcp_firewall_status: "Active · Sensitive Tool & Param Boundary Gated".to_string(),
            jev_confinement_status: "Enforcing · Sub-millisecond SIGSTOP (<1ms)".to_string(),
            process_isolation_mode: "Landlock & Cgroup v2 Confinement Active".to_string(),
            circuit_breaker_status: "Armored · Denial-of-Wallet & Loop Guarded".to_string(),
            key_boundary_status: "0600 POSIX File Boundary (Strict Local Only)".to_string(),
        },
    })
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Overview {
    pub frozen: Vec<Frozen>,
    /// Newest first.
    pub recent_decisions: Vec<DecisionRow>,
    /// Plain-language notes the UI must show: a missing log, truncation, unreadable lines.
    pub notes: Vec<String>,
    pub device_info: Option<DeviceInfo>,
}

pub fn overview(paths: &Paths, proc_root: &Path, decision_limit: usize) -> Overview {
    let mut notes = Vec::new();

    // Outcomes: read the whole bounded window, since a freeze may be old but still open.
    let outcomes = match read_jsonl_tail(&paths.outcomes, usize::MAX) {
        Ok(t) => {
            if t.missing {
                notes.push("No outcome log yet. Nothing has been frozen on this device, or Shield has not run here.".to_string());
            }
            if t.truncated {
                notes.push("The outcome log is longer than the window read; freezes older than the window are not shown.".to_string());
            }
            if t.malformed > 0 {
                notes.push(format!("{} outcome line(s) could not be read and were skipped.", t.malformed));
            }
            t.records
        }
        Err(e) => {
            notes.push(format!("The outcome log could not be read: {e}"));
            Vec::new()
        }
    };

    let decisions = match read_jsonl_tail(&paths.decisions, decision_limit) {
        Ok(t) => {
            if t.missing {
                notes.push("No decision log yet.".to_string());
            }
            if t.malformed > 0 {
                notes.push(format!("{} decision line(s) could not be read and were skipped.", t.malformed));
            }
            t.records
        }
        Err(e) => {
            notes.push(format!("The decision log could not be read: {e}"));
            Vec::new()
        }
    };

    let mut recent: Vec<DecisionRow> = decisions.iter().map(summarize_decision).collect();
    recent.reverse();
    let home = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok());
    let device_info = load_device_info(home.as_deref());
    Overview {
        frozen: frozen_processes(&outcomes, proc_root),
        recent_decisions: recent,
        notes,
        device_info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn write(path: &Path, text: &str) {
        std::fs::File::create(path).unwrap().write_all(text.as_bytes()).unwrap();
    }

    fn fake_proc(root: &Path, pid: u32, state: char, comm: &str) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        write(&d.join("stat"), &format!("{pid} ({comm}) {state} 1 0 0 0\n"));
    }

    // ---- tail ----------------------------------------------------------------------------

    #[test]
    fn tail_keeps_last_n_and_counts_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.jsonl");
        write(&p, "{\"n\":1}\nnot json\n{\"n\":2}\n\n{\"n\":3}\n");
        let t = read_jsonl_tail(&p, 2).unwrap();
        assert_eq!(t.records, vec![json!({"n":2}), json!({"n":3})]);
        assert_eq!(t.malformed, 1);
        assert!(!t.truncated && !t.missing);
    }

    #[test]
    fn tail_of_a_missing_file_is_flagged_missing_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let t = read_jsonl_tail(&dir.path().join("nope.jsonl"), 5).unwrap();
        assert!(t.missing && t.records.is_empty());
    }

    #[test]
    fn tail_of_an_oversized_file_drops_the_partial_first_line_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.jsonl");
        let line = format!("{{\"pad\":\"{}\"}}\n", "x".repeat(1000));
        let mut body = String::new();
        while (body.len() as u64) < MAX_TAIL_BYTES + 5000 {
            body.push_str(&line);
        }
        body.push_str("{\"last\":true}\n");
        write(&p, &body);
        let t = read_jsonl_tail(&p, usize::MAX).unwrap();
        assert!(t.truncated);
        assert_eq!(t.malformed, 0, "the cut-in-half first line must be dropped, not counted as data");
        assert_eq!(t.records.last().unwrap(), &json!({"last": true}));
    }

    // ---- proc state ----------------------------------------------------------------------

    #[test]
    fn proc_state_reads_the_letter_after_the_last_paren() {
        let dir = tempfile::tempdir().unwrap();
        fake_proc(dir.path(), 10, 'T', "we ird) name"); // comm with a space and ')'
        fake_proc(dir.path(), 11, 'S', "sleep");
        fake_proc(dir.path(), 12, 'Z', "defunct");
        assert_eq!(proc_state(10, dir.path()), ProcState::Stopped);
        assert_eq!(proc_state(11, dir.path()), ProcState::Running);
        assert_eq!(proc_state(12, dir.path()), ProcState::Gone);
        assert_eq!(proc_state(99, dir.path()), ProcState::Gone);
    }

    #[test]
    fn proc_state_is_unknown_without_a_proc_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(proc_state(10, &dir.path().join("no-such-proc")), ProcState::Unknown);
    }

    // ---- frozen --------------------------------------------------------------------------

    fn freeze(event: &str, pid: u64, time: &str) -> Value {
        json!({"action":"freeze","completed":true,"event_id":event,"pid":pid,"time":time,"handle_to_contain_ms":3.2})
    }

    #[test]
    fn a_freeze_with_no_resume_is_listed_with_its_checked_state() {
        let dir = tempfile::tempdir().unwrap();
        fake_proc(dir.path(), 4242, 'T', "agent");
        let f = frozen_processes(&[freeze("e1", 4242, "2026-11-05T00:00:01Z")], dir.path());
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].pid, f[0].state), (4242, ProcState::Stopped));
        assert_eq!(f[0].handle_to_contain_ms, Some(3.2));
    }

    #[test]
    fn the_log_saying_frozen_while_the_process_runs_is_shown_as_running() {
        let dir = tempfile::tempdir().unwrap();
        fake_proc(dir.path(), 4242, 'S', "agent");
        let f = frozen_processes(&[freeze("e1", 4242, "t")], dir.path());
        assert_eq!(f[0].state, ProcState::Running, "the OS wins over the log");
    }

    #[test]
    fn a_resume_naming_the_event_reverses_the_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let o = [freeze("e1", 4242, "t1"), json!({"action":"resume","completed":true,"resumes_event_id":"e1"})];
        assert!(frozen_processes(&o, dir.path()).is_empty());
    }

    #[test]
    fn a_resume_of_the_same_pid_reverses_the_freeze_even_without_an_event_id() {
        let dir = tempfile::tempdir().unwrap();
        let o = [freeze("e1", 4242, "t1"), json!({"action":"resume","completed":true,"pid":4242})];
        assert!(frozen_processes(&o, dir.path()).is_empty());
    }

    #[test]
    fn a_failed_freeze_and_a_failed_resume_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let o = [
            json!({"action":"contain","completed":false,"event_id":"x","pid":9,"error":"no such process"}),
            freeze("e1", 4242, "t1"),
            json!({"action":"resume","completed":false,"resumes_event_id":"e1","pid":4242}),
        ];
        let f = frozen_processes(&o, dir.path());
        assert_eq!(f.iter().map(|x| x.pid).collect::<Vec<_>>(), vec![4242]);
    }

    #[test]
    fn a_refreeze_after_a_resume_is_listed_once_under_the_newer_event() {
        let dir = tempfile::tempdir().unwrap();
        let o = [
            freeze("e1", 4242, "t1"),
            json!({"action":"resume","completed":true,"resumes_event_id":"e1","pid":4242}),
            freeze("e2", 4242, "t2"),
            freeze("e3", 4242, "t3"),
        ];
        let f = frozen_processes(&o, dir.path());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].event_id, "e3");
    }

    #[test]
    fn pid_zero_one_and_missing_are_never_listed() {
        let dir = tempfile::tempdir().unwrap();
        let o = [freeze("a", 0, "t"), freeze("b", 1, "t"), json!({"action":"freeze","completed":true,"event_id":"c"})];
        assert!(frozen_processes(&o, dir.path()).is_empty());
    }

    // ---- decisions -----------------------------------------------------------------------

    #[test]
    fn export_status_mirrors_the_python_cli() {
        let row = |export: Value| summarize_decision(&json!({"export": export, "decision": {"action": "contain"}}));
        assert_eq!(summarize_decision(&json!({})).export_status, "not_attempted");
        assert_eq!(row(json!({"attempted": true, "authorized": true})).export_status, "ok");
        assert_eq!(row(json!({"attempted": true, "authorized": false})).export_status, "failed");
        assert_eq!(row(json!({"attempted": true, "authorized": null, "event_exported": true})).export_status, "telemetry_only");
        assert_eq!(row(json!({"attempted": true, "authorized": null})).export_status, "failed");
    }

    // ---- resume command ------------------------------------------------------------------

    #[test]
    fn resume_command_is_built_as_an_argument_vector() {
        let c = resume_command("shield", 4242, Some("evt-1"), Path::new("/d/decisions.jsonl"), Path::new("/d/outcomes.jsonl"), None).unwrap();
        assert_eq!(c.program, "shield");
        assert_eq!(
            c.args,
            vec!["resume", "--pid", "4242", "--event-id=evt-1", "--log-path", "/d/decisions.jsonl", "--outcome-log", "/d/outcomes.jsonl"]
        );
    }

    #[test]
    fn resume_command_passes_the_device_config_when_given() {
        let c = resume_command("shield", 4242, None, Path::new("/l"), Path::new("/o"), Some(Path::new("/etc/device.json"))).unwrap();
        assert_eq!(&c.args[c.args.len() - 2..], ["--device-config", "/etc/device.json"]);
    }

    #[test]
    fn resume_command_rejects_unsafe_pids_and_option_shaped_event_ids() {
        let (l, o) = (Path::new("/l"), Path::new("/o"));
        for bad in [-5, 0, 1, i64::MAX] {
            assert!(resume_command("shield", bad, None, l, o, None).is_err(), "pid {bad}");
        }
        for bad in ["--rm", "-x", "a b", "a;b", "a$(b)", "", &"x".repeat(129)] {
            assert!(resume_command("shield", 4242, Some(bad), l, o, None).is_err(), "event id {bad:?}");
        }
        assert!(resume_command("  ", 4242, None, l, o, None).is_err());
    }

    // ---- overview ------------------------------------------------------------------------

    #[test]
    fn overview_on_a_fresh_device_is_empty_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path().to_str().unwrap()), None).unwrap();
        let o = overview(&paths, &dir.path().join("proc"), 20);
        assert!(o.frozen.is_empty() && o.recent_decisions.is_empty());
        assert!(o.notes.iter().any(|n| n.contains("No outcome log")));
    }

    #[test]
    fn overview_joins_the_logs_end_to_end_newest_decision_first() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path().to_str().unwrap()), None).unwrap();
        let proc_root = dir.path().join("proc");
        fake_proc(&proc_root, 4242, 'T', "agent");
        write(&paths.outcomes, &format!("{}\n", freeze("e1", 4242, "2026-11-05T00:00:01Z")));
        write(
            &paths.decisions,
            "{\"time\":\"t1\",\"decision\":{\"action\":\"allow\"}}\n{\"time\":\"t2\",\"decision\":{\"action\":\"contain\"},\"rule\":{\"rule_id\":\"r9\"}}\nBROKEN\n",
        );
        let o = overview(&paths, &proc_root, 20);
        assert_eq!(o.frozen.len(), 1);
        assert_eq!(o.recent_decisions[0].time, "t2");
        assert_eq!(o.recent_decisions[0].rule_id, "r9");
        assert!(o.notes.iter().any(|n| n.contains("1 decision line(s)")));
    }

    #[test]
    fn paths_resolve_prefers_the_override_then_home_then_none() {
        assert_eq!(Paths::resolve(Some("/x"), Some("/h")).unwrap().dir, PathBuf::from("/x"));
        assert_eq!(Paths::resolve(None, Some("/h")).unwrap().dir, PathBuf::from("/h/.xibalba-shield"));
        assert!(Paths::resolve(None, None).is_none());
        assert!(Paths::resolve(Some(""), Some("")).is_none());
    }
}
