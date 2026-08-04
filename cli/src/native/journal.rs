//! Structured event journal: a per-session, append-only JSONL file written by
//! the daemon.
//!
//! Opt-in via `AGENT_BROWSER_JOURNAL_DIR` (same env-var opt-in pattern as
//! `AGENT_BROWSER_NO_STREAM`): when the variable is unset or empty, no journal
//! exists and behavior is unchanged. When set, the daemon appends one JSON
//! object per line to `<dir>/<session>.jsonl`:
//!
//! - command / result records for every command the daemon executes
//!   (written unconditionally — the journal does not depend on the stream
//!   server, which is absent under `AGENT_BROWSER_NO_STREAM=1`),
//! - confirmation lifecycle records (pending / confirmed / denied),
//! - a tee of interesting CDP events (console, page errors, main-frame
//!   navigations, dialogs, document/xhr/fetch responses).
//!
//! Every record carries a monotonic `seq` and a `ts` (epoch ms). `seq`
//! survives daemon restarts: on open, the last line of an existing journal is
//! parsed (tail read, bounded) and numbering continues from there, so
//! consumers can poll with `since=seq` across restarts.
//!
//! The journal never panics and never fails a command: on any IO error it
//! logs once to stderr and disables itself for the rest of the process.

use serde_json::{json, Value};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::cdp::types::CdpEvent;
use super::network;

/// Rotate the journal once it grows past this many bytes. The previous file
/// is renamed to `<session>.jsonl.1` (replacing any older `.1`), so at most
/// ~64 MiB of journal is retained per session.
const ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// How many bytes of the file tail to scan for the last record's `seq` when
/// resuming an existing journal.
const SEQ_TAIL_SCAN_BYTES: u64 = 8 * 1024;

/// Elision convention: any string value longer than this many characters
/// (inside command `params` and result `data`) is truncated to its first
/// `ELIDE_MAX_CHARS` characters and given a `"...elided:<original-length>"`
/// suffix, where `<original-length>` is the original length in characters.
const ELIDE_MAX_CHARS: usize = 4096;

/// Console/page-error text in CDP tee records is capped at this many
/// characters (same suffix convention as [`ELIDE_MAX_CHARS`]).
const EVENT_TEXT_MAX_CHARS: usize = 2048;

struct Inner {
    /// `None` once the journal has been disabled by an IO error.
    file: Option<File>,
    /// Sequence number the next record will carry.
    next_seq: u64,
    /// Current size of the active journal file in bytes.
    bytes: u64,
}

pub struct Journal {
    path: PathBuf,
    rotated_path: PathBuf,
    inner: Mutex<Inner>,
}

impl Journal {
    /// Create the journal from `AGENT_BROWSER_JOURNAL_DIR`. Returns `None`
    /// when the variable is unset/empty (journal disabled) or when the
    /// directory/file cannot be prepared (logged to stderr, never fatal).
    pub fn from_env(session_name: &str) -> Option<Arc<Journal>> {
        let dir = env::var("AGENT_BROWSER_JOURNAL_DIR").ok()?;
        let dir = dir.trim();
        if dir.is_empty() {
            return None;
        }
        let dir = PathBuf::from(dir);
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!(
                "[agent-browser] journal disabled: cannot create {}: {}",
                dir.display(),
                e
            );
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }

        let path = dir.join(format!("{}.jsonl", session_name));
        let rotated_path = dir.join(format!("{}.jsonl.1", session_name));
        let next_seq = next_seq_from_existing(&path);
        let file = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "[agent-browser] journal disabled: cannot open {}: {}",
                    path.display(),
                    e
                );
                return None;
            }
        };
        let bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
        Some(Arc::new(Journal {
            path,
            rotated_path,
            inner: Mutex::new(Inner {
                file: Some(file),
                next_seq,
                bytes,
            }),
        }))
    }

    /// Append one record. Injects `seq` (monotonic) and `ts` (epoch ms) if
    /// absent. Never panics; on IO error the journal is disabled for the
    /// rest of the process (logged once to stderr).
    pub fn write(&self, mut record: Value) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.file.is_none() {
            return;
        }

        let seq = inner.next_seq;
        if let Some(obj) = record.as_object_mut() {
            obj.entry("seq").or_insert(json!(seq));
            obj.entry("ts").or_insert(json!(epoch_ms()));
        }
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[agent-browser] journal disabled: serialize failed: {}", e);
                inner.file = None;
                return;
            }
        };
        line.push('\n');

        let write_result = inner
            .file
            .as_mut()
            .expect("checked above")
            .write_all(line.as_bytes());
        if let Err(e) = write_result {
            eprintln!(
                "[agent-browser] journal disabled: write to {} failed: {}",
                self.path.display(),
                e
            );
            inner.file = None;
            return;
        }
        inner.next_seq = seq + 1;
        inner.bytes += line.len() as u64;

        if inner.bytes > ROTATE_BYTES {
            // fs::rename replaces any previous `.1`; seq continues.
            if let Err(e) = fs::rename(&self.path, &self.rotated_path) {
                eprintln!(
                    "[agent-browser] journal disabled: rotate {} failed: {}",
                    self.path.display(),
                    e
                );
                inner.file = None;
                return;
            }
            match OpenOptions::new().create(true).append(true).open(&self.path) {
                Ok(f) => {
                    inner.file = Some(f);
                    inner.bytes = 0;
                }
                Err(e) => {
                    eprintln!(
                        "[agent-browser] journal disabled: reopen {} failed: {}",
                        self.path.display(),
                        e
                    );
                    inner.file = None;
                }
            }
        }
    }
}

/// Read the `seq` of the last record in an existing journal file so numbering
/// continues across daemon restarts. Scans only the tail
/// ([`SEQ_TAIL_SCAN_BYTES`]); returns 0 (start fresh) when the file is
/// missing, empty, or its last line is unparseable.
fn next_seq_from_existing(path: &PathBuf) -> u64 {
    let Ok(mut file) = File::open(path) else {
        return 0;
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return 0;
    };
    if len == 0 {
        return 0;
    }
    let start = len.saturating_sub(SEQ_TAIL_SCAN_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return 0;
    }
    let mut tail = String::new();
    if file.read_to_string(&mut tail).is_err() {
        // Tail may start mid-UTF-8 sequence; retry lossily via bytes.
        let mut bytes = Vec::new();
        let _ = file.seek(SeekFrom::Start(start));
        if file.read_to_end(&mut bytes).is_err() {
            return 0;
        }
        tail = String::from_utf8_lossy(&bytes).into_owned();
    }
    tail.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .and_then(|v| v.get("seq").and_then(|s| s.as_u64()))
        .map(|seq| seq + 1)
        .unwrap_or(0)
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Recursively elide long string values (see [`ELIDE_MAX_CHARS`] for the
/// convention). Applied to command `params` and result `data` records so a
/// large eval result or page snapshot cannot bloat the journal.
pub fn elide_long_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(elided) = elide_str(s, ELIDE_MAX_CHARS) {
                *s = elided;
            }
        }
        Value::Array(items) => {
            for item in items {
                elide_long_strings(item);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                elide_long_strings(v);
            }
        }
        _ => {}
    }
}

/// Returns the elided form of `s` if it exceeds `max_chars`, else `None`.
fn elide_str(s: &str, max_chars: usize) -> Option<String> {
    let total = s.chars().count();
    if total <= max_chars {
        return None;
    }
    let mut truncated: String = s.chars().take(max_chars).collect();
    truncated.push_str(&format!("...elided:{}", total));
    Some(truncated)
}

fn capped(s: &str, max_chars: usize) -> String {
    elide_str(s, max_chars).unwrap_or_else(|| s.to_string())
}

/// Tee one CDP event into the journal. Called from the background journal
/// handler task (a `CdpClient::subscribe()` receiver, modeled on the fetch
/// and dialog handler tasks) — this is a separate subscription and does not
/// reroute the drain in `DaemonState::apply_drained_events`.
pub fn record_cdp_event(journal: &Journal, event: &CdpEvent) {
    match event.method.as_str() {
        "Runtime.consoleAPICalled" => {
            let level = event
                .params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("log");
            let raw_args: Vec<Value> = event
                .params
                .get("args")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let text = network::format_console_args(&raw_args);
            journal.write(json!({
                "type": "console",
                "level": level,
                "text": capped(&text, EVENT_TEXT_MAX_CHARS),
            }));
        }
        "Runtime.exceptionThrown" => {
            let details = event.params.get("exceptionDetails");
            let text = details
                .and_then(|d| d.get("exception"))
                .and_then(|e| e.get("description"))
                .and_then(|v| v.as_str())
                .or_else(|| {
                    details
                        .and_then(|d| d.get("text"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            let mut record = json!({
                "type": "page_error",
                "text": capped(text, EVENT_TEXT_MAX_CHARS),
            });
            let obj = record.as_object_mut().expect("literal object");
            if let Some(url) = details.and_then(|d| d.get("url")).and_then(|v| v.as_str()) {
                obj.insert("url".to_string(), json!(url));
            }
            if let Some(line) = details
                .and_then(|d| d.get("lineNumber"))
                .and_then(|v| v.as_i64())
            {
                obj.insert("line".to_string(), json!(line));
            }
            if let Some(column) = details
                .and_then(|d| d.get("columnNumber"))
                .and_then(|v| v.as_i64())
            {
                obj.insert("column".to_string(), json!(column));
            }
            journal.write(record);
        }
        "Page.frameNavigated" => {
            let Some(frame) = event.params.get("frame") else {
                return;
            };
            // Main frame only: subframes carry a parentId.
            if frame.get("parentId").is_some() {
                return;
            }
            let url = frame.get("url").and_then(|v| v.as_str()).unwrap_or("");
            journal.write(json!({ "type": "nav", "url": url }));
        }
        "Page.javascriptDialogOpening" => {
            let kind = event
                .params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message = event
                .params
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            journal.write(json!({
                "type": "dialog",
                "kind": kind,
                "message": capped(message, EVENT_TEXT_MAX_CHARS),
                "status": "opened",
            }));
        }
        "Page.javascriptDialogClosed" => {
            let accepted = event
                .params
                .get("result")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            journal.write(json!({
                "type": "dialog",
                "status": "closed",
                "accepted": accepted,
            }));
        }
        "Network.responseReceived" => {
            let resource_type = event
                .params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Other");
            // Only page-shaped traffic; images/fonts/scripts/styles are noise.
            if !matches!(resource_type, "Document" | "XHR" | "Fetch") {
                return;
            }
            let Some(response) = event.params.get("response") else {
                return;
            };
            let url = response.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let status = response.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
            // `method` is intentionally omitted: it only exists on the
            // requestWillBeSent side and pairing request ids here is not
            // worth the state.
            journal.write(json!({
                "type": "network",
                "url": url,
                "status": status,
                "resource_type": resource_type,
            }));
        }
        _ => {}
    }
}
