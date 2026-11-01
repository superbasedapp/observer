package hook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// V3-4 (carry-forward from V3 backlog, v1.7.17+): every observer hook
// invocation appends one structured JSONL line to a per-user log file
// so operators can answer "why didn't the hook fire?" / "is the hook
// being invoked at all?" without raising the observer log level
// (which floods stderr and bloats CI runs).
//
// Failure to write is silent — the hook MUST never break the host
// tool (spec P1). Operators see the file growing under
// `<observer home>/hook-events.jsonl` (default `~/.observer/`) when
// things are working.

// hookEventLogPath returns the event-log file location in the Observer
// home of the invocation's config (hookStateDir: the directory of
// db_path, ~/.observer by default).
func hookEventLogPath() string {
	return stateFilePath("hook-events.jsonl")
}

// forensicLogAllowed reports whether a forensic log (hook-events.jsonl,
// cursor-stop-debug.jsonl) may be appended at path. Not when its directory
// exists as a non-directory: the append could not succeed anyway, and
// cmd/observer's test backstop makes the default ~/.observer such a file.
// And, inside a test binary, not outside the test temp directory
// (surface-gap FU-102): a refusal is recorded and fails the package run
// through testwriteguard.Run, so a test that forgets to pin its home can
// never append to the developer's real ~/.observer logs again. Outside a
// test binary the second rule never refuses.
func forensicLogAllowed(path string) bool {
	if fi, err := os.Stat(filepath.Dir(path)); err == nil && !fi.IsDir() {
		return false
	}
	return testWriteRefused(path) == nil
}

// hookEvent is one row of the JSONL stream. Fields are flat to keep
// jq/grep ergonomics simple — operators don't have to descend a tree.
type hookEvent struct {
	Ts        string `json:"ts"`    // RFC3339Nano UTC
	Event     string `json:"event"` // hook channel name
	Bytes     int    `json:"bytes"` // payload byte count
	SessionID string `json:"session_id,omitempty"`
	Tool      string `json:"tool,omitempty"`   // PreToolUse / PostToolUse tool name
	Action    string `json:"action,omitempty"` // observer's response (approve / guard:deny / guard:ask / approve+flag)

	// Guard verdict fields (G4, guard spec §6.1): present only on
	// guard-evaluated events with a record-worthy verdict. The JSONL
	// doubles as the crash-window forensics record — if the hook
	// process dies between the stdout reply and the async DB
	// persist, the verdict survives here.
	RuleID       string `json:"rule_id,omitempty"`
	Decision     string `json:"verdict,omitempty"`       // allow|flag|ask|deny
	Severity     string `json:"severity,omitempty"`      // info|warn|high|critical
	DegradedFrom string `json:"degraded_from,omitempty"` // §6.2 capability downgrade
}

// eventLogWriteMu serializes writes from concurrent hook invocations
// in the same process. Multi-process serialization is provided by
// O_APPEND (POSIX-atomic for small writes up to PIPE_BUF on most
// filesystems; the JSONL lines here are typically <500 bytes).
var eventLogWriteMu sync.Mutex

// appendHookEventLog writes one JSONL row best-effort. All errors are
// swallowed — the hook handler must not propagate non-zero exits.
//
// Race-safety: O_APPEND atomic on POSIX for sub-PIPE_BUF writes; the
// per-process mutex prevents bytes interleaving across goroutines.
// On Windows the OS-level append is also atomic for small writes.
func appendHookEventLog(ev hookEvent) {
	path := hookEventLogPath()
	if path == "" {
		return
	}
	if !forensicLogAllowed(path) {
		return
	}
	if ev.Ts == "" {
		ev.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	body = append(body, '\n')

	eventLogWriteMu.Lock()
	defer eventLogWriteMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrPermission) || err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(body)
}

// payloadFieldString cheaply extracts a top-level string from the
// hook payload by unmarshaling into a small map. Used by hook
// handlers to surface session_id / tool_name into the event log
// without parsing the full schema.
//
// Caller passes the raw payload bytes ONCE; this helper unmarshals
// into a fresh map[string]any each call. For multi-field extraction
// callers should parse once into a map[string]any locally.
func payloadFieldString(body []byte, key string) string {
	if len(body) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
