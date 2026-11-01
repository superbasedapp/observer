//go:build !sbo_omit_adapter_cursor

package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Cursor emits per-generation usage ONLY on the `stop` hook, so
// cursor.BuildStopTokenEvent off the live stop payload is the sole path
// that populates token_usage for cursor (transcripts carry no usage and
// there is no proxy tier). When that parse rejects a payload it returns
// early to stderr, which Cursor discards — so a Cursor payload-shape
// change (a renamed usage field, a dropped generation_id) silently
// yields zero token rows with no visible failure.
//
// dumpCursorStopReject closes that blind spot: on every stop-reject
// branch in processCursorEvent it appends one CONTENT-SAFE forensic row
// to <observer home>/cursor-stop-debug.jsonl. It records only the SET of
// top-level JSON keys plus the values of short scalar fields — never
// conversation content — which is exactly enough to spot a shape change
// (e.g. keys carrying "inputTokens" instead of "input_tokens", or a
// missing "generation_id") without capturing prompts or transcripts.

// cursorStopDebugPath returns the cursor stop-reject debug log location,
// in the same Observer home as hookEventLogPath (hookStateDir).
func cursorStopDebugPath() string {
	return stateFilePath("cursor-stop-debug.jsonl")
}

// cursorStopReject is one forensic row. Fields are flat for jq/grep
// ergonomics. Scalars holds only privacy-safe values (see safeScalar).
type cursorStopReject struct {
	Ts      string         `json:"ts"`     // RFC3339Nano UTC
	Reason  string         `json:"reason"` // which reject branch fired
	Bytes   int            `json:"bytes"`  // raw payload byte count
	Keys    []string       `json:"keys"`   // sorted top-level key set
	Scalars map[string]any `json:"scalars,omitempty"`
}

// cursorStopDebugMu serializes writes from concurrent hook invocations
// in the same process; O_APPEND handles the multi-process case.
var cursorStopDebugMu sync.Mutex

// dumpCursorStopReject appends one content-safe forensic row explaining
// why a cursor stop payload failed to produce a usage row. Best-effort:
// every error is swallowed so the hook stays fail-open (spec P1).
func dumpCursorStopReject(body []byte, reason string) {
	path := cursorStopDebugPath()
	if path == "" || !forensicLogAllowed(path) {
		return
	}
	row := cursorStopReject{
		Ts:     time.Now().UTC().Format(time.RFC3339Nano),
		Reason: reason,
		Bytes:  len(body),
	}

	// Parse the top-level object only; never descend into nested
	// values, so content (prompt / transcript arrays) is never read.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err == nil {
		row.Keys = make([]string, 0, len(m))
		row.Scalars = make(map[string]any, len(m))
		for k, raw := range m {
			row.Keys = append(row.Keys, k)
			if v, ok := safeScalar(raw); ok {
				row.Scalars[k] = v
			}
		}
		sort.Strings(row.Keys)
	}

	out, err := json.Marshal(row)
	if err != nil {
		return
	}
	out = append(out, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}

	cursorStopDebugMu.Lock()
	defer cursorStopDebugMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(out)
}

// safeScalar returns a privacy-safe representation of a top-level JSON
// value: numbers and booleans verbatim (the usage counts we care about),
// strings only when short (<= 64 bytes — IDs, model names, status), and
// objects/arrays/long-strings elided to a type/length placeholder so
// prompts, transcripts, and file paths are never echoed. The second
// return is false for null / empty values.
func safeScalar(raw json.RawMessage) (any, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, false
	}
	switch s[0] {
	case '{':
		return "object", true
	case '[':
		return "array", true
	case '"':
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return nil, false
		}
		if len(str) > 64 {
			return fmt.Sprintf("string:%d", len(str)), true
		}
		return str, true
	default:
		// number or bool — echo the raw JSON verbatim.
		return raw, true
	}
}
