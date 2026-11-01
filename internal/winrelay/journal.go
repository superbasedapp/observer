package winrelay

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The bypass journal: one JSON line per fail-open forward, written by the
// relay on the Windows host before the request leaves, and read by the
// node's doctor and managed-integrity step. Metadata only: the time, the
// lane tool, the provider host, the HTTP method, a sanitized path and the
// reason. Never a header (so never a credential), a query string, a body,
// a model name taken from a body, or the client's address.

// JournalDir and JournalFile name the journal under the Windows user's home:
// <home>/.observer/relay/bypass.jsonl. The relay writes it there, and a WSL
// daemon reads it through the home's /mnt/<drive> mount.
const (
	JournalDir  = ".observer/relay"
	JournalFile = "bypass.jsonl"
	// JournalRotated is the one older generation kept beside the journal
	// when it reaches its size cap.
	JournalRotated = JournalFile + ".1"
)

// JournalDirUnder is the ONE place the journal's directory is derived from a
// home: <home>/.observer/relay. The relay writes there and every reader
// (the doctor, the managed report, `observer relay status`) reads there;
// nothing relocates it (no flag, no config key, not the database path), so
// a bypass can never be recorded where no reader looks.
func JournalDirUnder(home string) string {
	return filepath.Join(home, filepath.FromSlash(JournalDir))
}

// DefaultJournalMaxBytes caps the journal before it rotates (1 MiB, about
// 5,000 records). The reader reads both generations.
const DefaultJournalMaxBytes = 1 << 20

// ReasonProxyUnreachable is the one bypass reason today: no connection to
// Observer's proxy could be opened.
const ReasonProxyUnreachable = "proxy_unreachable"

// Entry is one recorded bypass.
type Entry struct {
	At       time.Time `json:"at"`
	Tool     string    `json:"tool"`
	Upstream string    `json:"upstream"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Reason   string    `json:"reason"`
}

// maxPathLen bounds a recorded path.
const maxPathLen = 128

// SanitizePath returns the path a record carries: the request path only
// (the caller strips the query), cut to maxPathLen, and "other" when it holds
// a byte outside the plain URL path alphabet, so nothing a client encoded
// into an unusual path lands in the file.
func SanitizePath(p string) string {
	if p == "" {
		return "/"
	}
	if len(p) > maxPathLen {
		p = p[:maxPathLen]
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("/._:-", c) >= 0
		if !ok {
			return "other"
		}
	}
	return p
}

// SanitizeMethod returns an HTTP method a record carries: an upper-case
// token of at most 16 letters, else "OTHER".
func SanitizeMethod(m string) string {
	if m == "" || len(m) > 16 {
		return "OTHER"
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return "OTHER"
		}
	}
	return m
}

// Encode renders one entry as a journal line (JSON plus a newline), with the
// time in UTC.
func Encode(e Entry) ([]byte, error) {
	e.At = e.At.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseJournal decodes journal bytes. A line that does not decode, has no
// time or names no tool is skipped and counted; an unterminated last line (a
// write in progress) is skipped the same way.
func ParseJournal(data []byte) (entries []Entry, skipped int) {
	for len(data) > 0 {
		line, rest, found := bytes.Cut(data, []byte{'\n'})
		data = rest
		if !found {
			if len(bytes.TrimSpace(line)) > 0 {
				skipped++
			}
			break
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil || e.At.IsZero() || e.Tool == "" {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	return entries, skipped
}

// ToolSummary is the recorded bypasses of one tool inside a window.
type ToolSummary struct {
	Tool  string
	Count int
	First time.Time
	Last  time.Time
}

// Summary is the journal read for one window.
type Summary struct {
	Tools   []ToolSummary
	Skipped int
}

// Total is the number of recorded bypasses in the summary.
func (s Summary) Total() int {
	n := 0
	for _, t := range s.Tools {
		n += t.Count
	}
	return n
}

// Summarize groups the entries at or after since by tool, sorted by tool.
func Summarize(entries []Entry, since time.Time, skipped int) Summary {
	by := map[string]*ToolSummary{}
	for _, e := range entries {
		if e.At.Before(since) {
			continue
		}
		t := by[e.Tool]
		if t == nil {
			t = &ToolSummary{Tool: e.Tool, First: e.At, Last: e.At}
			by[e.Tool] = t
		}
		t.Count++
		if e.At.Before(t.First) {
			t.First = e.At
		}
		if e.At.After(t.Last) {
			t.Last = e.At
		}
	}
	out := Summary{Skipped: skipped}
	for _, t := range by {
		out.Tools = append(out.Tools, *t)
	}
	sort.Slice(out.Tools, func(i, j int) bool { return out.Tools[i].Tool < out.Tools[j].Tool })
	return out
}
