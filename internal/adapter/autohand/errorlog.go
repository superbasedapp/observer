package autohand

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// errorLogName is the vendor's append-only failure log in the data home.
	errorLogName = "error.log"

	// maxErrorLogTail bounds how much of error.log is read: the newest
	// records only. The log is pretty-printed JSON records separated by a
	// `---` line and grows without bound.
	maxErrorLogTail = 1 << 20

	// errorWindowSlack widens a session's [createdAt, lastActiveAt] span
	// when attributing a log record to it: a failure is logged just before
	// the session record is saved, and a session's last save can precede
	// the final retry.
	errorWindowSlack = 5 * time.Second

	maxLogMessageBytes = 500
)

// versionPattern bounds what is stamped as a tool version (the store rejects
// anything prose-shaped anyway).
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

// logEntry is the part of one error.log record this adapter uses: when it was
// written, which CLI build wrote it and in which workspace, plus the error
// class and message. The record also carries host facts (hostname, user name,
// memory, CPU) and a stack; none of them is decoded.
type logEntry struct {
	When       time.Time
	Version    string
	Workspace  string
	ErrorName  string
	ErrorLine  string
	ErrorFirst string
}

type rawLogRecord struct {
	Timestamp string `json:"timestamp"`
	Error     struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
	Context struct {
		Workspace string `json:"workspace"`
	} `json:"context"`
	CLI struct {
		Version string `json:"version"`
	} `json:"cli"`
}

// parseErrorLog decodes the records of an error.log body. A malformed record
// is skipped, never fatal. The result is sorted by time.
func parseErrorLog(body []byte) []logEntry {
	var out []logEntry
	for _, chunk := range splitLogRecords(body) {
		var r rawLogRecord
		if json.Unmarshal(chunk, &r) != nil {
			continue
		}
		when := parseTime(r.Timestamp)
		if when.IsZero() {
			continue
		}
		e := logEntry{
			When:      when,
			Workspace: r.Context.Workspace,
			ErrorName: r.Error.Name,
		}
		if v := strings.TrimSpace(r.CLI.Version); versionPattern.MatchString(v) {
			e.Version = v
		}
		msg := strings.TrimSpace(r.Error.Message)
		if msg != "" {
			e.ErrorLine = truncate(msg, maxLogMessageBytes)
			first, _, _ := strings.Cut(msg, "\n")
			e.ErrorFirst = truncate(strings.TrimSpace(first), maxTargetLen)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].When.Before(out[j].When) })
	return out
}

// splitLogRecords splits on lines consisting solely of `---`.
func splitLogRecords(body []byte) [][]byte {
	var recs [][]byte
	var cur []byte
	for _, line := range bytes.Split(body, []byte("\n")) {
		if string(bytes.TrimSpace(line)) == "---" {
			if len(bytes.TrimSpace(cur)) > 0 {
				recs = append(recs, cur)
			}
			cur = nil
			continue
		}
		cur = append(cur, line...)
		cur = append(cur, '\n')
	}
	if len(bytes.TrimSpace(cur)) > 0 {
		recs = append(recs, cur)
	}
	return recs
}

type logCacheItem struct {
	mod     time.Time
	size    int64
	entries []logEntry
}

// errorLog returns the decoded tail of <dataHome>/error.log, cached by
// (mtime, size) so a busy watcher does not re-read it per transcript line.
func (a *Adapter) errorLog(dataHome string) []logEntry {
	path := filepath.Join(dataHome, errorLogName)
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	a.mu.Lock()
	if c, ok := a.logCache[path]; ok && c.mod.Equal(fi.ModTime()) && c.size == fi.Size() {
		a.mu.Unlock()
		return c.entries
	}
	a.mu.Unlock()

	f, err := os.Open(path) //nolint:gosec // vendor failure log beside the watched sessions dir
	if err != nil {
		return nil
	}
	defer f.Close()
	start := int64(0)
	if fi.Size() > maxErrorLogTail {
		start = fi.Size() - maxErrorLogTail
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return nil
		}
	}
	body, err := io.ReadAll(io.LimitReader(f, maxErrorLogTail+1))
	if err != nil {
		return nil
	}
	if start > 0 {
		// The first record is cut mid-way: drop through the first separator.
		if i := bytes.Index(body, []byte("\n---\n")); i >= 0 {
			body = body[i+len("\n---\n"):]
		} else {
			body = nil
		}
	}
	entries := parseErrorLog(body)
	a.mu.Lock()
	if a.logCache == nil {
		a.logCache = map[string]logCacheItem{}
	}
	a.logCache[path] = logCacheItem{mod: fi.ModTime(), size: fi.Size(), entries: entries}
	a.mu.Unlock()
	return entries
}

// samePath compares a log record's workspace with a session projectPath,
// tolerant of separator style and (for drive-letter paths) case.
func samePath(a, b string) bool {
	norm := func(p string) string {
		p = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"), "/")
		if pathFamily(p) == "windows" {
			p = strings.ToLower(p)
		}
		return p
	}
	return a != "" && b != "" && norm(a) == norm(b)
}

// sessionSpan returns the [from, to] interval a log record must fall in to be
// attributed to the session.
func sessionSpan(m metadata) (from, to time.Time) {
	from = parseTime(m.CreatedAt)
	to = parseTime(m.LastActiveAt)
	if to.Before(from) {
		to = from
	}
	return from, to.Add(errorWindowSlack)
}

// entriesFor returns the log records written during the session, in its
// workspace.
func entriesFor(entries []logEntry, m metadata) []logEntry {
	from, to := sessionSpan(m)
	if from.IsZero() {
		return nil
	}
	var out []logEntry
	for _, e := range entries {
		if e.When.Before(from) || e.When.After(to) {
			continue
		}
		if e.Workspace != "" && m.ProjectPath != "" && !samePath(e.Workspace, m.ProjectPath) {
			continue
		}
		out = append(out, e)
	}
	return out
}
