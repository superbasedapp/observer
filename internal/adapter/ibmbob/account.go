package ibmbob

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Bob Shell's per-process debug log: `<home>/.bob/logs/shell/
// bob-shell-<local ts>.log`, NDJSON lines {ts, level, module, msg, data?}.
// Live-grounded 2026-10-21 (bobshell 2.0.6, Windows): an SSO sign-in logs
// module "Auth", msg "Login successful", data = the signed-in e-mail; a
// later launch logs "Restored session from stored tokens" with no e-mail
// (the stored tokens belong to that same login); a sign-out logs "Logged
// out". The vendor logs the login's userId, which is the e-mail on every
// grounded install. No line carries a task id, a pid or an account id, so
// a task is attributed by TIME: the e-mail in force when its message was
// written.
const (
	logsDirRel  = "logs/shell"
	logPrefix   = "bob-shell-"
	logSuffix   = ".log"
	authModule  = "Auth"
	maxLogFiles = 2000
	maxLogBytes = 8 << 20
	maxLogLine  = 1 << 20

	// accountSource / accountScope label the observation. The e-mail is
	// the person who signed in to IBM Bob (an IBMid SSO login), so it is
	// PERSON-level evidence (Email set, not the account-level marker):
	// toolaccount.Normalize refuses an account-level row that carries an
	// e-mail, and an e-mail placed in AccountID would let the unsalted
	// account key ship under the metadata-only org posture (PRIV-1).
	accountSource = "ibm_bob_shell_log"
	accountScope  = "login_log"
)

// authNeedle is the cheap pre-filter for Auth lines.
var authNeedle = []byte(`"` + authModule + `"`)

// authEffect is what one Auth log line does to the signed-in account.
type authEffect int

const (
	authLogin authEffect = iota + 1
	authLogout
)

// authRules maps an Auth log message onto its effect, matched exactly.
// "Restored session from stored tokens" and "Auth state changed to" keep
// the current account and are deliberately absent.
var authRules = map[string]authEffect{
	"Login successful": authLogin,
	"Logged out":       authLogout,
}

// authEvent is one sign-in (Email set) or sign-out (Email "") at At.
type authEvent struct {
	At    time.Time
	Email string
}

// accountTimeline is a home's sign-in history, ordered by time.
type accountTimeline []authEvent

// at returns the e-mail signed in at t: the latest event at or before t,
// "" when that event is a sign-out or no event precedes t (a login older
// than the oldest kept log is never assumed).
func (tl accountTimeline) at(t time.Time) string {
	i := sort.Search(len(tl), func(i int) bool { return tl[i].At.After(t) })
	if i == 0 {
		return ""
	}
	return tl[i-1].Email
}

// logCache keeps each log file's parsed Auth events keyed by path, reused
// while the file's size and modification time are unchanged (a finished
// process's log never changes again).
//
// Bob keeps only its 10 newest logs (bobshell 2.0.6 prunes the rest at
// startup), so the one "Login successful" line is deleted ten launches
// after the sign-in while the stored tokens it minted stay in use. The
// cache therefore KEEPS the events of a log Bob has deleted: a sign-in the
// running daemon once read stays on the timeline for the daemon's
// lifetime. A daemon that starts after the login log is gone has no e-mail
// to bind (documented gap; the only other copy is auth-secrets.json, which
// is never read).
type logCache struct {
	mu    sync.Mutex
	files map[string]cachedLog
}

type cachedLog struct {
	size   int64
	mod    time.Time
	events []authEvent
}

// maxCachedLogs bounds the cache; past it, entries for logs no longer on
// disk are evicted oldest-name first.
const maxCachedLogs = 4096

func newLogCache() *logCache { return &logCache{files: map[string]cachedLog{}} }

// readAccountTimeline builds the sign-in timeline of the Bob home that owns
// dbPath (`<home>/.bob/db/bob.db` -> `<home>/.bob/logs/shell`): the Auth
// events of every log on disk plus those of logs Bob has since deleted that
// this cache read earlier. Only Auth lines are decoded and only their
// e-mail is kept; auth-secrets.json and every settings file are never
// opened. No logs yield an empty timeline.
func (c *logCache) readAccountTimeline(dbPath string) accountTimeline {
	dir := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), filepath.FromSlash(logsDirRel))
	var names []string
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if e.Type().IsRegular() && strings.HasPrefix(n, logPrefix) && strings.HasSuffix(n, logSuffix) {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	if len(names) > maxLogFiles {
		names = names[len(names)-maxLogFiles:]
	}
	var tl accountTimeline
	onDisk := make(map[string]bool, len(names))
	for _, n := range names {
		p := filepath.Join(dir, n)
		onDisk[p] = true
		tl = append(tl, c.eventsFor(p)...)
	}
	tl = append(tl, c.retained(dir, onDisk)...)
	c.evict(onDisk)
	sort.SliceStable(tl, func(i, j int) bool { return tl[i].At.Before(tl[j].At) })
	return tl
}

// eventsFor returns one log file's Auth events, from the cache when the
// file is unchanged.
func (c *logCache) eventsFor(path string) []authEvent {
	fi, err := os.Stat(path) //nolint:gosec // G703: a Bob shell log beside the watcher-discovered store, stat only
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if c != nil {
		c.mu.Lock()
		hit, ok := c.files[path]
		c.mu.Unlock()
		if ok && hit.size == fi.Size() && hit.mod.Equal(fi.ModTime()) {
			return hit.events
		}
	}
	events := readAuthEvents(path)
	if c != nil {
		c.mu.Lock()
		c.files[path] = cachedLog{size: fi.Size(), mod: fi.ModTime(), events: events}
		c.mu.Unlock()
	}
	return events
}

// retained returns the cached events of logs in dir that are no longer on
// disk, in path order.
func (c *logCache) retained(dir string, onDisk map[string]bool) []authEvent {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var paths []string
	for p := range c.files {
		if !onDisk[p] && filepath.Dir(p) == dir {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []authEvent
	for _, p := range paths {
		out = append(out, c.files[p].events...)
	}
	return out
}

// evict trims the cache back to maxCachedLogs by dropping entries for logs
// that are no longer on disk, oldest path first.
func (c *logCache) evict(onDisk map[string]bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.files) <= maxCachedLogs {
		return
	}
	var gone []string
	for p := range c.files {
		if !onDisk[p] {
			gone = append(gone, p)
		}
	}
	sort.Strings(gone)
	for _, p := range gone {
		if len(c.files) <= maxCachedLogs {
			return
		}
		delete(c.files, p)
	}
}

// readAuthEvents decodes the sign-in / sign-out lines of one log file.
func readAuthEvents(path string) []authEvent {
	f, err := os.Open(path) //nolint:gosec // vendor debug log under the Bob home
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxLogBytes))
	sc.Buffer(make([]byte, 0, 64<<10), maxLogLine)
	var out []authEvent
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, authNeedle) {
			continue
		}
		var rec struct {
			TS     string          `json:"ts"`
			Module string          `json:"module"`
			Msg    string          `json:"msg"`
			Data   json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Module != authModule {
			continue
		}
		effect, ok := authRules[rec.Msg]
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rec.TS)
		if err != nil {
			continue
		}
		ev := authEvent{At: at.UTC()}
		if effect == authLogin {
			var email string
			if json.Unmarshal(rec.Data, &email) != nil || !plausibleEmail(email) {
				continue
			}
			ev.Email = strings.TrimSpace(email)
		}
		out = append(out, ev)
	}
	return out
}

// plausibleEmail accepts a single address: one "@" with a non-empty local
// part and a dotted domain, no whitespace or control characters, at most
// 254 bytes. Anything else is not taken as an identity.
func plausibleEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return false
	}
	dot := strings.LastIndex(domain, ".")
	return dot > 0 && dot < len(domain)-1
}

// accountObservations binds the e-mail signed in when each message was
// written to that message, once per (role, message id): user prompts as
// "submission", assistant text / tool calls / notices as "activity". A
// message with no signed-in account in the timeline gets nothing, and an
// event without a message id (the task error row) is never bound.
func accountObservations(tl accountTimeline, sessionID string, events []models.ToolEvent) []models.ToolAccountObservation {
	if len(tl) == 0 || sessionID == "" {
		return nil
	}
	var out []models.ToolAccountObservation
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.MessageID == "" || ev.Timestamp.IsZero() {
			continue
		}
		role, stage := "assistant", "activity"
		if ev.ActionType == models.ActionUserPrompt {
			role, stage = "user", "submission"
		}
		key := role + "|" + ev.MessageID
		if seen[key] {
			continue
		}
		seen[key] = true
		email := tl.at(ev.Timestamp)
		if email == "" {
			continue
		}
		out = append(out, models.ToolAccountObservation{
			SessionID:   sessionID,
			Tool:        models.ToolIBMBob,
			BindingKind: "message",
			BindingID:   ev.MessageID,
			Role:        role,
			Email:       email,
			Source:      accountSource,
			Scope:       accountScope,
			Stage:       stage,
			ObservedAt:  ev.Timestamp,
		})
	}
	return out
}
