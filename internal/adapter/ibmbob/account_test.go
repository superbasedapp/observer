package ibmbob

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

// copyLogFixtures copies testdata/ibmbob/logs/shell/*.log into the Bob home
// that owns dbPath.
func copyLogFixtures(t *testing.T, dbPath string) {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "ibmbob", "logs", "shell")
	dst := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "logs", "shell")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeLog(t *testing.T, dbPath, name string, lines ...string) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "logs", "shell")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAccountObservationsReal parses the real anonymized tasks with the
// anonymized shell-log fixtures beside the store (the live Windows sign-in
// sequence: Logged out, SSO flow, Login successful <email>, then restored
// sessions with no e-mail). Every task that has messages was written after
// that sign-in, so each of its messages is bound to the e-mail; the
// hook-blocked tasks (no messages) get nothing.
func TestAccountObservationsReal(t *testing.T) {
	realSQL, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ibmbob", "real.sql"))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := newHome(t, "", string(realSQL), "")
	copyLogFixtures(t, dbPath)
	res := parseHome(t, dbPath)
	if len(res.ToolAccounts) == 0 {
		t.Fatal("no ToolAccounts emitted")
	}

	// Expected bindings: one per (role, message id) among the events.
	want := map[string]bool{}
	for _, e := range res.ToolEvents {
		if e.MessageID == "" {
			continue
		}
		role := "assistant"
		if e.ActionType == models.ActionUserPrompt {
			role = "user"
		}
		want[e.SessionID+"|"+role+"|"+e.MessageID] = true
	}
	got := map[string]bool{}
	perSession := map[string]int{}
	for _, o := range res.ToolAccounts {
		n, _, ok := toolaccount.Normalize(o)
		if !ok {
			t.Fatalf("observation refused by toolaccount.Normalize: %+v", o)
		}
		if n.Email != "user@example.com" || n.AccountID != "" || n.Name != "" {
			t.Errorf("identity = %q/%q/%q, want only the e-mail", n.Email, n.AccountID, n.Name)
		}
		if models.ToolAccountScopeIsAccountLevel(n.Scope) || n.Scope != accountScope || n.Source != accountSource {
			t.Errorf("scope/source = %q/%q", n.Scope, n.Source)
		}
		if n.Tool != models.ToolIBMBob || n.BindingKind != "message" {
			t.Errorf("tool/binding = %q/%q", n.Tool, n.BindingKind)
		}
		wantStage := "activity"
		if n.Role == "user" {
			wantStage = "submission"
		}
		if n.Stage != wantStage {
			t.Errorf("%s stage = %q, want %q", n.BindingID, n.Stage, wantStage)
		}
		key := n.SessionID + "|" + n.Role + "|" + n.BindingID
		if got[key] {
			t.Errorf("duplicate observation %s", key)
		}
		got[key] = true
		perSession[n.SessionID]++
	}
	if len(got) != len(want) {
		t.Errorf("bound %d (role, message) pairs, want %d", len(got), len(want))
	}
	for k := range got {
		if !want[k] {
			t.Errorf("observation %s binds no emitted message", k)
		}
	}
	for _, s := range []string{realWSLTask, realWinTask, realCompactTask} {
		if perSession[s] == 0 {
			t.Errorf("session %s has no account observation", s)
		}
	}
	for _, s := range []string{realHookBlockTsk, realHookBlockJSON} {
		if perSession[s] != 0 {
			t.Errorf("hook-blocked session %s bound %d observations, want 0", s, perSession[s])
		}
	}
}

// TestAccountObservationsNoLogs: no logs directory, no observations (the
// existing real-store tests run this way).
func TestAccountObservationsNoLogs(t *testing.T) {
	if res := parseReal(t); len(res.ToolAccounts) != 0 {
		t.Errorf("ToolAccounts = %d without logs, want 0", len(res.ToolAccounts))
	}
}

// TestAccountTimeline drives the sign-in rules over synthetic log lines:
// a login sets the account, a logout clears it, a restore keeps it, a
// second login replaces it, and malformed lines / non-addresses / other
// modules are ignored.
func TestAccountTimeline(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".bob", "db", dbFile)
	writeLog(t, dbPath, "bob-shell-20261020T090000.log",
		`{"ts":"2026-10-20T09:00:00.000Z","level":"info","module":"Auth","msg":"Logged out"}`,
		`{"ts":"2026-10-20T09:00:05.000Z","level":"info","module":"Auth","msg":"Login successful","data":"first@example.com"}`,
		`not json at all`,
		`{"ts":"2026-10-20T09:00:06.000Z","level":"info","module":"Gateway","msg":"Login successful","data":"gateway@example.com"}`,
		`{"ts":"2026-10-20T09:00:07.000Z","level":"info","module":"Auth","msg":"Login successful","data":"not an address"}`,
	)
	writeLog(t, dbPath, "bob-shell-20261020T100000.log",
		`{"ts":"2026-10-20T10:00:00.000Z","level":"info","module":"Auth","msg":"Restored session from stored tokens"}`,
		`{"ts":"2026-10-20T10:30:00.000Z","level":"info","module":"Auth","msg":"Logged out"}`,
		`{"ts":"2026-10-20T10:31:00.000Z","level":"info","module":"Auth","msg":"Login successful","data":"Second@Example.com"}`,
	)
	writeLog(t, dbPath, "unrelated.log",
		`{"ts":"2026-10-20T11:00:00.000Z","level":"info","module":"Auth","msg":"Login successful","data":"other@example.com"}`,
	)

	c := newLogCache()
	tl := c.readAccountTimeline(dbPath)
	at := func(s string) string {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tl.at(ts)
	}
	cases := []struct{ when, want string }{
		{"2026-10-20T08:59:59Z", ""},
		{"2026-10-20T09:00:05Z", "first@example.com"},
		{"2026-10-20T10:15:00Z", "first@example.com"},
		{"2026-10-20T10:30:30Z", ""},
		{"2026-10-20T12:00:00Z", "Second@Example.com"},
	}
	for _, tc := range cases {
		if got := at(tc.when); got != tc.want {
			t.Errorf("at(%s) = %q, want %q", tc.when, got, tc.want)
		}
	}
	if len(c.files) != 2 {
		t.Errorf("cache holds %d files, want 2 (unrelated.log is not a shell log)", len(c.files))
	}

	// A rewritten log is re-read. A log Bob deleted (it keeps its 10
	// newest) stays on the timeline from the cache: its sign-in and
	// sign-out are still history.
	writeLog(t, dbPath, "bob-shell-20261020T090000.log",
		`{"ts":"2026-10-20T09:00:05.000Z","level":"info","module":"Auth","msg":"Login successful","data":"changed-first@example.com"}`,
		`{"ts":"2026-10-20T09:00:06.000Z","level":"debug","module":"Auth","msg":"Auth state changed to","data":"authenticated"}`,
	)
	if err := os.Remove(filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "logs", "shell", "bob-shell-20261020T100000.log")); err != nil {
		t.Fatal(err)
	}
	tl = c.readAccountTimeline(dbPath)
	if got := tl.at(time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)); got != "changed-first@example.com" {
		t.Errorf("after rewrite at(09:30) = %q", got)
	}
	if got := tl.at(time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)); got != "Second@Example.com" {
		t.Errorf("after delete at(12:00) = %q, want the retained sign-in", got)
	}
	if len(c.files) != 2 {
		t.Errorf("cache holds %d files after delete, want 2", len(c.files))
	}

	// A fresh cache (a daemon started after the delete) only sees what is
	// on disk.
	if got := newLogCache().readAccountTimeline(dbPath).at(time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)); got != "changed-first@example.com" {
		t.Errorf("fresh cache at(12:00) = %q", got)
	}
	// A different home never sees this home's retained events.
	other := filepath.Join(t.TempDir(), ".bob", "db", dbFile)
	if got := c.readAccountTimeline(other); len(got) != 0 {
		t.Errorf("other home timeline = %+v, want empty", got)
	}
}

// TestLogCacheEvict: past maxCachedLogs, only entries for logs no longer
// on disk are dropped, oldest first.
func TestLogCacheEvict(t *testing.T) {
	c := newLogCache()
	for i := 0; i < maxCachedLogs+3; i++ {
		c.files[filepath.Join("d", "bob-shell-"+itoa(100000+i)+".log")] = cachedLog{}
	}
	live := filepath.Join("d", "bob-shell-100000.log")
	c.evict(map[string]bool{live: true})
	if len(c.files) != maxCachedLogs {
		t.Fatalf("cache = %d entries, want %d", len(c.files), maxCachedLogs)
	}
	if _, ok := c.files[live]; !ok {
		t.Error("evicted a log still on disk")
	}
	if _, ok := c.files[filepath.Join("d", "bob-shell-100001.log")]; ok {
		t.Error("oldest gone log was kept")
	}
}

// TestAccountObservationsBinding pins the per-message binding rules.
func TestAccountObservationsBinding(t *testing.T) {
	login := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	tl := accountTimeline{{At: login, Email: "user@example.com"}}
	ev := func(action, msg string, at time.Time) models.ToolEvent {
		return models.ToolEvent{ActionType: action, MessageID: msg, Timestamp: at}
	}
	after := login.Add(time.Minute)
	events := []models.ToolEvent{
		ev(models.ActionUserPrompt, "m1", after),
		ev(models.ActionAssistantMessage, "m2", after),
		ev(models.ActionWriteFile, "m2", after), // same assistant message
		ev(models.ActionAPIError, "", after),    // task error row: no message id
		ev(models.ActionUserPrompt, "m0", login.Add(-time.Minute)),
	}
	got := accountObservations(tl, "s1", events)
	if len(got) != 2 {
		t.Fatalf("got %d observations, want 2: %+v", len(got), got)
	}
	if got[0].Role != "user" || got[0].BindingID != "m1" || got[0].Stage != "submission" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Role != "assistant" || got[1].BindingID != "m2" || got[1].Stage != "activity" {
		t.Errorf("second = %+v", got[1])
	}
	if accountObservations(nil, "s1", events) != nil {
		t.Error("empty timeline produced observations")
	}
}

func TestPlausibleEmail(t *testing.T) {
	for s, want := range map[string]bool{
		"user@example.com":     true,
		" user@example.com ":   true,
		"user@localhost":       false,
		"@example.com":         false,
		"user@@example.com":    false,
		"user example@x.com":   false,
		"user@example.":        false,
		"":                     false,
		"authenticated":        false,
		"user@example.com\nxx": false,
	} {
		if got := plausibleEmail(s); got != want {
			t.Errorf("plausibleEmail(%q) = %v, want %v", s, got, want)
		}
	}
}
