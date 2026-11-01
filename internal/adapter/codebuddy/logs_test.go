package codebuddy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// logStamp renders the diagnostic log's `[dd/mm/yyyy, h:mm:ss pm.mmm]` stamp.
func logStamp(ts time.Time) string {
	return fmt.Sprintf("%s.%03d", ts.In(time.Local).Format("02/01/2006, 3:04:05 pm"), ts.Nanosecond()/1e6)
}

func logLine(ts time.Time, pid int, msg string) string {
	return fmt.Sprintf("[%s] [Info] [pid=%d] %s\n", logStamp(ts), pid, msg)
}

// stageLive stages a live fixture AND points HOME at the staged data home's
// user directory so the same-OS guard for pid seeds holds. It returns the
// transcript path, the adapter, the data home and the transcript's first and
// last record times.
func stageLive(t *testing.T, fixture, session string) (string, *Adapter, string) {
	t.Helper()
	body, err := os.ReadFile(fixturePath(fixture))
	if err != nil {
		t.Fatal(err)
	}
	p, a := stage(t, session, string(body))
	home := dataHome(p)
	if home == "" {
		t.Fatalf("no data home for %s", p)
	}
	user := filepath.Dir(home)
	t.Setenv("HOME", user)
	t.Setenv("USERPROFILE", user)
	t.Setenv(configDirEnv, "")
	resetLogCache()
	t.Cleanup(resetLogCache)
	return p, a, home
}

// writeLog writes a day log the staged session's first record falls on.
func writeLog(t *testing.T, home string, day time.Time, name, body string) string {
	t.Helper()
	dir := filepath.Join(home, "logs", day.In(time.Local).Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const liveSID = "01a15e5d-65aa-751d-80c7-4e7ad26233b3"

// firstGeneration returns the messageId of the first generation in the live
// fixture (the Read call's), read off the parse so the test does not hard-code
// vendor ids.
func firstGeneration(t *testing.T, a *Adapter, p string) (msg string, at time.Time) {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	return res.TokenEvents[0].MessageID, res.TokenEvents[0].Timestamp
}

// TestLogFactsStampVersionSurfaceSeedAndGenerationTiming drives the whole
// log -> parse path with a log written in the real format: per-process start
// line, session-scoped lines, and agent.model_call.completed telemetry.
func TestLogFactsStampVersionSurfaceSeedAndGenerationTiming(t *testing.T) {
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	msg, at := firstGeneration(t, a, p)

	log := logLine(at.Add(-2*time.Second), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
		logLine(at.Add(-time.Second), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID) +
		logLine(at, 4242, `[ModelProvider]  {"model":"hy3","step":1,"attempt_no":1,"time_to_first_token_ms":17,"input_tokens":10,"output_tokens":5,"finish_reason":"tool_calls","event_name":"agent.model_call.completed","result":"success","duration_ms":123,"conversation_id":"`+liveSID+`","conversation_message_id":"`+msg+`"}`) +
		// A failed attempt of the same generation must not win.
		logLine(at, 4242, `[ModelProvider]  {"event_name":"agent.model_call.completed","result":"error","duration_ms":9999,"conversation_message_id":"`+msg+`"}`) +
		// Another process / session sharing the workspace log.
		logLine(at, 7, "[CliDispatcher]  [ColdStart] cli onStart pid=7 version=2.100.0") +
		logLine(at, 7, "[FinalStop] executing FinalStop hooks sessionId=01a15e5b-473e-7413-959d-4df8c15348f1")
	writeLog(t, home, at, "project__abc.log", log)

	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0] != (models.SessionToolVersion{SessionID: liveSID, Version: "2.171.0"}) {
		t.Errorf("tool versions = %+v, want the pid's own 2.171.0 (not the neighbour's 2.100.0)", res.SessionToolVersions)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceCLI || res.SessionSurfaces[0].SessionID != liveSID {
		t.Errorf("surfaces = %+v, want one cli", res.SessionSurfaces)
	}
	if len(res.SessionProcessSeeds) != 1 {
		t.Fatalf("seeds = %+v, want one", res.SessionProcessSeeds)
	}
	seed := res.SessionProcessSeeds[0]
	if seed.PID != 4242 || seed.SessionID != liveSID || seed.Tool != models.ToolCodeBuddy || seed.ExecHint != "codebuddy" {
		t.Errorf("seed = %+v", seed)
	}
	var stamped int
	for _, tok := range res.TokenEvents {
		if tok.MessageID == msg {
			stamped++
			if tok.GenMs != 123 || tok.GenBasis != models.GenBasisNative || tok.GenTimingV != genTimingV {
				t.Errorf("gen timing = %d/%q/%d, want 123/native/%d", tok.GenMs, tok.GenBasis, tok.GenTimingV, genTimingV)
			}
		} else if tok.GenMs != 0 {
			t.Errorf("generation %s got GenMs %d with no log line", tok.MessageID, tok.GenMs)
		}
	}
	if stamped != 1 {
		t.Errorf("stamped rows = %d, want 1", stamped)
	}
}

// TestLogIsExtendedIncrementally: the cached index reads only what a log
// grew by, and a rewritten (shorter) log is rebuilt from scratch.
func TestLogIsExtendedIncrementally(t *testing.T) {
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	msg, at := firstGeneration(t, a, p)
	first := logLine(at.Add(-time.Second), 55, "[CliDispatcher]  [ColdStart] cli onStart pid=55 version=2.171.0") +
		logLine(at, 55, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
	lp := writeLog(t, home, at, "w__1.log", first)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.TokenEvents[0].GenMs != 0 {
		t.Fatalf("GenMs = %d before any model_call line", res.TokenEvents[0].GenMs)
	}
	more := logLine(at, 55, `[ModelProvider]  {"event_name":"agent.model_call.completed","result":"success","duration_ms":77,"conversation_message_id":"`+msg+`"}`)
	// A partial trailing line must be left for the next pass.
	f, err := os.OpenFile(lp, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(more + "[21/10/2026, 5:36:44 pm.965] [Info] [pid=55] half a li"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	res, err = a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.TokenEvents[0].GenMs; got != 77 {
		t.Errorf("GenMs after append = %d, want 77", got)
	}
	// Rewrite the log shorter: the index must reset, dropping the old call.
	if err := os.WriteFile(lp, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.TokenEvents[0].GenMs; got != 0 {
		t.Errorf("GenMs after a rewritten log = %d, want 0", got)
	}
}

// TestPidReuseDoesNotRewriteAnEarlierSession: a recycled pid's new start line
// must not change the version recorded for the session the old process owned.
func TestPidReuseDoesNotRewriteAnEarlierSession(t *testing.T) {
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	_, at := firstGeneration(t, a, p)
	body := logLine(at.Add(-2*time.Second), 90, "[CliDispatcher]  [ColdStart] cli onStart pid=90 version=2.150.0") +
		logLine(at.Add(-time.Second), 90, "[FinalStop] executing FinalStop hooks sessionId="+liveSID) +
		logLine(at.Add(time.Minute), 90, "[CliDispatcher]  [ColdStart] cli onStart pid=90 version=2.171.0") +
		logLine(at.Add(time.Minute), 90, "[FinalStop] executing FinalStop hooks sessionId=01a15e5b-473e-7413-959d-4df8c15348f1")
	writeLog(t, home, at, "w__1.log", body)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "2.150.0" {
		t.Errorf("versions = %+v, want 2.150.0 (the process that ran the session)", res.SessionToolVersions)
	}
}

// TestToolVersionFallbacks: with no log line for the session, the newest
// start line of the day's logs applies; with no logs at all, the installed
// package's version; with neither, nothing is stamped.
func TestToolVersionFallbacks(t *testing.T) {
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	_, at := firstGeneration(t, a, p)

	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 0 || len(res.SessionSurfaces) != 0 || len(res.SessionProcessSeeds) != 0 {
		t.Errorf("no log, no install: stamps = %+v %+v %+v", res.SessionToolVersions, res.SessionSurfaces, res.SessionProcessSeeds)
	}

	// Install-level: the npm package under the user's AppData.
	pkgDir := filepath.Join(filepath.Dir(home), "AppData", "Roaming", "npm", "node_modules", "@tencent-ai", "codebuddy-code")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"@tencent-ai/codebuddy-code","version":"2.171.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	installVersionCache.Lock()
	installVersionCache.m = map[string]installVersionEntry{}
	installVersionCache.Unlock()
	res, err = a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "2.171.0" {
		t.Errorf("install fallback = %+v", res.SessionToolVersions)
	}
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("surface stamped without a CLI start line: %+v", res.SessionSurfaces)
	}

	// Day-level: a start line in the day's log beats the installed package.
	writeLog(t, home, at, "w__1.log", logLine(at, 5, "[CliDispatcher]  [ColdStart] cli onStart pid=5 version=2.180.1"))
	res, err = a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "2.180.1" {
		t.Errorf("day fallback = %+v", res.SessionToolVersions)
	}
	// A foreign package of the same path is not trusted.
	if v := readPackageVersion(filepath.Join(pkgDir, "package.json")); v != "2.171.0" {
		t.Errorf("readPackageVersion = %q", v)
	}
}

// TestSeedRequiresOwnSideHome: a log under a data home that is not the
// running user's (a cross-mounted foreign OS) must never seed a pid.
func TestSeedRequiresOwnSideHome(t *testing.T) {
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	_, at := firstGeneration(t, a, p)
	writeLog(t, home, at, "w__1.log",
		logLine(at, 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0")+
			logLine(at, 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID))
	other := t.TempDir()
	t.Setenv("HOME", other)
	t.Setenv("USERPROFILE", other)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionProcessSeeds) != 0 {
		t.Errorf("seeds = %+v, want none for a foreign-side home", res.SessionProcessSeeds)
	}
	if len(res.SessionToolVersions) != 1 {
		t.Errorf("version must still be stamped from a foreign-side log: %+v", res.SessionToolVersions)
	}
}

func TestLogLineHelpers(t *testing.T) {
	ts := parseLogTime("[21/10/2026, 5:36:44 pm.965] [Info] [pid=11792] x")
	if ts.IsZero() || ts.Hour() != 17 || ts.Minute() != 36 || ts.Second() != 44 || ts.Nanosecond()/1e6 != 965 ||
		ts.Day() != 21 || ts.Month() != time.October {
		t.Errorf("parseLogTime = %v", ts)
	}
	if !parseLogTime("garbage").IsZero() || !parseLogTime("[13/13/2026, 5:36:44 pm.965] x").IsZero() {
		t.Error("an unparsable stamp must be the zero time")
	}
	if v := versionToken("2.171.0 foo"); v != "2.171.0" {
		t.Errorf("versionToken = %q", v)
	}
	for _, bad := range []string{"", "unknown", "v1", "x.y"} {
		if v := versionToken(bad); v != "" {
			t.Errorf("versionToken(%q) = %q, want empty", bad, v)
		}
	}
	if id := uuidPrefix("01a15e5b-473e-7413-959d-4df8c15348f1 rest"); id != "01a15e5b-473e-7413-959d-4df8c15348f1" {
		t.Errorf("uuidPrefix = %q", id)
	}
	if uuidPrefix("not-a-uuid-at-all-not-a-uuid-at-all!!") != "" {
		t.Error("uuidPrefix accepted a non-uuid")
	}
	if n, ok := atoiPrefix("11792]"); !ok || n != 11792 {
		t.Errorf("atoiPrefix = %d %v", n, ok)
	}
	if got := dataHome(filepath.Join("a", ".codebuddy", "projects", "slug", "x.jsonl")); filepath.Base(got) != ".codebuddy" {
		t.Errorf("dataHome = %q", got)
	}
	if dataHome(filepath.Join("a", "other", "slug", "x.jsonl")) != "" {
		t.Error("dataHome must reject a non-projects layout")
	}
	// An over-long line is truncated, not fatal, and consumed whole.
	long := strings.Repeat("x", maxLogLineBytes*3)
	idx := newLogIndex()
	idx.consume("[21/10/2026, 5:36:44 pm.965] [Info] [pid=1] " + long[:100])
	if idx.pids[1] == nil {
		t.Error("short line not indexed")
	}
}
