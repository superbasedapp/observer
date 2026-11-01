package dirac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

const (
	winDistinct = "aaaaaaaa0123456789abcdef0123456789abcdef0123456789abcdefffffffff"
	linDistinct = "bbbbbbbbfedcba9876543210fedcba9876543210fedcba987654321000000000"
)

// pinNativeHomes makes the foreign-mount seam deterministic: no home is a
// foreign mount, so fixture paths under t.TempDir() are native.
func pinNativeHomes(t *testing.T) {
	t.Helper()
	old := allHomesFunc
	t.Cleanup(func() { allHomesFunc = old })
	allHomesFunc = func() []crossmount.HomeRoot { return nil }
}

// TestProbeTaskTimingsModeAndAccount replays the real Windows probe task
// (read_file, execute_command, edit_file, respond) and pins the
// dimensions the audit found unread: per-call generation span, per-tool
// duration from the ui cards, plan/act mode, the log-derived pid seed and
// the account-level install id.
func TestProbeTaskTimingsModeAndAccount(t *testing.T) {
	pinNativeHomes(t)
	root, _ := copyFixture(t, "windows")
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, "1792584662340", opsName)
	res := parseAll(t, a, path)
	if len(res.Warnings) != 0 {
		t.Errorf("warnings: %v", res.Warnings)
	}
	want := []struct {
		raw string
		dur int64
	}{
		{"dirac.user_prompt", 0},
		{"read_file", 12},        // card 1792584672856 -> 1792584672868
		{"execute_command", 148}, // card 1792584681320 -> 1792584681468
		{"edit_file", 48},        // card 1792584688924 -> 1792584688972
		{"respond.complete", 0},  // a message, not work: never timed
	}
	if len(res.ToolEvents) != len(want) {
		t.Fatalf("actions = %v", rawNames(res.ToolEvents))
	}
	for i, w := range want {
		e := res.ToolEvents[i]
		if e.RawToolName != w.raw || e.DurationMs != w.dur {
			t.Errorf("event %d = %s dur=%d, want %s dur=%d", i, e.RawToolName, e.DurationMs, w.raw, w.dur)
		}
		if i > 0 && (e.Metadata == nil || e.Metadata.CollaborationMode != "act") {
			t.Errorf("event %d (%s) mode metadata = %+v, want collaboration_mode act", i, e.RawToolName, e.Metadata)
		}
	}
	// Generation span = assistant message ts - its api_status create ts.
	wantGen := []int64{3450, 3214, 3275, 4350}
	if len(res.TokenEvents) != len(wantGen) {
		t.Fatalf("token rows = %d", len(res.TokenEvents))
	}
	for i, k := range res.TokenEvents {
		if k.GenMs != wantGen[i] || k.GenBasis != models.GenBasisNative || k.GenTimingV != diracGenTimingV {
			t.Errorf("token %d gen = %d/%q/v%d, want %d/native/v%d", i, k.GenMs, k.GenBasis, k.GenTimingV, wantGen[i], diracGenTimingV)
		}
		if k.EstimatedCostUSD != 0 {
			t.Errorf("token %d cost = %v, want 0 (subscription provider reports 0)", i, k.EstimatedCostUSD)
		}
	}
	// pid seed from the log's [Task <id>] lines.
	if len(res.SessionProcessSeeds) != 1 {
		t.Fatalf("seeds = %+v", res.SessionProcessSeeds)
	}
	seed := res.SessionProcessSeeds[0]
	if seed.PID != 38164 || seed.SessionID != "1792584662340" || seed.Tool != models.ToolDirac || seed.ExecHint != "dirac" {
		t.Errorf("seed = %+v", seed)
	}
	if !strings.HasSuffix(filepath.ToSlash(seed.CWD), "Users/user/project") {
		t.Errorf("seed cwd = %q", seed.CWD)
	}
	// Account: one observation per prompt + per assistant message, all
	// account-level, accepted by the shared normalizer.
	if len(res.ToolAccounts) != 5 {
		t.Fatalf("accounts = %d, want 5 (1 prompt + 4 assistant messages)", len(res.ToolAccounts))
	}
	for _, o := range res.ToolAccounts {
		if o.AccountID != winDistinct || o.Email != "" || o.Name != "" || !models.ToolAccountScopeIsAccountLevel(o.Scope) {
			t.Errorf("account obs = %+v, want account-level %s", o, winDistinct)
		}
		if _, _, ok := toolaccount.Normalize(o); !ok {
			t.Errorf("Normalize refused %+v", o)
		}
	}
	// Message-bound: every binding id is a message id the rows carry.
	ids := map[string]bool{}
	for _, e := range res.ToolEvents {
		ids[e.MessageID] = true
	}
	for _, o := range res.ToolAccounts {
		if !ids[o.BindingID] {
			t.Errorf("binding %q matches no emitted MessageID", o.BindingID)
		}
	}
}

// TestPermissionCardDoesNotCountAsExecution: a write's execution card is
// "running" while its Permission Request card waits for the human; that
// wait is subtracted. The approval card of execute_command precedes the
// execution card and never counts.
func TestPermissionCardDoesNotCountAsExecution(t *testing.T) {
	pinNativeHomes(t)
	root, _ := copyFixture(t, "linux")
	a := NewWithOptions(nil, root)
	res := parseAll(t, a, filepath.Join(root, "1792563515376", opsName))
	var writes, execs []int64
	for _, e := range res.ToolEvents {
		switch e.RawToolName {
		case "write_to_file":
			writes = append(writes, e.DurationMs)
		case "execute_command":
			execs = append(execs, e.DurationMs)
		}
	}
	// write 1: card 518859->562263 minus approval 518861->562240 = 25 ms;
	// write 2: card 569687->574259 minus approval 569687->574249 = 10 ms.
	if len(writes) != 2 || writes[0] != 25 || writes[1] != 10 {
		t.Errorf("write durations = %v, want [25 10]", writes)
	}
	// execs: 567090->567185, 576663->576750, 580272->580353.
	if len(execs) != 3 || execs[0] != 95 || execs[1] != 87 || execs[2] != 81 {
		t.Errorf("exec durations = %v, want [95 87 81]", execs)
	}
	if got := res.SessionProcessSeeds; len(got) != 1 || got[0].PID != 116316 {
		t.Errorf("seeds = %+v", got)
	}
	for _, o := range res.ToolAccounts {
		if o.AccountID != linDistinct {
			t.Errorf("account = %q, want %s", o.AccountID, linDistinct)
		}
	}
}

// TestResumedTaskFixture: the real `-T` resume task (its ui log carries
// `reset` ops that re-list the presentation) parses to the same actions
// and a hook-cancelled resume prompt adds nothing to the api log.
func TestResumedTaskFixture(t *testing.T) {
	pinNativeHomes(t)
	root, _ := copyFixture(t, "linux")
	a := NewWithOptions(nil, root)
	res := parseAll(t, a, filepath.Join(root, "1792585271550", opsName))
	got := strings.Join(rawNames(res.ToolEvents), ",")
	want := "dirac.user_prompt/user_prompt,read_file/read_file,execute_command/run_command,edit_file/edit_file,respond.complete/task_complete"
	if got != want {
		t.Fatalf("actions:\n got %s\nwant %s", got, want)
	}
	for _, e := range res.ToolEvents {
		if e.RawToolName == "dirac.user_prompt" {
			continue
		}
		if e.RawToolName != "respond.complete" && e.DurationMs <= 0 {
			t.Errorf("%s has no duration (ui cards survived two ui resets)", e.RawToolName)
		}
	}
	if len(res.TokenEvents) != 4 {
		t.Fatalf("token rows = %d", len(res.TokenEvents))
	}
	for i, k := range res.TokenEvents {
		if k.GenMs <= 0 || k.GenMs > maxGenMs {
			t.Errorf("token %d GenMs = %d", i, k.GenMs)
		}
	}
	// the LAST process on the task is the `-T` resume run (pid 352173), not the first run (347638)
	if len(res.SessionProcessSeeds) != 1 || res.SessionProcessSeeds[0].PID != 352173 {
		t.Errorf("seeds = %+v", res.SessionProcessSeeds)
	}
}

// TestCancelledTaskStampsFromLog: a task cancelled by a prompt hook has an
// empty op log (one empty reset) and NO task_metadata.json. It still gets
// the surface from the log channel and emits no compaction row (an empty
// reset replaces an empty history).
func TestCancelledTaskStampsFromLog(t *testing.T) {
	pinNativeHomes(t)
	root, _ := copyFixture(t, "windows")
	a := NewWithOptions(nil, root)
	res := parseAll(t, a, filepath.Join(root, "1792584820846", opsName))
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("events = %d/%d, want none (no compaction on an empty reset)", len(res.ToolEvents), len(res.TokenEvents))
	}
	wantSurf := models.SessionSurface{SessionID: "1792584820846", Surface: models.SurfaceCLI, SurfaceHost: "dirac-cli"}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != wantSurf {
		t.Errorf("surfaces = %+v, want %+v", res.SessionSurfaces, wantSurf)
	}
	if len(res.SessionProcessSeeds) != 1 || res.SessionProcessSeeds[0].PID != 980 {
		t.Errorf("seeds = %+v", res.SessionProcessSeeds)
	}
}

// TestToolVersionFallsBackToInstalledPackage: with no environment record
// the version is the installed package of the process that ran the task
// (the log's Extension dir -> package.json).
func TestToolVersionFallsBackToInstalledPackage(t *testing.T) {
	pinNativeHomes(t)
	base := t.TempDir()
	data := filepath.Join(base, ".dirac", "data")
	ext := filepath.Join(base, "npm", "node_modules", "dirac-cli")
	for _, d := range []string{filepath.Join(data, "tasks", "1792500000000"), filepath.Join(data, "logs"), ext} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(ext, "package.json"), `{"name":"dirac-cli","version":"9.8.7"}`)
	extJSON := strings.ReplaceAll(ext, `\`, `\\`)
	write(filepath.Join(data, "logs", logFileName),
		`2026-10-21T06:00:00.000Z {"level":30,"pid":4242,"channel":"Dirac CLI","msg":"Dirac CLI initialized. Data dir: x, Extension dir: `+extJSON+`, Log dir: y"}`+"\n"+
			`2026-10-21T06:00:01.000Z {"level":30,"pid":4242,"channel":"Dirac CLI","msg":"INFO [Task 1792500000000] Using StandaloneTerminalManager for backgroundExec mode"}`+"\n")
	write(filepath.Join(data, "tasks", "1792500000000", opsName),
		jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": userMsg(1792500000100, text("<task>hi</task>"))}))
	a := NewWithOptions(nil, filepath.Join(data, "tasks"))
	res := parseAll(t, a, filepath.Join(data, "tasks", "1792500000000", opsName))
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "9.8.7" {
		t.Errorf("versions = %+v, want 9.8.7 from the package", res.SessionToolVersions)
	}
	// A package that is not dirac-cli is refused.
	write(filepath.Join(ext, "package.json"), `{"name":"something-else","version":"1.0.0"}`)
	if v := packageVersion(ext); v != "" {
		t.Errorf("packageVersion(foreign package) = %q, want empty", v)
	}
}

// TestForeignMountLogSkipsPidSeed: a pid read through a foreign-OS mount
// is the other OS's pid, so no seed is emitted (the stamps still are).
func TestForeignMountLogSkipsPidSeed(t *testing.T) {
	root, _ := copyFixture(t, "windows")
	old := allHomesFunc
	t.Cleanup(func() { allHomesFunc = old })
	home := filepath.Dir(filepath.Dir(filepath.Dir(root))) // the temp dir holding .dirac
	allHomesFunc = func() []crossmount.HomeRoot { return []crossmount.HomeRoot{{Path: home, Origin: "windows"}} }
	a := NewWithOptions(nil, root)
	res := parseAll(t, a, filepath.Join(root, "1792584662340", opsName))
	if len(res.SessionProcessSeeds) != 0 {
		t.Errorf("seeds = %+v, want none for a foreign-mount log", res.SessionProcessSeeds)
	}
	if len(res.SessionToolVersions) != 1 {
		t.Errorf("tool version still expected, got %+v", res.SessionToolVersions)
	}
}

// TestLogScanKeepsOnlyFactsAndLatestPid: only the four fact shapes are
// read; the LAST pid on a task's lines wins (a resume runs in a new
// process); unrelated lines (prompts, commands) are never kept.
func TestLogScanKeepsOnlyFactsAndLatestPid(t *testing.T) {
	snap := newLogSnapshot()
	lines := []string{
		`2026-10-21T06:00:00.000Z {"pid":10,"channel":"Dirac CLI","msg":"LOG [DistinctId] initialized: ` + winDistinct + `"}`,
		`2026-10-21T06:00:01.000Z {"pid":10,"channel":"Dirac CLI","msg":"INFO [Task 1792500000001] Using StandaloneTerminalManager"}`,
		`2026-10-21T06:00:02.000Z {"pid":10,"channel":"Dirac CLI","msg":"INFO Executing command in standalone terminal: echo SECRET-PROMPT"}`,
		`2026-10-21T07:00:00.000Z {"pid":20,"channel":"Dirac CLI","msg":"LOG [DistinctId] initialized: ` + linDistinct + `"}`,
		`2026-10-21T07:00:01.000Z {"pid":20,"channel":"Dirac CLI","msg":"INFO [Task 1792500000001] resumed"}`,
		`not json {`,
		`2026-10-21T07:00:02.000Z {"pid":0,"msg":"[Task 1792500000002] zero pid"}`,
	}
	for _, l := range lines {
		snap.scanLine(l)
	}
	if got := snap.pidFor("1792500000001"); got != 20 {
		t.Errorf("pid = %d, want the latest (20)", got)
	}
	if got := snap.accountFor("1792500000001"); got != linDistinct {
		t.Errorf("account = %q, want the id of pid 20", got)
	}
	if got := snap.pidFor("1792500000002"); got != 0 {
		t.Errorf("zero pid recorded as %d", got)
	}
	for _, v := range snap.pidDistinct {
		if strings.Contains(v, "SECRET") {
			t.Errorf("a message body leaked into the snapshot: %q", v)
		}
	}
	var nilSnap *logSnapshot
	if nilSnap.pidFor("x") != 0 || nilSnap.accountFor("x") != "" || nilSnap.versionFor("x") != "" || nilSnap.channelFor("x") != "" {
		t.Error("nil snapshot must answer empty")
	}
}

// TestLogTailCapDropsPartialLine: a log larger than the cap is read from
// its tail and the first (partial) line is discarded.
func TestLogTailCapDropsPartialLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, logFileName)
	old := `2026-10-21T00:00:00.000Z {"pid":1,"msg":"INFO [Task 1792500000009] old"}` + "\n"
	filler := strings.Repeat("x", 1<<20) + "\n"
	body := old + strings.Repeat(filler, 5) + `2026-10-21T09:00:00.000Z {"pid":77,"msg":"INFO [Task 1792500000008] tail"}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := scanLog(p, int64(len(body)))
	if snap == nil || snap.pidFor("1792500000008") != 77 {
		t.Fatalf("tail line lost: %+v", snap)
	}
	if snap.pidFor("1792500000009") != 0 {
		t.Error("a line before the tail window was read")
	}
}

// twoSessionOps builds an op log: 5 messages, an optional condense call,
// then a reset that keeps `keep` of them.
func resetOps(t *testing.T, condense bool, keep int) string {
	t.Helper()
	m1 := userMsg(1000, text("<task>go</task>"))
	m2 := asstMsg("r1", 2000, "anthropic", 10, 5, 0, toolUse("t1", "read_file", map[string]any{"paths": []string{"a"}}))
	m3 := userMsg(3000, toolResult("t1", "x"))
	var last map[string]any
	var ops string
	ops += jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": m1})
	ops += jsonLine(t, map[string]any{"offset": 1, "type": "append_message", "message": m2})
	ops += jsonLine(t, map[string]any{"offset": 2, "type": "append_message", "message": m3})
	off := 3
	if condense {
		last = asstMsg("r2", 4000, "anthropic", 10, 5, 0, toolUse("t2", "condense", map[string]any{"context": "summary"}))
		ops += jsonLine(t, map[string]any{"offset": off, "type": "append_message", "message": last})
		off++
		ops += jsonLine(t, map[string]any{"offset": off, "type": "append_message", "message": userMsg(5000, toolResult("t2", "ok"))})
		off++
	}
	all := []any{m1, m2, m3}
	ops += jsonLine(t, map[string]any{"offset": off, "type": "reset", "messages": all[:keep]})
	return ops
}

func compactedRows(res adapter.ParseResult) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.RawToolName == models.ToolDirac+".history_reset" {
			out = append(out, e)
		}
	}
	return out
}

// TestResetCompaction: a reset that SHRINKS the history is a
// context_compacted row (content-derived id from the op offset); an
// explicit condense call owns its reset (no second row); a mid-file
// resume derives the prior count from the consumed prefix.
func TestResetCompaction(t *testing.T) {
	pinNativeHomes(t)
	t.Run("shrinking reset emits one row", func(t *testing.T) {
		root, path := writeTask(t, map[string]string{opsName: resetOps(t, false, 1)})
		res := parseAll(t, NewWithOptions(nil, root), path)
		rows := compactedRows(res)
		if len(rows) != 1 {
			t.Fatalf("history_reset rows = %d, want 1", len(rows))
		}
		r := rows[0]
		if r.ActionType != models.ActionContextCompacted || r.SourceEventID != "reset:op3" || r.Target != "1 msgs (was 3)" || !r.Success {
			t.Errorf("row = %+v", r)
		}
		if r.Timestamp.UnixMilli() != 3000 {
			t.Errorf("row ts = %d, want the newest message ts 3000", r.Timestamp.UnixMilli())
		}
		again := parseAll(t, NewWithOptions(nil, root), path)
		if compactedRows(again)[0].SourceEventID != r.SourceEventID {
			t.Error("id is not stable across parses")
		}
	})
	t.Run("non-shrinking reset emits none", func(t *testing.T) {
		root, path := writeTask(t, map[string]string{opsName: resetOps(t, false, 3)})
		if rows := compactedRows(parseAll(t, NewWithOptions(nil, root), path)); len(rows) != 0 {
			t.Errorf("rows = %v, want none", rows)
		}
	})
	t.Run("condense call owns its reset", func(t *testing.T) {
		root, path := writeTask(t, map[string]string{opsName: resetOps(t, true, 2)})
		res := parseAll(t, NewWithOptions(nil, root), path)
		if rows := compactedRows(res); len(rows) != 0 {
			t.Errorf("history_reset rows = %d, want 0 (the condense tool row is the event)", len(rows))
		}
		n := 0
		for _, e := range res.ToolEvents {
			if e.RawToolName == "condense" && e.ActionType == models.ActionContextCompacted {
				n++
			}
		}
		if n != 1 {
			t.Errorf("condense rows = %d, want 1", n)
		}
	})
	t.Run("mid-file resume counts the consumed prefix", func(t *testing.T) {
		ops := resetOps(t, false, 1)
		lines := strings.SplitAfter(ops, "\n")
		prefix := lines[0] + lines[1] + lines[2]
		root, path := writeTask(t, map[string]string{opsName: ops})
		a := NewWithOptions(nil, root)
		res, err := a.ParseSessionFile(context.Background(), path, int64(len(prefix)))
		if err != nil {
			t.Fatal(err)
		}
		rows := compactedRows(res)
		if len(rows) != 1 || rows[0].Target != "1 msgs (was 3)" {
			t.Errorf("rows = %+v, want one (was 3) from the consumed prefix", rows)
		}
	})
}

// TestPickPrefersLatestStartBeforePersist: two requests with identical
// counts are not swapped; the one begun last before the response wins.
func TestPickPrefersLatestStartBeforePersist(t *testing.T) {
	mk := func(start int64) *uiStatus {
		return &uiStatus{TokensIn: i64(10), TokensOut: i64(5), CacheReads: i64(0), CacheWrites: i64(0), startMs: start}
	}
	d := &uiData{statuses: []*uiStatus{mk(1000), mk(5000), mk(9000)}}
	m := rawMetricTokens{Prompt: 10, Completion: 5}
	if s, idx := d.pick(m, 6000, 0); s == nil || s.startMs != 5000 || idx != 1 {
		t.Errorf("pick(ts=6000) = %+v idx %d, want start 5000", s, idx)
	}
	if s, idx := d.pick(m, 9500, 0); s == nil || s.startMs != 9000 || idx != 2 {
		t.Errorf("pick(ts=9500) = %+v idx %d, want start 9000", s, idx)
	}
	// Nothing started before the response: fall back to the first match.
	if s, idx := d.pick(m, 500, 0); s == nil || s.startMs != 1000 || idx != 0 {
		t.Errorf("pick(ts=500) = %+v idx %d, want the first match", s, idx)
	}
	if s, _ := d.pick(rawMetricTokens{Prompt: 99}, 6000, 0); s != nil {
		t.Errorf("pick(no equal counts) = %+v, want nil", s)
	}
}

// TestToolDurationRules: ambiguity and unfinished cards never produce a
// duration; a multi-command call sums its cards.
func TestToolDurationRules(t *testing.T) {
	st := &uiStatus{startMs: 1000}
	next := int64(5000)
	d := &uiData{
		starts: []int64{1000, next},
		cards: []*uiCard{
			{toolName: "execute_command", status: "success", start: 1100, end: 1150},
			{toolName: "execute_command", status: "success", start: 1200, end: 1230},
			{toolName: "execute_command", status: "success", start: 6000, end: 6500}, // a later request
			{toolName: "read_file", status: "running", start: 1300},
		},
	}
	if ms, ok := d.toolDuration(st, "execute_command"); !ok || ms != 80 {
		t.Errorf("two commands = %d,%v, want 80,true (later request excluded)", ms, ok)
	}
	if _, ok := d.toolDuration(st, "read_file"); ok {
		t.Error("an unfinished card must not yield a duration")
	}
	if _, ok := d.toolDuration(st, "edit_file"); ok {
		t.Error("no card, no duration")
	}
	if _, ok := d.toolDuration(nil, "execute_command"); ok {
		t.Error("nil status, no duration")
	}
}

// TestDeniedAndCostAndMode: a user denial stamps the approval kind, a
// reported per-request cost is carried, and the plan/act mode rides on
// every assistant row.
func TestDeniedAndCostAndMode(t *testing.T) {
	pinNativeHomes(t)
	m1 := userMsg(1000, text("<task>do</task>"))
	m2 := asstMsg("r1", 2000, "anthropic", 10, 5, 0, toolUse("t1", "execute_command", map[string]any{"commands": []string{"rm x"}}))
	m2["modelInfo"] = map[string]any{"modelId": "claude-sonnet-4-6", "providerId": "anthropic", "mode": "plan"}
	m2["metrics"] = map[string]any{"tokens": map[string]any{"prompt": 10, "completion": 5, "cached": 0}, "cost": 0.0123}
	m3 := userMsg(3000, toolResult("t1", "The user denied this operation."))
	ops := jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": m1}) +
		jsonLine(t, map[string]any{"offset": 1, "type": "append_message", "message": m2}) +
		jsonLine(t, map[string]any{"offset": 2, "type": "append_message", "message": m3})
	root, path := writeTask(t, map[string]string{opsName: ops})
	res := parseAll(t, NewWithOptions(nil, root), path)
	var cmd models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.RawToolName == "execute_command" {
			cmd = e
		}
	}
	if cmd.Success || cmd.Metadata == nil || cmd.Metadata.PermissionApprovalKind != "denied" || cmd.Metadata.CollaborationMode != "plan" {
		t.Errorf("denied command = success %v meta %+v, want denied in plan mode", cmd.Success, cmd.Metadata)
	}
	if len(res.TokenEvents) != 1 || res.TokenEvents[0].EstimatedCostUSD != 0.0123 {
		t.Errorf("token cost = %+v, want 0.0123 carried", res.TokenEvents)
	}
	if res.TokenEvents[0].GenMs != 0 {
		t.Errorf("GenMs = %d without a ui log, want 0", res.TokenEvents[0].GenMs)
	}
}

// TestReadTranscript folds the real probe task through the handoff
// reader: the wrapped prompt (not <environment_details>), calls paired
// with their results, the respond voice as assistant text, no thinking.
func TestReadTranscript(t *testing.T) {
	pinNativeHomes(t)
	root, _ := copyFixture(t, "windows")
	a := NewWithOptions(nil, root)
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "1792584662340"}, nil)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("messages = %d", len(msgs))
	}
	if msgs[0].Role != models.TranscriptUser || !strings.HasPrefix(msgs[0].Text, "Do exactly these three steps") {
		t.Errorf("msg0 = %+v", msgs[0])
	}
	if strings.Contains(msgs[0].Text, "environment_details") {
		t.Error("environment_details leaked into the prompt")
	}
	var calls, resolved int
	var names []string
	var lastText string
	for _, m := range msgs {
		for _, c := range m.ToolCalls {
			calls++
			names = append(names, c.Name)
			if c.Resolved {
				resolved++
			}
		}
		if m.Role == models.TranscriptAssistant && m.Text != "" {
			lastText = m.Text
		}
		if m.Role == models.TranscriptAssistant && m.Model != "gpt-6-luna" {
			t.Errorf("assistant model = %q", m.Model)
		}
	}
	if calls != 3 || resolved != 3 || strings.Join(names, ",") != "read_file,execute_command,edit_file" {
		t.Errorf("calls=%d resolved=%d names=%v, want the 3 tool calls paired (respond is text)", calls, resolved, names)
	}
	if !strings.Contains(lastText, "gamma line") {
		t.Errorf("respond text not rendered as assistant text: %q", lastText)
	}
	// A hint naming the live log wins; an unknown session errors.
	hint := filepath.Join(root, "1792584662340", opsName)
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "nope"}, []string{hint}); err != nil {
		t.Errorf("hint not honoured: %v", err)
	}
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "nope"}, nil); err == nil {
		t.Error("unknown session must error")
	}
}

// TestReadTranscriptReplaysArchivesResetAndUserContent: archives then the
// live log, a reset replaces the history, an append_user_content block
// joins the trailing user message.
func TestReadTranscriptReplaysArchivesResetAndUserContent(t *testing.T) {
	pinNativeHomes(t)
	m1 := userMsg(1000, text("<task>first</task>"))
	m2 := asstMsg("r1", 2000, "anthropic", 1, 1, 0, text("ack"))
	m3 := userMsg(3000, text("<feedback>second</feedback>"))
	archive := jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": m1}) +
		jsonLine(t, map[string]any{"offset": 1, "type": "append_message", "message": m2})
	live := jsonLine(t, map[string]any{"offset": 2, "type": "append_message", "message": m3}) +
		jsonLine(t, map[string]any{"offset": 3, "type": "append_user_content", "content": text("<user_message>third</user_message>")})
	root, path := writeTask(t, map[string]string{archivePrefix + "1": archive, opsName: live})
	a := NewWithOptions(nil, root)
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "100"}, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, m := range msgs {
		texts = append(texts, string(m.Role)+":"+m.Text)
	}
	got := strings.Join(texts, "|")
	if !strings.Contains(got, "user:first") || !strings.Contains(got, "assistant:ack") || !strings.Contains(got, "second") {
		t.Errorf("replayed transcript = %s", got)
	}
	// reset replaces everything before it.
	live2 := live + jsonLine(t, map[string]any{"offset": 4, "type": "reset", "messages": []any{m3}})
	if err := os.WriteFile(path, []byte(live2), 0o644); err != nil {
		t.Fatal(err)
	}
	msgs, err = a.ReadTranscript(context.Background(), models.Session{ID: "100"}, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(m.Text, "first") || strings.Contains(m.Text, "ack") {
			t.Errorf("pre-reset history survived the reset: %+v", m)
		}
	}
}

// The handoff reader contract (internal/handoffsvc.TranscriptReader)
// is satisfied; asserted here without importing the service package.
var _ interface {
	ReadTranscript(context.Context, models.Session, []string) ([]models.TranscriptMessage, error)
} = (*Adapter)(nil)
