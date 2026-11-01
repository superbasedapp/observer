package cortexcode

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

// probeSID is the anonymized WSL hook-probe session (real, 2026-10-21):
// two hook-blocked bash calls (status "error"), a hook-injected context
// block and a hook-rewritten command.
const probeSID = "5c4b3a29-1807-4f6e-8d5c-4b3a29180706"

// stageDataHome copies the fixture conversations of osDir plus its
// anonymized logs/coco.log into a fresh data home and returns the
// conversations directory.
func stageDataHome(t *testing.T, osDir string, sids ...string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, conversationsDir)
	for _, sid := range sids {
		for _, name := range []string{sid + historySuffix, sid + metaSuffix} {
			data, err := os.ReadFile(fixturePath(osDir, "conversations", name)) //nolint:gosec // test fixture
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			writeFile(t, filepath.Join(dir, name), string(data))
		}
	}
	data, err := os.ReadFile(fixturePath(osDir, logDir, logFile)) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, logDir, logFile), string(data))
	return dir
}

// noForeignHomes makes isForeignMountPath see only the native home.
func noForeignHomes(t *testing.T) {
	t.Helper()
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return nil }
	t.Cleanup(func() { allHomesFunc = orig })
}

func TestLogStampsFromFixtures(t *testing.T) {
	noForeignHomes(t)
	cases := []struct {
		osDir, sid string
	}{
		{"wsl", wslSID},
		{"wsl", probeSID},
		{"windows", winSID},
		{"windows", winToolSID},
	}
	for _, tc := range cases {
		t.Run(tc.osDir+"/"+tc.sid[:8], func(t *testing.T) {
			dir := stageDataHome(t, tc.osDir, tc.sid)
			a := NewWithOptions(nil, dir)
			for _, path := range []string{filepath.Join(dir, tc.sid+metaSuffix), filepath.Join(dir, tc.sid+historySuffix)} {
				res := parse(t, a, path, 0)
				if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0] != (models.SessionToolVersion{SessionID: tc.sid, Version: "1.2.18"}) {
					t.Errorf("%s versions = %+v", filepath.Base(path), res.SessionToolVersions)
				}
				if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != (models.SessionSurface{SessionID: tc.sid, Surface: models.SurfaceCLI}) {
					t.Errorf("%s surfaces = %+v", filepath.Base(path), res.SessionSurfaces)
				}
				// Every fixture run logged its exit cleanup: no live pid.
				if len(res.SessionProcessSeeds) != 0 {
					t.Errorf("%s seeds = %+v, want none for an exited run", filepath.Base(path), res.SessionProcessSeeds)
				}
			}
		})
	}
}

func TestLogSeedsLiveRunOnly(t *testing.T) {
	noForeignHomes(t)
	dir := stageDataHome(t, "wsl", probeSID)
	logPath := filepath.Join(filepath.Dir(dir), logDir, logFile)
	// SYNTHETIC: a later run of the same session that has not exited
	// (the session was resumed in pid 4242).
	appendLog(t, logPath,
		`{"ts":"2026-10-21T13:00:00.000Z","level":"INFO","logger":"coco.init","session_id":null,"request_id":null,"pid":4242,"msg":"=== Cortex Code logging initialized ===","terminal_launcher_source":"cli"}`,
		`{"ts":"2026-10-21T13:00:01.000Z","level":"INFO","logger":"coco.utils.bundle","session_id":null,"request_id":null,"pid":4242,"msg":"Found bundled resource at: /home/user/.local/share/cortex/1.3.0+1.abc/bundled_skills","terminal_launcher_source":"cli"}`,
		`{"ts":"2026-10-21T13:00:02.000Z","level":"INFO","logger":"coco.main","session_id":"`+probeSID+`","request_id":null,"pid":4242,"msg":"x","terminal_launcher_source":"cli"}`,
	)
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, probeSID+metaSuffix), 0)
	want := models.SessionProcessSeed{PID: 4242, SessionID: probeSID, Tool: models.ToolCortexCode, CWD: "/home/user/project", ExecHint: "cortex"}
	if len(res.SessionProcessSeeds) != 1 || res.SessionProcessSeeds[0] != want {
		t.Fatalf("seeds = %+v, want %+v", res.SessionProcessSeeds, want)
	}
	// Both builds, origin first (the store keeps the first, moves "last").
	if len(res.SessionToolVersions) != 2 || res.SessionToolVersions[0].Version != "1.2.18" || res.SessionToolVersions[1].Version != "1.3.0" {
		t.Fatalf("versions = %+v", res.SessionToolVersions)
	}
}

func TestLogSeedsSkippedOnForeignMount(t *testing.T) {
	dir := stageDataHome(t, "wsl", probeSID)
	logPath := filepath.Join(filepath.Dir(dir), logDir, logFile)
	appendLog(t, logPath,
		`{"ts":"2026-10-21T13:00:00.000Z","level":"INFO","logger":"coco.main","session_id":"`+probeSID+`","request_id":null,"pid":4242,"msg":"x","terminal_launcher_source":"cli"}`)
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: filepath.Dir(filepath.Dir(dir)), Origin: "wsl-windows"}}
	}
	t.Cleanup(func() { allHomesFunc = orig })
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, probeSID+metaSuffix), 0)
	if len(res.SessionProcessSeeds) != 0 {
		t.Fatalf("seeds = %+v, want none for a foreign-OS log", res.SessionProcessSeeds)
	}
	if len(res.SessionToolVersions) == 0 || len(res.SessionSurfaces) == 0 {
		t.Fatalf("version/surface must still stamp across a mount: %+v %+v", res.SessionToolVersions, res.SessionSurfaces)
	}
}

func appendLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLogNeverKeepsMessageText(t *testing.T) {
	// SYNTHETIC: free-text messages that carry prompt excerpts must not
	// influence the index; only the allow-listed prefixes do.
	body := strings.Join([]string{
		`{"ts":"t1","logger":"coco.main","session_id":"s1","pid":7,"msg":"Initial message: \"SECRET-PROMPT /home/x/cortex/9.9.9/\"","terminal_launcher_source":"cli"}`,
		`{"ts":"t2","logger":"coco.image","session_id":"s1","pid":7,"msg":"Found bundled resource at: /a/cortex/8.8.8/x","terminal_launcher_source":"cli"}`,
		`{"ts":"t3","logger":"coco.main","session_id":"s1","pid":7,"msg":"Print query: Desktop sidecar mode: true","terminal_launcher_source":"cli"}`,
		`not json at all`,
		`{"ts":"t4","logger":"coco.main","session_id":"../evil","pid":7,"msg":"x","terminal_launcher_source":"cli"}`,
	}, "\n") + "\n"
	idx := parseLog(strings.NewReader(body), false)
	if len(idx.runs) != 1 {
		t.Fatalf("runs = %d", len(idx.runs))
	}
	r := idx.runs[0]
	if r.version != "" || r.desktop || r.exited || r.acp || len(r.sessions) != 1 || r.sessions[0] != "s1" {
		t.Fatalf("run = %+v", r)
	}
}

func TestLogRunBoundariesSplitRecycledPid(t *testing.T) {
	body := strings.Join([]string{
		`{"ts":"t1","logger":"coco.init","session_id":null,"pid":9,"msg":"=== Cortex Code logging initialized ===","terminal_launcher_source":"cli"}`,
		`{"ts":"t2","logger":"coco.main","session_id":"old","pid":9,"msg":"x","terminal_launcher_source":"cli"}`,
		`{"ts":"t3","logger":"coco.init","session_id":null,"pid":9,"msg":"=== Cortex Code logging initialized ===","terminal_launcher_source":"vscode"}`,
		`{"ts":"t4","logger":"coco.acp.server","session_id":"new","pid":9,"msg":"x","terminal_launcher_source":"vscode"}`,
	}, "\n") + "\n"
	idx := parseLog(strings.NewReader(body), false)
	if len(idx.runs) != 2 || idx.runs[0].sessions[0] != "old" || idx.runs[1].sessions[0] != "new" || !idx.runs[1].acp {
		t.Fatalf("runs = %+v %+v", idx.runs[0], idx.runs[1])
	}
	// The first line of a mid-file tail is a partial record: skipped.
	tail := parseLog(strings.NewReader(`d":"x"}`+"\n"+`{"ts":"t9","logger":"coco.main","session_id":"z","pid":3,"msg":"x"}`+"\n"), true)
	if len(tail.runs) != 1 || tail.runs[0].sessions[0] != "z" {
		t.Fatalf("tail runs = %+v", tail.runs)
	}
}

func TestVersionFromInstallPath(t *testing.T) {
	cases := map[string]string{
		`C:\Users\user\AppData\Local\cortex\1.2.18+192728.aa2238062732\bundled_skills`: "1.2.18",
		`/home/user/.local/share/cortex/1.2.18+192728.aa2238062732/bundled_plugins`:    "1.2.18",
		`/opt/cortex/2.0.0-beta.1/x`:          "2.0.0-beta.1",
		`/home/user/.snowflake/cortex/skills`: "",
		`/srv/other/1.2.3/x`:                  "",
		``:                                    "",
	}
	for in, want := range cases {
		if got := versionFromInstallPath(in); got != want {
			t.Errorf("versionFromInstallPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSurfaceRules(t *testing.T) {
	cases := []struct {
		name string
		run  logRun
		want models.SessionSurface
		ok   bool
	}{
		{"cli", logRun{launcher: "cli"}, models.SessionSurface{Surface: models.SurfaceCLI}, true},
		{"vscode", logRun{launcher: "vscode"}, models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}, true},
		{"desktop source", logRun{launcher: "desktop"}, models.SessionSurface{Surface: models.SurfaceDesktop}, true},
		{"desktop sidecar", logRun{launcher: "cli", desktop: true}, models.SessionSurface{Surface: models.SurfaceDesktop}, true},
		{"acp vscode", logRun{launcher: "vscode", acp: true}, models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}, true},
		{"acp other editor", logRun{launcher: "cli", acp: true}, models.SessionSurface{Surface: models.SurfaceIDE}, true},
		{"sandbox", logRun{launcher: "sandbox"}, models.SessionSurface{}, false},
		{"none", logRun{}, models.SessionSurface{}, false},
	}
	for _, tc := range cases {
		got, ok := surfaceOf(&tc.run)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: surfaceOf = %+v,%v want %+v,%v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestInstallVersionFallback(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".snowflake", "cortex", conversationsDir)
	writeFile(t, filepath.Join(dir, wslSID+metaSuffix), `{"session_id":"`+wslSID+`"}`)
	writeFile(t, filepath.Join(home, ".local", "share", "cortex", "1.2.9+1.a", "cortex-version.txt"), "1.2.9+1.a\n")
	writeFile(t, filepath.Join(home, ".local", "share", "cortex", "1.2.18+192728.aa2238062732", "cortex-version.txt"), "1.2.18+192728.aa2238062732\n")
	writeFile(t, filepath.Join(home, "AppData", "Local", "cortex", "bin", "cortex.cmd"), "@echo off\n")
	writeFile(t, filepath.Join(home, "AppData", "Local", "cortex", "junk", "cortex-version.txt"), "not a version")
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, wslSID+metaSuffix), 0)
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "1.2.18" {
		t.Fatalf("versions = %+v, want the highest install-level 1.2.18", res.SessionToolVersions)
	}
	// No surface without log evidence.
	if len(res.SessionSurfaces) != 0 || len(res.SessionProcessSeeds) != 0 {
		t.Fatalf("surfaces=%+v seeds=%+v, want none without a log", res.SessionSurfaces, res.SessionProcessSeeds)
	}
	// A data home outside its default place has no install fallback.
	if v := installVersion(filepath.Join(home, "custom-home")); v != "" {
		t.Fatalf("installVersion(custom) = %q", v)
	}
}

func TestAccountObservations(t *testing.T) {
	dir := stageFixture(t, "wsl", wslSID)
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, wslSID+historySuffix), 0)
	if len(res.ToolAccounts) == 0 {
		t.Fatal("no account observations")
	}
	msgIDs := map[string]bool{}
	for _, ev := range res.ToolEvents {
		if ev.MessageID != "" {
			msgIDs[ev.MessageID] = true
		}
	}
	seen := map[string]bool{}
	roles := map[string]int{}
	for _, o := range res.ToolAccounts {
		norm, key, ok := toolaccount.Normalize(o)
		if !ok || key == "" {
			t.Fatalf("observation rejected by Normalize: %+v", o)
		}
		if !models.ToolAccountScopeIsAccountLevel(norm.Scope) || norm.Email != "" || norm.Name != "" ||
			norm.AccountID != "example.snowflakecomputing.com" || norm.BindingKind != "message" || norm.Stage != "activity" {
			t.Errorf("observation = %+v", norm)
		}
		if !msgIDs[o.BindingID] {
			t.Errorf("binding %q matches no emitted message id", o.BindingID)
		}
		k := o.Role + "|" + o.BindingID
		if seen[k] {
			t.Errorf("duplicate observation %s", k)
		}
		seen[k] = true
		roles[o.Role]++
	}
	if roles["user"] == 0 || roles["assistant"] == 0 {
		t.Errorf("roles = %v, want both", roles)
	}

	// No account host -> no observation.
	dir2 := filepath.Join(t.TempDir(), conversationsDir)
	writeFile(t, filepath.Join(dir2, "s1"+historySuffix),
		`{"role":"user","id":"m1","content":[{"type":"text","text":"hi","is_user_prompt":true,"message_id":"m1"}],"user_sent_time":"2026-10-21T04:05:35.144Z"}`+"\n")
	writeFile(t, filepath.Join(dir2, "s1"+metaSuffix), `{"session_id":"s1"}`)
	if r := parse(t, NewWithOptions(nil, dir2), filepath.Join(dir2, "s1"+historySuffix), 0); len(r.ToolAccounts) != 0 {
		t.Fatalf("observations without a host = %+v", r.ToolAccounts)
	}
}

func TestProbeFixtureOutcomes(t *testing.T) {
	dir := stageFixture(t, "wsl", probeSID)
	res := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, probeSID+historySuffix), 0)
	var failed, ok int
	for _, ev := range res.ToolEvents {
		if ev.ActionType != models.ActionRunCommand {
			if ev.ActionType == models.ActionUserPrompt && strings.Contains(ev.Target, "PROBE-CONTEXT") {
				t.Errorf("hook-injected context emitted as a prompt")
			}
			continue
		}
		switch {
		case !ev.Success && strings.Contains(ev.ErrorMessage, "Blocked"):
			failed++
		case ev.Success && ev.DurationMs == 20:
			ok++
		default:
			t.Errorf("bash event = %+v", ev)
		}
	}
	if failed != 2 || ok != 1 {
		t.Fatalf("failed=%d ok=%d, want 2 hook-blocked + 1 success", failed, ok)
	}
}

func TestReadTranscript(t *testing.T) {
	dir := stageFixture(t, "windows", winSID)
	a := NewWithOptions(nil, dir)
	ctx := context.Background()
	msgs, err := a.ReadTranscript(ctx, models.Session{ID: winSID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var users, asst, calls, resolved int
	for i, m := range msgs {
		if m.Index != i {
			t.Errorf("index %d = %d", i, m.Index)
		}
		if strings.Contains(m.Text, "system-reminder") || strings.Contains(m.Text, "Request interrupted") {
			t.Errorf("harness text leaked into transcript: %q", m.Text)
		}
		if m.ID == "" {
			t.Errorf("message %d has no source id", i)
		}
		switch m.Role {
		case models.TranscriptUser:
			users++
		case models.TranscriptAssistant:
			asst++
			if m.Model == "" {
				t.Errorf("assistant %d has no model", i)
			}
			for _, c := range m.ToolCalls {
				calls++
				if c.Resolved {
					resolved++
				}
			}
		}
	}
	if users != 2 || asst < 2 || calls != 2 || resolved != 2 {
		t.Fatalf("users=%d assistant=%d calls=%d resolved=%d (msgs=%+v)", users, asst, calls, resolved, msgs)
	}
	full, err := a.ReadTranscriptFull(ctx, models.Session{ID: winSID}, nil)
	if err != nil || len(full) != len(msgs) {
		t.Fatalf("full = %d msgs, err %v; capped = %d", len(full), err, len(msgs))
	}
	// A metadata-file hint resolves its history sibling.
	hinted, err := NewWithOptions(nil, t.TempDir()).ReadTranscript(ctx, models.Session{ID: winSID}, []string{filepath.Join(dir, winSID+metaSuffix)})
	if err != nil || len(hinted) != len(msgs) {
		t.Fatalf("hinted = %d msgs, err %v", len(hinted), err)
	}
	if _, err := a.ReadTranscript(ctx, models.Session{ID: "missing"}, nil); err == nil {
		t.Fatal("missing session: want an error")
	}
	if _, err := a.ReadTranscript(ctx, models.Session{ID: "../" + winSID}, nil); err == nil {
		t.Fatal("path-shaped id: want an error")
	}
}

func TestReadTranscriptProbeFixture(t *testing.T) {
	dir := stageFixture(t, "wsl", probeSID)
	msgs, err := NewWithOptions(nil, dir).ReadTranscriptFull(context.Background(), models.Session{ID: probeSID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var users, calls int
	for _, m := range msgs {
		if m.Role == models.TranscriptUser {
			users++
			if strings.Contains(m.Text, "PROBE-CONTEXT") {
				t.Errorf("internalOnly hook context surfaced as a user message")
			}
		}
		for _, c := range m.ToolCalls {
			calls++
			if !c.Resolved || c.ResultExcerpt == "" {
				t.Errorf("call %s unresolved: %+v", c.ID, c)
			}
		}
	}
	if users != 3 || calls != 3 {
		t.Fatalf("users=%d calls=%d, want 3/3", users, calls)
	}
}

func TestResolveTerminalSession(t *testing.T) {
	noForeignHomes(t)
	ctx := context.Background()
	boundary := func(pid string) string {
		return `{"ts":"T` + pid + `","logger":"coco.init","session_id":null,"pid":` + pid + `,"msg":"=== Cortex Code logging initialized ===","terminal_launcher_source":"cli"}`
	}
	line := func(pid, sid string) string {
		return `{"ts":"t","logger":"coco.main","session_id":"` + sid + `","pid":` + pid + `,"msg":"x","terminal_launcher_source":"cli"}`
	}
	exit := func(pid, sid string) string {
		return `{"ts":"t","logger":"coco.app-exit-manager","session_id":"` + sid + `","pid":` + pid + `,"msg":"Starting app exit cleanup (reason: command)","terminal_launcher_source":"cli"}`
	}
	cases := []struct {
		name    string
		lines   []string
		metas   map[string]string
		pid     int
		wantSID string
	}{
		{
			"live run",
			[]string{boundary("50"), line("50", "hookid"), line("50", "s-main")},
			map[string]string{"s-main": `{"session_type":"main"}`},
			50, "s-main",
		},
		{
			"exited run",
			[]string{boundary("50"), line("50", "s-main"), exit("50", "s-main")},
			map[string]string{"s-main": `{}`},
			50, "",
		},
		{
			"two sessions with files",
			[]string{boundary("50"), line("50", "s-a"), line("50", "s-b")},
			map[string]string{"s-a": `{}`, "s-b": `{}`},
			50, "",
		},
		{
			"subagent ignored",
			[]string{boundary("50"), line("50", "s-main"), line("50", "s-sub")},
			map[string]string{"s-main": `{}`, "s-sub": `{"session_type":"subagent"}`},
			50, "s-main",
		},
		{
			"recycled pid new run without session",
			[]string{boundary("50"), line("50", "s-old"), boundary("50")},
			map[string]string{"s-old": `{}`},
			50, "",
		},
		{
			"unknown pid",
			[]string{boundary("50"), line("50", "s-main")},
			map[string]string{"s-main": `{}`},
			51, "",
		},
		{
			"pid one",
			[]string{boundary("1"), line("1", "s-main")},
			map[string]string{"s-main": `{}`},
			1, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, conversationsDir)
			for sid, body := range tc.metas {
				writeFile(t, filepath.Join(dir, sid+metaSuffix), body)
			}
			writeFile(t, filepath.Join(home, logDir, logFile), strings.Join(tc.lines, "\n")+"\n")
			got, err := NewWithOptions(nil, dir).ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: tc.pid})
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != tc.wantSID {
				t.Fatalf("SessionID = %q, want %q", got.SessionID, tc.wantSID)
			}
			if tc.wantSID != "" && !strings.Contains(got.Evidence, "#pid=50@T50") {
				t.Fatalf("Evidence = %q", got.Evidence)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := New().ResolveTerminalSession(cancelled, adapter.TerminalProcess{PID: 50}); err == nil {
		t.Fatal("cancelled context: want an error")
	}
}

// Compile-time capability pins.
var (
	_ adapter.TerminalSessionResolver = (*Adapter)(nil)
	_ interface {
		ReadTranscript(context.Context, models.Session, []string) ([]models.TranscriptMessage, error)
		ReadTranscriptFull(context.Context, models.Session, []string) ([]models.TranscriptMessage, error)
	} = (*Adapter)(nil)
)
