package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestResolveClaudeExecution pins the entrypoint -> execution-location
// table (cloud-agents lane CA-B4). Only the two cloud entrypoints grounded
// live on 2026-10-31 stamp a location; every local client stamps nothing
// (an unstamped session is the honest unknown, never a defaulted "local").
func TestResolveClaudeExecution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		entrypoint string
		want       string
		wantOK     bool
	}{
		{"remote_desktop", models.ExecutionVendorCloud, true},
		{"remote", models.ExecutionVendorCloud, true},
		{"remote_mobile", models.ExecutionVendorCloud, true},
		{"cli", "", false},
		{"claude-desktop", "", false},
		{"claude-vscode", "", false},
		{"claude-jetbrains", "", false},
		{"sdk-ts", "", false},
		{"sdk-cli", "", false},
		{"remote-web", "", false}, // unobserved spelling: no guess
		{"", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.entrypoint, func(t *testing.T) {
			t.Parallel()
			got, ok := resolveClaudeExecution(tc.entrypoint)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("resolveClaudeExecution(%q) = (%q, %v); want (%q, %v)", tc.entrypoint, got, ok, tc.want, tc.wantOK)
			}
		})
	}
	// Every row is a known location, so the store's strict writer never
	// refuses what this table emits.
	for ep, loc := range claudeEntrypointExecution {
		if !models.KnownExecutionLocation(loc) {
			t.Errorf("entrypoint %q maps to unknown location %q", ep, loc)
		}
		if _, _, ok := resolveClaudeSurface(ep); !ok {
			t.Errorf("cloud entrypoint %q has no surface row", ep)
		}
	}
}

// signalAdapter returns an adapter whose CA-D20 second signals read env
// (never the test process's own environment, which in a cloud CI session
// carries the very marker under test) and the real filesystem.
func signalAdapter(env map[string]string) *Adapter {
	a := New()
	a.lookupEnv = func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
	return a
}

// cloudLayout copies a cloud fixture into the A2 VM layout
// (projects/<slug>/<session>.jsonl plus <session>/ccr-tip.json) and returns
// the transcript path.
func cloudLayout(t *testing.T, file, sessionID string, withTip bool) string {
	t.Helper()
	src, err := os.ReadFile(fixturePath(t, filepath.Join("cloud", file)))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "projects", "-home-user-example-repo")
	if err := os.MkdirAll(filepath.Join(dir, sessionID), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sessionID+".jsonl")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if withTip {
		if err := os.WriteFile(filepath.Join(dir, sessionID, "ccr-tip.json"), []byte(`{"eventId":"e","updatedAt":"2026-10-31T10:00:00Z"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestCloudSecondSignalTable pins decision CA-D20: a cloud entrypoint alone
// stamps nothing; the hook rail's marker in the scanning process or the
// cloud VM layout confirms it; the vendor reference rides only with the
// VM's own session id.
func TestCloudSecondSignalTable(t *testing.T) {
	t.Parallel()
	const sid = "40b6413f-7a79-504b-8be9-87a38ca950cb" // remote_desktop.jsonl's session
	const ref = "cse_0123456789abcdefABCDEFGH"
	marker := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": ref, "CLAUDE_CODE_SESSION_ID": sid}
	other := map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": ref, "CLAUDE_CODE_SESSION_ID": "someone-else"}
	tests := []struct {
		name    string
		env     map[string]string
		tip     bool
		want    bool
		wantRef string
	}{
		{"entrypoint alone (a teleported copy) stamps nothing", nil, false, false, ""},
		{"a wrong marker value stamps nothing", map[string]string{"CLAUDE_CODE_REMOTE": "false"}, false, false, ""},
		{"hook rail agreement, the VM's own session", marker, false, true, ref},
		{"hook rail agreement, another transcript in the VM", other, false, true, ""},
		{"cloud VM layout (ccr-tip.json)", nil, true, true, ""},
		{"both: the first row's reference wins", marker, true, true, ref},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := cloudLayout(t, "remote_desktop.jsonl", sid, tc.tip)
			res, err := signalAdapter(tc.env).ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("the surface stamp must not depend on the second signal: %+v", res.SessionSurfaces)
			}
			if !tc.want {
				if len(res.SessionExecutions) != 0 {
					t.Fatalf("stamped %+v without a second signal", res.SessionExecutions)
				}
				return
			}
			want := models.SessionExecution{SessionID: sid, ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: tc.wantRef}
			if len(res.SessionExecutions) != 1 || res.SessionExecutions[0] != want {
				t.Fatalf("executions = %+v; want %+v", res.SessionExecutions, want)
			}
		})
	}
	// Every row is named (the docs and the hand-back cite them).
	for _, s := range claudeCloudSecondSignals {
		if s.name == "" || s.holds == nil {
			t.Fatalf("unnamed or empty signal row %+v", s)
		}
	}
}

// TestCloudSecondSignalSubagentLayout: a subagent transcript
// (<session>/subagents/agent-*.jsonl) finds its parent's ccr-tip.json.
func TestCloudSecondSignalSubagentLayout(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "projects", "-home-user-r", "sess-parent")
	if err := os.MkdirAll(filepath.Join(dir, "subagents"), 0o755); err != nil {
		t.Fatal(err)
	}
	in := cloudSignalInput{
		transcriptPath: filepath.Join(dir, "subagents", "agent-a1.jsonl"), sessionID: "sess-parent",
		exists: func(p string) bool { return p == filepath.Join(dir, "ccr-tip.json") },
	}
	if _, sig, ok := confirmClaudeCloudExecution(in); !ok || sig == "" {
		t.Fatal("a subagent transcript did not find its parent's ccr-tip.json")
	}
	in.exists = func(string) bool { return false }
	if _, _, ok := confirmClaudeCloudExecution(in); ok {
		t.Fatal("confirmed with no signal")
	}
}

// TestTeleportedCopyKeepsCloudStamp pins the CA-D20 teleport rule on the
// store: a session another rail stamped vendor_cloud with its cse_
// reference keeps both when a local copy of its cloud lines (no second
// signal) is parsed, because this rail stamps nothing and the writer is
// first-wins.
func TestTeleportedCopyKeepsCloudStamp(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	const sid = "40b6413f-7a79-504b-8be9-87a38ca950cb"
	const ref = "cse_0123456789abcdefABCDEFGH"
	// The cloud rail (hook environment or OTLP) stamped it first.
	res, err := signalAdapter(nil).ParseSessionFile(ctx, cloudLayout(t, "remote_desktop.jsonl", sid, false), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionExecutions) != 0 {
		t.Fatalf("the teleported copy stamped %+v", res.SessionExecutions)
	}
	if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{SessionExecutions: []models.SessionExecution{
		{SessionID: sid, ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: ref},
	}}); err != nil {
		t.Fatal(err)
	}
	// The local copy is re-parsed (a teleport continuation appended).
	if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{SessionExecutions: res.SessionExecutions}); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadSessionExecution(ctx, sid)
	if err != nil || got.ExecutionLocation != models.ExecutionVendorCloud || got.VendorSessionRef != ref {
		t.Fatalf("after the teleported copy = %+v %v; want vendor_cloud + %s", got, err, ref)
	}
}

// TestParseCloudTranscriptFixtures parses the anonymized Claude Code cloud
// transcripts (testdata/claudecode/cloud, see its README for how they were
// recorded and anonymized), one per grounded entrypoint, laid out the way
// the cloud VM lays them out (so the CA-D20 second signal holds), and checks
// the surface, the execution stamp and that the ordinary capture (prompt,
// tool call, tokens) is unchanged.
func TestParseCloudTranscriptFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file, entrypoint, sid string
		wantKind, wantHost    string
	}{
		{"remote_desktop.jsonl", "remote_desktop", "40b6413f-7a79-504b-8be9-87a38ca950cb", models.SurfaceDesktop, "claude-desktop"},
		{"remote.jsonl", "remote", "c8263d13-fded-5d06-a187-d9220b8b9f45", models.SurfaceWeb, "claude-remote"},
	}
	for _, tc := range tests {
		t.Run(tc.entrypoint, func(t *testing.T) {
			t.Parallel()
			res, err := signalAdapter(nil).ParseSessionFile(context.Background(), cloudLayout(t, tc.file, tc.sid, true), 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.ToolEvents) == 0 || len(res.TokenEvents) == 0 {
				t.Fatalf("capture changed: %d tool events, %d token events", len(res.ToolEvents), len(res.TokenEvents))
			}
			sid := res.ToolEvents[0].SessionID
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("surfaces = %+v; want one", res.SessionSurfaces)
			}
			if s := res.SessionSurfaces[0]; s.SessionID != sid || s.Surface != tc.wantKind || s.SurfaceHost != tc.wantHost {
				t.Errorf("surface = %+v; want {%s %s %s}", s, sid, tc.wantKind, tc.wantHost)
			}
			if len(res.SessionExecutions) != 1 {
				t.Fatalf("executions = %+v; want one", res.SessionExecutions)
			}
			ex := res.SessionExecutions[0]
			// The transcript carries no `cse_...` id, so the reference is
			// left for the hook environment / Rail S flush to fill.
			want := models.SessionExecution{SessionID: sid, ExecutionLocation: models.ExecutionVendorCloud}
			if ex != want {
				t.Errorf("execution = %+v; want %+v", ex, want)
			}
			var bash bool
			for _, e := range res.ToolEvents {
				if e.RawToolName == "Bash" && e.ActionType == models.ActionRunCommand {
					bash = true
				}
			}
			if !bash {
				t.Errorf("Bash tool call not captured as run_command: %+v", res.ToolEvents)
			}
		})
	}
}

// TestLocalTranscriptStampsNoExecution pins the off-cloud half: a local
// transcript (simple-session.jsonl, entrypoint "cli") emits no execution
// stamp, so nothing changes for a developer machine.
func TestLocalTranscriptStampsNoExecution(t *testing.T) {
	t.Parallel()
	// Even with the cloud marker in the environment: a local entrypoint has
	// no execution row, so there is nothing to confirm.
	res, err := signalAdapter(map[string]string{"CLAUDE_CODE_REMOTE": "true"}).ParseSessionFile(context.Background(), fixturePath(t, "simple-session.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionExecutions) != 0 {
		t.Fatalf("local transcript stamped %+v; want none", res.SessionExecutions)
	}
}

// TestCloudExecutionStampedOncePerParse pins the once-per-parse gate: two
// cloud lines yield one stamp, from the first.
func TestCloudExecutionStampedOncePerParse(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cloud-twice.jsonl")
	body := userLine("sess-cloud", "m1", "remote_desktop") + "\n" + userLine("sess-cloud", "m2", "remote") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := signalAdapter(map[string]string{"CLAUDE_CODE_REMOTE": "true"}).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionExecutions) != 1 || res.SessionExecutions[0].SessionID != "sess-cloud" {
		t.Fatalf("executions = %+v; want exactly one for sess-cloud", res.SessionExecutions)
	}
}

// TestCloudFixtureLandsVendorCloud runs the fixture through the real store
// seam the watcher uses (IngestOptions.SessionExecutions ->
// Store.SetSessionExecution) and checks the session row, then that a later
// hook-environment stamp fills the reference without moving the location.
func TestCloudFixtureLandsVendorCloud(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	res, err := signalAdapter(nil).ParseSessionFile(ctx, cloudLayout(t, "remote_desktop.jsonl", "40b6413f-7a79-504b-8be9-87a38ca950cb", true), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	ir, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{
		SessionSurfaces:   res.SessionSurfaces,
		SessionExecutions: res.SessionExecutions,
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if ir.SessionExecutionsSkipped != 0 {
		t.Fatalf("SessionExecutionsSkipped = %d", ir.SessionExecutionsSkipped)
	}
	sid := res.SessionExecutions[0].SessionID
	got, err := st.LoadSessionExecution(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExecutionLocation != models.ExecutionVendorCloud || got.VendorSessionRef != "" {
		t.Fatalf("stored = %+v; want vendor_cloud with no reference yet", got)
	}
	const ref = "cse_0123456789abcdefABCDEFGH"
	if _, err := st.Ingest(ctx, nil, nil, store.IngestOptions{SessionExecutions: []models.SessionExecution{
		{SessionID: sid, ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: ref},
	}}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.LoadSessionExecution(ctx, sid)
	if got.ExecutionLocation != models.ExecutionVendorCloud || got.VendorSessionRef != ref {
		t.Fatalf("after hook stamp = %+v; want vendor_cloud + %s", got, ref)
	}
}

// TestCloudVMLayoutSignal pins the grounded VM-layout row of the CA-D20
// second-signal table (CA-A2 and the 2026-10-31 web / mobile probes): home
// /root, repository at /home/user/<repo>, transcript under
// /root/.claude/projects/-home-user-<repo>/.
func TestCloudVMLayoutSignal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, path, cwd string
		want            bool
	}{
		{"session transcript", "/root/.claude/projects/-home-user-acme/0b6e.jsonl", "/home/user/acme", true},
		{"subdirectory working dir", "/root/.claude/projects/-home-user-acme/0b6e.jsonl", "/home/user/acme/pkg", true},
		{"subagent transcript", "/root/.claude/projects/-home-user-acme/0b6e/subagents/agent-a1.jsonl", "/home/user/acme", true},
		{"no working dir seen yet", "/root/.claude/projects/-home-user-acme/0b6e.jsonl", "", true},
		{"a developer's own home", "/home/dev/.claude/projects/-home-dev-acme/0b6e.jsonl", "/home/dev/acme", false},
		{"root, but the repository elsewhere", "/root/.claude/projects/-srv-acme/0b6e.jsonl", "/srv/acme", false},
		{"layout path, working dir elsewhere", "/root/.claude/projects/-home-user-acme/0b6e.jsonl", "/tmp/acme", false},
		{"bare prefix slug", "/root/.claude/projects/-home-user-/0b6e.jsonl", "/home/user/", false},
		{"too deep", "/root/.claude/projects/-home-user-acme/x/y/z.jsonl", "/home/user/acme", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := cloudVMLayout(tc.path, tc.cwd); got != tc.want {
				t.Fatalf("cloudVMLayout(%q, %q) = %v; want %v", tc.path, tc.cwd, got, tc.want)
			}
			_, _, ok := confirmClaudeCloudExecution(cloudSignalInput{transcriptPath: tc.path, sessionID: "0b6e", cwd: tc.cwd, exists: func(string) bool { return false }})
			if ok != tc.want {
				t.Fatalf("confirm = %v; want %v (the layout row decides alone here)", ok, tc.want)
			}
		})
	}
}

// TestRemoteMobileTranscript: a mobile-started cloud transcript stamps the
// mobile surface, and vendor_cloud once a second signal holds.
func TestRemoteMobileTranscript(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mobile.jsonl")
	if err := os.WriteFile(path, []byte(userLine("sess-mobile", "m1", "remote_mobile")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := signalAdapter(map[string]string{"CLAUDE_CODE_REMOTE": "true"}).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceMobile || res.SessionSurfaces[0].SurfaceHost != "claude-mobile" {
		t.Fatalf("surface = %+v", res.SessionSurfaces)
	}
	if len(res.SessionExecutions) != 1 || res.SessionExecutions[0].ExecutionLocation != models.ExecutionVendorCloud {
		t.Fatalf("execution = %+v", res.SessionExecutions)
	}
}
