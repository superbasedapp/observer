//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// sandbox_p2e_merge_test.go pins the fixes made at the SBX-P2E merge
// (audit findings 3 to 8).

var p2eDrift = sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseHooksDrifted}}

// TestRelayFloorEnderRetriesAFailedEnd (finding 3): an end that did not
// happen is not marked done, so the next health change retries it, and the
// warning says it was NOT ended; a run with no terminal run is never called
// ended either.
func TestRelayFloorEnderRetriesAFailedEnd(t *testing.T) {
	prev := relayRequireFullCapture
	relayRequireFullCapture = func() bool { return true }
	t.Cleanup(func() { relayRequireFullCapture = prev })

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ok, calls := false, 0
	step := relayFloorEnder(func(string, string, string) bool { calls++; return ok }, logger)
	run := sandboxrelayd.RunRecord{RunID: "relay-retry", TerminalRunID: "term-retry"}
	t.Cleanup(func() { relayOnRunEnd(run) })

	step(run, p2eDrift)
	if calls != 1 {
		t.Fatalf("calls %d, want 1", calls)
	}
	if _, marked := relayEndedByFloor.Load(run.RunID); marked {
		t.Fatal("a failed end was marked done, so it would never be retried")
	}
	if !strings.Contains(buf.String(), "is NOT ended") || strings.Contains(buf.String(), "the run is ended") {
		t.Fatalf("the warning does not say what happened: %s", buf.String())
	}
	buf.Reset()
	ok = true
	step(run, p2eDrift)
	if calls != 2 {
		t.Fatalf("the failed end was not retried: calls %d", calls)
	}
	if _, marked := relayEndedByFloor.Load(run.RunID); !marked || !strings.Contains(buf.String(), "the run is ended") {
		t.Fatalf("a successful end: marked %v, log %s", marked, buf.String())
	}
	step(run, p2eDrift)
	if calls != 2 {
		t.Fatalf("an ended run was ended again: calls %d", calls)
	}

	buf.Reset()
	cli := sandboxrelayd.RunRecord{RunID: "relay-cli"}
	step(cli, p2eDrift)
	if calls != 2 || !strings.Contains(buf.String(), "is NOT ended") {
		t.Fatalf("a run with no terminal run: calls %d, log %s", calls, buf.String())
	}
	if _, marked := relayEndedByFloor.Load(cli.RunID); marked {
		t.Fatal("a run with no terminal run was marked ended")
	}
}

// TestRelayFloorPublishEndsRunsThatDriftedBefore (finding 4): a run that
// drifted while no floor was in force keeps running; publishing a
// require_full_capture floor through the real dispatch sweeps it and ends
// it, once.
func TestRelayFloorPublishEndsRunsThatDriftedBefore(t *testing.T) {
	isolationFloorsClear()
	ended := make(chan string, 4)
	endRun := func(id, reason, _ string) bool {
		if reason != store.EndReasonOrgFloorHooksDrifted {
			t.Errorf("end reason %q", reason)
		}
		ended <- id
		return true
	}
	run := sandboxrelayd.RunRecord{RunID: "relay-before", TerminalRunID: "term-before"}
	t.Cleanup(func() { relayOnRunEnd(run) })
	onHealth := relayHealthSteps(relayOnHealth(nil, nil), relayFloorEnder(endRun, nil))
	onHealth(run, p2eDrift)
	select {
	case id := <-ended:
		t.Fatalf("%s ended with no floor in force", id)
	default:
	}

	sweep := relayFloorSweep(endRun, nil)
	prevSweep := relayFloorSweeper.Load()
	relayFloorSweeper.Store(&sweep)
	t.Cleanup(func() { relayFloorSweeper.Store(prevSweep) })

	publishFloorsForTest(t, `{"require_full_capture":true}`, true)
	select {
	case id := <-ended:
		if id != "term-before" {
			t.Fatalf("ended %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the floor publish did not end the run that drifted before it")
	}
	relayFloorsApplied()
	select {
	case id := <-ended:
		t.Fatalf("%s ended twice", id)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestTerminalRunEnderRecordsWhyAndShowsIt (finding 5): through the real
// terminal service and manager, the ender records the end reason first,
// writes the notice to the terminal's output, then closes the run; an
// unknown run ends nothing.
func TestTerminalRunEnderRecordsWhyAndShowsIt(t *testing.T) {
	ctx := context.Background()
	mgr := termsession.NewManager(termsession.Options{Spawner: fakeSpawner{}})
	t.Cleanup(mgr.Shutdown)
	svc := termsvc.New(termsvc.Options{Recorder: nopRunRecorder{}, Launcher: mgrLauncher{mgr: mgr}})
	res, err := svc.LaunchHandoff(ctx, termsvc.HandoffRequest{Tool: "claude-code", Subcommand: "claude", SessionID: "src"})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := mgr.Subscribe(res.Handle)
	if err != nil {
		t.Fatal(err)
	}
	var ref atomic.Pointer[termsvc.Service]
	ref.Store(svc)
	var order []string
	stamp := func(_ context.Context, runID, reason string) error {
		if _, live := svc.HandleForRun(runID); !live {
			t.Error("the reason was recorded after the run closed")
		}
		order = append(order, "stamp:"+runID+":"+reason)
		return nil
	}
	end := terminalRunEnder(&ref, mgr, stamp, nil)
	if end("no-such-run", store.EndReasonOrgFloorHooksDrifted, "x") {
		t.Fatal("an unknown run was reported ended")
	}
	notice := relayFullCaptureEndCauses[sandboxrelayd.CauseHooksDrifted].notice
	if !end(res.RunID, store.EndReasonOrgFloorHooksDrifted, notice) {
		t.Fatal("the live run was not ended")
	}
	if len(order) != 1 || order[0] != "stamp:"+res.RunID+":"+store.EndReasonOrgFloorHooksDrifted {
		t.Fatalf("recorded %v", order)
	}
	got := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 512)
		for {
			n, err := sub.Read(buf)
			b.Write(buf[:n])
			if err != nil || strings.Contains(b.String(), "Require full capture") {
				break
			}
		}
		got <- b.String()
	}()
	select {
	case s := <-got:
		if !strings.Contains(s, "Require full capture") || !strings.Contains(s, "drifted") {
			t.Fatalf("the terminal's last output %q does not say why", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the notice never reached the terminal")
	}
	if _, err := mgr.Subscribe(res.Handle); err == nil {
		t.Fatal("the run's terminal is still open")
	}
}

// TestResumableSessionSetSkipsFloorEndedRuns (finding 5): a run the org
// floor ended is never offered for auto-resume, even with no exit recorded.
func TestResumableSessionSetSkipsFloorEndedRuns(t *testing.T) {
	set := resumableSessionSet([]store.TerminalRunSummary{
		{RunID: "f1", Tool: "claude-code", Kind: string(termrun.KindAttach), EndReason: store.EndReasonOrgFloorHooksDrifted, BestSessionID: "sess-floor"},
	})
	if len(set) != 0 {
		t.Fatalf("a floor-ended run is resumable: %v", set)
	}
}

// p2eProber is a fixed sandbox probe answer.
type p2eProber struct{ av dashapi.SandboxAvailability }

func (p p2eProber) ProbeSandbox(context.Context) dashapi.SandboxAvailability { return p.av }

// TestSandboxManagedRefusedReachesThePush (finding 6): with a managed body
// in force, the push helper's real path (config.Load plus composition)
// returns the node's refusals, and bindSandboxCapability carries them onto
// the real store's push envelope; withdrawn, the push carries none.
func TestSandboxManagedRefusedReachesThePush(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the body's POSIX paths are not absolute on Windows (PT-02 pattern)")
	}
	ctx := context.Background()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldCfg := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(&cfgPath)
	t.Cleanup(func() { daemonConfigPathSetting.Store(oldCfg) })
	t.Cleanup(func() { processSandboxManaged.observe(orgclient.ManagedPullOutcome{}) })

	body := []byte(`{"schema":"sbo-sandbox-managed-v1","prep_timeout_seconds":600,"node":{"extra_rw_binds":["/home/alice/.config/gh"]}}`)
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 2, ExpiresAt: time.Now().Add(time.Hour).Unix(), Body: body})
	got := sandboxManagedRefusedForPush(ctx)
	if len(got) != 1 || got[0].Key != "extra_rw_binds" || got[0].Reason != sandboxRefusedSensitive {
		t.Fatalf("the in-force push helper returned %+v", got)
	}

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	bindSandboxCapability(ctx, st, true, p2eProber{av: dashapi.SandboxAvailability{Egress: "internet", Backends: []dashapi.SandboxBackendAvail{
		{ID: "bwrap", Available: true, Class: "process", CaptureByTier: map[string]string{"internet": "full"}},
	}}})
	push := func() *orgcontract.SandboxCapabilityRow {
		t.Helper()
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org", "dev@example.test", store.ShareOptions{TerminalDetail: true}, store.ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if batch.SandboxCapability == nil {
			t.Fatal("no capability row on the push")
		}
		return batch.SandboxCapability
	}
	row := push()
	if len(row.Backends) != 1 || row.Backends[0] != "bwrap" || len(row.ManagedRefused) != 1 || row.ManagedRefused[0].Key != "extra_rw_binds" || row.ManagedRefused[0].Reason != sandboxRefusedSensitive {
		t.Fatalf("the push row %+v", row)
	}
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	if row := push(); len(row.ManagedRefused) != 0 {
		t.Fatalf("the body is withdrawn, but the push carries %+v", row.ManagedRefused)
	}
}

// TestComposeSandboxManagedCaseAndWSLWriteBinds (finding 7, ruling P-054):
// at node apply, a WSL Windows drive mount's home, its holders, its denied
// entries and its system directories are refused as write binds in any
// case, a project under it passes, and a home entry spelled in another case
// is refused only where the node compares case-insensitively.
func TestComposeSandboxManagedCaseAndWSLWriteBinds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths are not absolute on Windows (PT-02 pattern)")
	}
	home := t.TempDir()
	env := sandboxManagedEnv{home: home, observerDir: "/nonexistent-sbx-p2e/obs", resolve: resolveSandboxBindPath}
	prev := sandboxHostCaseSensitive
	t.Cleanup(func() { sandboxHostCaseSensitive = prev })
	refusedAs := func(p string) string {
		node := orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &[]string{p}}
		_, refused := composeSandboxManaged(config.TerminalSandboxConfig{}, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &node}, env)
		if len(refused) == 0 {
			return ""
		}
		return refused[0].Reason
	}
	sandboxHostCaseSensitive = func() bool { return true }
	for _, tc := range []struct{ p, want string }{
		{"/mnt", sandboxRefusedSensitive},
		{"/mnt/c", sandboxRefusedSensitive},
		{"/mnt/c/Users", sandboxRefusedSensitive},
		{"/mnt/c/Users/Alice", sandboxRefusedSensitive},
		{"/mnt/c/Users/Alice/.SSH", sandboxRefusedSensitive},
		{"/mnt/c/users/alice/AppData/Roaming", sandboxRefusedSensitive},
		{"/mnt/c/Users/alice/.config", sandboxRefusedSensitive},
		{"/mnt/c/Windows/System32", sandboxRefusedSensitive},
		{"/mnt/D/WINDOWS", sandboxRefusedSensitive},
		{"/mnt/c/Users/alice/proj", ""},
		{"/mnt/data/cache", ""},
		{filepath.Join(home, ".SSH"), ""},
		{filepath.Join(home, ".ssh"), sandboxRefusedSensitive},
	} {
		if got := refusedAs(tc.p); got != tc.want {
			t.Errorf("case-sensitive node, %s: got %q want %q", tc.p, got, tc.want)
		}
	}
	sandboxHostCaseSensitive = func() bool { return false }
	if got := refusedAs(filepath.Join(home, ".SSH")); got != sandboxRefusedSensitive {
		t.Errorf("case-insensitive node, ~/.SSH: got %q", got)
	}
	if got := refusedAs(strings.ToUpper(home)); got != sandboxRefusedSensitive {
		t.Errorf("case-insensitive node, the home in upper case: got %q", got)
	}
}

// TestSandboxManagedOrgRWBinds (finding 8): the org-set write binds are the
// in-force body's per-node extra_rw_binds, none when the key was refused or
// no body is in force.
func TestSandboxManagedOrgRWBinds(t *testing.T) {
	binds := []string{"/srv/repo", "/srv/other/"}
	p := &orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &binds}}
	got := sandboxManagedOrgRWBinds(p, nil)
	if len(got) != 2 || got[0] != filepath.Clean(filepath.FromSlash("/srv/repo")) || got[1] != filepath.Clean(filepath.FromSlash("/srv/other")) {
		t.Fatalf("org binds %v", got)
	}
	if got := sandboxManagedOrgRWBinds(p, []SandboxManagedRefusedKey{{Key: "terminal.sandbox.extra_rw_binds", Reason: sandboxRefusedSensitive}}); got != nil {
		t.Fatalf("a refused key still yields %v", got)
	}
	if sandboxManagedOrgRWBinds(nil, nil) != nil || sandboxManagedOrgRWBinds(&orgcontract.SandboxManagedPolicyV1{}, nil) != nil {
		t.Fatal("no body or no binds yields binds")
	}
}

// TestSandboxOrgBindReposGetReadOnlyGitState (finding 8, ruling P-054):
// through the launch's own overlay composition, an org-set write bind that
// is a repository (or holds one directly inside it, or a .git pointer file)
// gets .git/hooks and .git/config read-only even with
// allow_tool_config_writes on; the developer's own write bind is untouched;
// a symlinked .git refuses the launch naming the path.
func TestSandboxOrgBindReposGetReadOnlyGitState(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	parent := filepath.Join(root, "parent")
	nested := filepath.Join(parent, "inner")
	pointer := filepath.Join(root, "worktree")
	mine := filepath.Join(root, "mine")
	for _, d := range []string{filepath.Join(repo, ".git", "hooks"), filepath.Join(nested, ".git"), pointer, filepath.Join(mine, ".git", "hooks")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(repo, ".git", "config"), filepath.Join(mine, ".git", "config")} {
		if err := os.WriteFile(f, []byte("[core]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pointer, ".git"), []byte("gitdir: /elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(root, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{repo, parent, pointer, mine}, AllowToolConfigWrites: true},
		observerDir: filepath.Join(root, "obs"),
		orgRWBinds:  []string{repo, parent, pointer},
	}
	ovs, err := r.overlays(filepath.Join(root, "home"), ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]sandbox.OverlayKind{}
	for _, o := range ovs {
		got[o.Path] = o.Kind
	}
	for _, p := range []string{
		filepath.Join(repo, ".git", "config"), filepath.Join(repo, ".git", "hooks"),
		filepath.Join(nested, ".git", "config"), filepath.Join(nested, ".git", "hooks"),
		filepath.Join(pointer, ".git"),
	} {
		if k, ok := got[p]; !ok || k != sandbox.OverlayReadOnly {
			t.Errorf("%s: overlay %v (present %v), want read-only", p, k, ok)
		}
	}
	for _, p := range []string{filepath.Join(mine, ".git", "config"), filepath.Join(mine, ".git", "hooks")} {
		if _, ok := got[p]; ok {
			t.Errorf("%s: the developer's own write bind was re-bound", p)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	linked := filepath.Join(root, "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, filepath.Join(repo, ".git"), filepath.Join(linked, ".git")); err != nil {
		t.Fatal(err)
	}
	r.cfg.ExtraRWBinds = append(r.cfg.ExtraRWBinds, linked)
	r.orgRWBinds = append(r.orgRWBinds, linked)
	if _, err := r.overlays(filepath.Join(root, "home"), ws, integration.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), filepath.Join(linked, ".git")) {
		t.Fatalf("a symlinked .git under an org bind: %v", err)
	}
}
