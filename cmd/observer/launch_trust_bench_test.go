//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_benchmark

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// recordingHarness is a benchmark driver that records the request it was
// handed (relaunchingHarness adds the inner-launcher capability).
type recordingHarness struct {
	got *[]DriveRequest
}

func (h recordingHarness) Name() string { return "recording" }
func (h recordingHarness) Drive(_ context.Context, req DriveRequest) (DriveResult, error) {
	*h.got = append(*h.got, req)
	return DriveResult{}, nil
}

// relaunchingHarness is recordingHarness with the inner-launcher capability.
type relaunchingHarness struct{ recordingHarness }

func (relaunchingHarness) ChecksLaunchAgain() bool { return true }

// acceptAllTrust accepts every digest the check reports in root.
func acceptAllTrust(t *testing.T, cfgPath, root string) {
	t.Helper()
	res, err := sectrust.Check(context.Background(), sectrust.OSFS(root), sectrust.Request{})
	if err != nil {
		t.Fatal(err)
	}
	st := openTrustTestDBFromConfig(t, cfgPath)
	if _, err := st.AcceptSecTrustItems(context.Background(), guard.HashProjectRoot(root), secTrustItems(res), "cli:test", time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestBenchmarkAttemptHonoursTheTaskSourceAccepts (items 2, 3 and 9): an
// attempt's fresh workspace is refused under enforce until the task's
// local source repository is accepted, the refusal names that source and
// the command that accepts there, and one accept of the source covers
// every later attempt. The harness process learns the source for its own
// inner check, and what the check raised lands under the workspace's own
// hash, never the source's.
func TestBenchmarkAttemptHonoursTheTaskSourceAccepts(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	source := writeTrustRepo(t, untrustedHookRepo)
	var got []DriveRequest
	d := budgetControlledBenchmarkDriver{HarnessDriver: recordingHarness{got: &got}, configPath: cfgPath}

	ws := writeTrustRepo(t, untrustedHookRepo)
	_, err := d.Drive(context.Background(), DriveRequest{WorkspaceDir: ws, TaskRepo: source})
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+source) {
		t.Fatalf("unaccepted source: %v, want a refusal naming the source's accept", err)
	}
	if len(got) != 0 {
		t.Fatal("the harness ran after a refusal")
	}
	st := openTrustTestDBFromConfig(t, cfgPath)
	if recs, _ := st.ListSecTrustItems(context.Background(), guard.HashProjectRoot(source)); len(recs) != 0 {
		t.Fatalf("the workspace's items landed in the source's list: %+v", recs)
	}
	if recs, _ := st.ListSecTrustItems(context.Background(), guard.HashProjectRoot(ws)); len(recs) == 0 {
		t.Fatal("the workspace's items were not recorded under its own hash")
	}

	acceptAllTrust(t, cfgPath, source)
	for i := 0; i < 2; i++ {
		fresh := writeTrustRepo(t, untrustedHookRepo)
		if _, err := d.Drive(context.Background(), DriveRequest{WorkspaceDir: fresh, TaskRepo: "file://" + source}); err != nil {
			t.Fatalf("attempt %d after the source's accept: %v", i+1, err)
		}
		req := got[len(got)-1]
		want := []string{repoTrustCheckedEnv + "=" + guard.HashProjectRoot(fresh), repoTrustBenchmarkSourceEnv + "=" + source, repoTrustBenchmarkMarkerEnv + "=" + fresh}
		if strings.Join(req.TrustEnv, "|") != strings.Join(want, "|") {
			t.Fatalf("attempt %d trust env %v, want %v", i+1, req.TrustEnv, want)
		}
	}
	if os.Getenv(repoTrustCheckedEnv) != "" {
		t.Fatal("the marker reached the runner's own environment")
	}
}

// TestBenchmarkAttemptWithNoLocalSource: a task whose repository is not a
// local directory has nothing to accept. A driver whose harness is the
// inner `observer <tool>` launcher skips the outer check and says why; any
// other driver (the claude-code driver) is checked here on the workspace's
// own accepts, and its refusal says to point the task at a local file://
// clone and accept there, never to accept the throwaway workspace (plans
// decision log P-037).
func TestBenchmarkAttemptWithNoLocalSource(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	ws := writeTrustRepo(t, untrustedHookRepo)
	remote := "https://example.invalid/repo.git"

	var got []DriveRequest
	direct := budgetControlledBenchmarkDriver{HarnessDriver: recordingHarness{got: &got}, configPath: cfgPath}
	_, err := direct.Drive(context.Background(), DriveRequest{WorkspaceDir: ws, TaskRepo: remote})
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "file:// URL") ||
		!strings.Contains(err.Error(), "accept it there with `observer security trust accept --all --dir <clone>`") {
		t.Fatalf("direct harness, remote task: %v, want the outer check's refusal pointing at a local clone", err)
	}
	if strings.Contains(err.Error(), "--dir "+ws) {
		t.Fatalf("the refusal tells the developer to accept the throwaway workspace: %v", err)
	}
	if len(got) != 0 {
		t.Fatal("the harness ran after a refusal")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	inner := budgetControlledBenchmarkDriver{HarnessDriver: relaunchingHarness{recordingHarness{got: &got}}, configPath: cfgPath}
	_, err = inner.Drive(context.Background(), DriveRequest{WorkspaceDir: ws, TaskRepo: remote})
	os.Stderr = oldStderr
	_ = w.Close()
	said, _ := readAllString(r)
	if err != nil || len(got) != 1 {
		t.Fatalf("inner-launcher harness, remote task: %v (ran %d), want the outer check skipped", err, len(got))
	}
	if !strings.Contains(said, "not checked here") || !strings.Contains(said, "not a local directory") {
		t.Fatalf("the skip was not said: %q", said)
	}
	for _, kv := range got[0].TrustEnv {
		if strings.HasPrefix(kv, repoTrustBenchmarkSourceEnv+"=") {
			t.Fatalf("a remote task carried a source: %v", got[0].TrustEnv)
		}
	}
}

// TestBenchmarkScorerIsNotATrustCheckedLaunch (items 4 and 9): the scorer
// runs on what the agent wrote; a `.mcp.json` the agent added must not
// refuse scoring.
func TestBenchmarkScorerIsNotATrustCheckedLaunch(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	ws := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"node","args":["evil.js"]}}}`})
	if _, err := enforceDaemonStartedLaunch(context.Background(), cfgPath, "benchmark", budgetLaunchEvidence{}, daemonLaunch{dir: ws}); err == nil {
		t.Fatal("test premise: the agent-written .mcp.json refuses an agent launch here")
	}
	scored := 0
	s := budgetControlledBenchmarkScorer{inner: countingScorer{n: &scored}, configPath: cfgPath}
	if _, err := s.Score(context.Background(), scoreInput{WorkspaceDir: ws}); err != nil || scored != 1 {
		t.Fatalf("scorer: %v (scored %d), want scoring to run", err, scored)
	}
}

type countingScorer struct{ n *int }

func (c countingScorer) Score(context.Context, scoreInput) ([]benchmark.ScoreRecord, error) {
	*c.n++
	return nil, nil
}

// TestBenchmarkInnerLauncherReadsTheTaskSource: the `observer <tool>`
// launcher an attempt starts honours the task source named in its
// environment, as an unattended launch that records under its own root.
func TestBenchmarkInnerLauncherReadsTheTaskSource(t *testing.T) {
	source := writeTrustRepo(t, map[string]string{"README.md": "# x\n"})
	old := cliSandboxedEnv
	t.Cleanup(func() { cliSandboxedEnv = old })
	cliSandboxedEnv = func() bool { return false }
	ws := writeTrustRepo(t, map[string]string{"README.md": "# ws\n"})
	oldDir := cliLaunchDir
	t.Cleanup(func() { cliLaunchDir = oldDir })
	launchIn := filepath.Join(ws, "sub")
	if err := os.MkdirAll(launchIn, 0o755); err != nil {
		t.Fatal(err)
	}
	cliLaunchDir = func() (string, error) { return launchIn, nil }
	t.Setenv(repoTrustBenchmarkSourceEnv, source)
	// No driver-set marker: a stray variable is ignored.
	t.Setenv(repoTrustBenchmarkMarkerEnv, "")
	if h, dir := cliRepoTrustAcceptRoot(); h != "" || dir != "" {
		t.Fatalf("the source was honoured without the driver's marker: %q %q", h, dir)
	}
	// A marker naming another directory: ignored too.
	t.Setenv(repoTrustBenchmarkMarkerEnv, t.TempDir())
	if h, dir := cliRepoTrustAcceptRoot(); h != "" || dir != "" {
		t.Fatalf("the source was honoured with a marker for another directory: %q %q", h, dir)
	}
	// The marker the driver sets: the attempt's workspace, above the launch.
	t.Setenv(repoTrustBenchmarkMarkerEnv, ws)
	if h, dir := cliRepoTrustAcceptRoot(); h != guard.HashProjectRoot(source) || dir != source {
		t.Fatalf("accept root %q %q, want the source", h, dir)
	}
	t.Setenv(repoTrustBenchmarkSourceEnv, "relative/path")
	if h, dir := cliRepoTrustAcceptRoot(); h != "" || dir != "" {
		t.Fatalf("a relative source was honoured: %q %q", h, dir)
	}
	if !isInternalChildEnv(repoTrustBenchmarkSourceEnv+"="+source) || !isInternalChildEnv(repoTrustBenchmarkMarkerEnv+"="+ws) {
		t.Fatal("the daemon would pass an inherited task source or marker to its children")
	}
	env := benchmarkTrustChildEnv([]string{"A=1", repoTrustBenchmarkSourceEnv + "=/stale", repoTrustBenchmarkMarkerEnv + "=/stale", repoTrustCheckedEnv + "=x"}, []string{"B=2"})
	if strings.Join(env, "|") != "A=1|B=2" {
		t.Fatalf("child env %v", env)
	}
}

// readAllString drains r.
func readAllString(r *os.File) (string, error) {
	defer r.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String(), nil
		}
	}
}

// TestBenchmarkTaskSource reads a task repository as a local directory.
func TestBenchmarkTaskSource(t *testing.T) {
	dir := t.TempDir()
	real, _ := filepath.EvalSymlinks(dir)
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		dir: real, "file://" + dir: real, "https://example.invalid/r.git": "", "rel/dir": "", file: "", filepath.Join(dir, "missing"): "", "": "",
	} {
		if got := benchmarkTaskSource(in); got != want {
			t.Errorf("benchmarkTaskSource(%q) = %q, want %q", in, got, want)
		}
	}
}
