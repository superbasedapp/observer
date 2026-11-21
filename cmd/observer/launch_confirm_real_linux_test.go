//go:build linux && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// launch_confirm_real_linux_test.go pins lane cli-2 fixes-2, audit H-A,
// against the REAL confirm checks (no injected confirmer): an agent that
// runs `observer terminals confirm` on its own held launch, or POSTs the
// dashboard's confirm route, is refused when it carries an agent session's
// marker, whether it reports the marker (the CLI's hint) or not (the daemon
// reads the caller's and its ancestors' environment itself).

// helperConfirmURL is set in the environment of the helper child process.
const helperConfirmURL = "OBSERVER_TEST_HELPER_CONFIRM_URL"

// TestHelperConfirmPost is not a test: run as a child process with
// helperConfirmURL set, it POSTs the dashboard confirm route from its own
// process (so the daemon identifies it) and prints the status.
func TestHelperConfirmPost(t *testing.T) {
	u := os.Getenv(helperConfirmURL)
	if u == "" {
		t.Skip("helper process only")
	}
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Observer-Confirm", "tok")
	req.AddCookie(&http.Cookie{Name: "sb_remote_confirm", Value: "tok"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("status=error", err)
		return
	}
	_ = resp.Body.Close()
	fmt.Printf("status=%d\n", resp.StatusCode)
}

// markerInOwnAncestry reports whether this test process's own chain
// carries an agent marker (a run inside an agent's shell): then no child
// of it can read as a human, and the human legs are skipped.
func markerInOwnAncestry() bool {
	_, ok := readSessionMarker(append([]int{os.Getpid()}, peerproc.Ancestors(os.Getpid())...))
	return ok
}

// childEnv is this process's environment without the marker keys, plus
// extra.
func childEnv(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		drop := false
		for _, k := range procmodel.SessionTokenEnvKeys {
			if strings.HasPrefix(kv, k+"=") {
				drop = true
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

// TestRealConfirmRefusesAnAgentMarkerOverHTTP drives the real dashboard
// confirm route with the real resolver (launchInitiator.dashboardOrigin:
// the connection's holder found in /proc, its environment read).
func TestRealConfirmRefusesAnAgentMarkerOverHTTP(t *testing.T) {
	if !peerproc.Supported() {
		t.Skip("no caller lookup here")
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := newPendingLaunchStore()
	var started atomic.Int32
	held, err := store.hold(agentlaunch.Pending{Tool: "codex", Origin: termrun.Origin{Initiator: termrun.InitiatorAgent}},
		func(context.Context) (pendingOutcome, error) { started.Add(1); return pendingOutcome{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	li := launchInitiator{ancestors: peerproc.Ancestors, envMarker: readSessionMarker}
	s, err := dashboard.New(dashboard.Options{DB: database, LaunchCaller: li.dashboardOrigin, PendingLaunches: dashboardPending{p: store}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	post := func(env []string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperConfirmPost$", "-test.v")
		cmd.Env = slices.Concat(env, []string{helperConfirmURL + "=" + srv.URL + "/api/terminal/pending/" + held.ID + "/confirm"})
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %v\n%s", err, out)
		}
		return string(out)
	}
	// The child carries the marker in its own environment and reports
	// nothing: the daemon reads it.
	if out := post(childEnv(procmodel.SessionTokenEnvKeys[0] + "=sess-agent")); !strings.Contains(out, "status=403") {
		t.Fatalf("an agent's HTTP confirm was not refused:\n%s", out)
	}
	if started.Load() != 0 || len(store.holds.List()) != 1 {
		t.Fatalf("an agent's confirm started the hold (%d) or consumed it", started.Load())
	}
	if markerInOwnAncestry() {
		t.Log("this test runs inside an agent's shell; the human leg is skipped")
		return
	}
	if out := post(childEnv()); !strings.Contains(out, "status=200") || started.Load() != 1 {
		t.Fatalf("a human's HTTP confirm: started %d\n%s", started.Load(), out)
	}
}

// TestRealConfirmRefusesAnAgentMarkerOverTheCLI drives `observer terminals
// confirm` over the real attach socket against the real confirmer
// (launchConfirmer): the CLI reports the marker it finds in its
// environment, and the confirm is refused.
func TestRealConfirmRefusesAnAgentMarkerOverTheCLI(t *testing.T) {
	requireTerminalsActive(t)
	f := newFakeTermsvc()
	f.probe = liveProbe()
	var agent atomic.Bool
	agent.Store(true)
	c := agentCallerDaemon(t, f, &agent)
	// The real confirmer: ancestry, the start check (fixes-3) and the
	// client's hint. (The daemon's environment read is pinned over HTTP
	// above; it is left out here so the human leg runs even inside an
	// agent's shell.)
	c.confirmer = launchConfirmer(launchInitiator{ancestors: peerproc.Ancestors, startOf: peerproc.StartToken})

	_, _, code := runVerb(t, "launch", "claude", "--project", "/home/dev/repo", "--detach")
	if code != launchExitPending {
		t.Fatalf("launch exit %d, want held", code)
	}
	id := store1(t, c)

	t.Setenv(procmodel.SessionTokenEnvKeys[0], "sess-agent")
	_, errb, code := runVerb(t, "terminals", "confirm", id)
	if code != launchExitUnavailable || !strings.Contains(errb, "agent") || len(f.specs) != 0 {
		t.Fatalf("an agent's CLI confirm: exit %d, stderr %q, specs %d", code, errb, len(f.specs))
	}
	t.Setenv(procmodel.SessionTokenEnvKeys[0], "")
	if _, errb, code = runVerb(t, "terminals", "confirm", id); code != 0 || len(f.specs) != 1 {
		t.Fatalf("a human's CLI confirm: exit %d, stderr %q, specs %d", code, errb, len(f.specs))
	}
}

// store1 returns the one held launch's id.
func store1(t *testing.T, c *launchControl) string {
	t.Helper()
	list := c.pending.holds.List()
	if len(list) != 1 {
		t.Fatalf("holds = %+v", list)
	}
	return list[0].ID
}

// TestRealResolverReadsAChildsMarker: the daemon's own environment read
// finds the marker of a launching process that did not report it.
func TestRealResolverReadsAChildsMarker(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.Env = childEnv(procmodel.SessionTokenEnvKeys[0] + "=sess-child")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	li := launchInitiator{ancestors: peerproc.Ancestors, envMarker: readSessionMarker}
	want := termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-child"}
	// Start returns once the child is forked, which can be before it has
	// exec'd sleep; until then /proc/<pid>/environ is still the parent's,
	// without the marker (a loaded gate box, 2026-11-12). Wait for the exec.
	var got termrun.Origin
	for deadline := time.Now().Add(5 * time.Second); ; {
		got = li.origin(context.Background(), agentlaunch.FrontCLI, cmd.Process.Pid, false, "")
		if got == want || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("origin = %+v", got)
	}
	ok, why, _ := agentlaunch.MayConfirm(agentlaunch.ConfirmFacts{Origin: got})
	if ok || why == "" {
		t.Fatal("a caller carrying the marker may confirm")
	}
}
