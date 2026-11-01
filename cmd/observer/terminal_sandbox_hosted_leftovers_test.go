//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// hostedLeftoverEnv sets HOME and registers a fake E2B driver.
func hostedLeftoverEnv(t *testing.T) (string, *fakeBoxClient) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	obs := filepath.Join(home, ".observer")
	_ = os.MkdirAll(obs, 0o700)
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_leftover"})
	c := newFakeBoxClient()
	old, had := hostedVendorRegs[sandboxremote.VendorE2B]
	hostedVendorRegs[sandboxremote.VendorE2B] = hostedVendorReg{vendor: sandboxremote.VendorE2B, newClient: func(sandboxremote.Credential, string) (sandboxremote.Client, error) { return c, nil }}
	t.Cleanup(func() {
		if had {
			hostedVendorRegs[sandboxremote.VendorE2B] = old
		} else {
			delete(hostedVendorRegs, sandboxremote.VendorE2B)
		}
	})
	return obs, c
}

func TestHostedLeftoverDeleteConfirms(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "r1"}})
	rec := sandboxremote.NewIntent("r1", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "r1", time.Now().Add(-time.Hour), time.Hour)
	rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
	_ = hostedSaveRecord(obs, rec)
	// A lost create: no vendor id, found by its label.
	lost, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "r2"}})
	rec2 := sandboxremote.NewIntent("r2", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "r2", time.Now(), time.Hour)
	rec2.State = sandboxremote.StateCreateLost
	_ = hostedSaveRecord(obs, rec2)
	if len(c.calls) != 2 {
		t.Fatalf("setup calls %v", c.calls)
	}
	if err := hostedDeleteLeftover(ctx, obs, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := hostedDeleteLeftover(ctx, obs, "r2"); err != nil {
		t.Fatal(err)
	}
	if !c.boxes[info.ID].deleted || !c.boxes[lost.ID].deleted {
		t.Error("a leftover box was not deleted")
	}
	if recs := hostedLoadRecords(obs); len(recs) != 0 {
		t.Errorf("records %+v", recs)
	}
	if err := hostedAdopt(ctx, obs, "r1", strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Error("adopted a deleted run")
	}
}

// TestHostedLiveRunIsNotALeftover: a run whose helper still runs is not
// listed, and neither a delete nor an adopt touches its box.
func TestHostedLiveRunIsNotALeftover(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	old := hostedHelperAlive
	hostedHelperAlive = func(pid string) bool { return pid == "4242" }
	t.Cleanup(func() { hostedHelperAlive = old })
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "live"}})
	rec := sandboxremote.NewIntent("live", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "live", time.Now(), time.Hour)
	rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
	rec.Extra = map[string]string{hostedHelperPIDKey: "4242", "pty_pid": "42"}
	_ = hostedSaveRecord(obs, rec)
	if list := hostedLeftoverList(obs); len(list) != 0 {
		t.Errorf("a live run is listed: %+v", list)
	}
	if err := hostedDeleteLeftover(ctx, obs, "live"); err == nil || !strings.Contains(err.Error(), "still live") {
		t.Errorf("delete of a live run: %v", err)
	}
	if err := hostedAdopt(ctx, obs, "live", strings.NewReader(""), &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "still live") {
		t.Errorf("adopt of a live run: %v", err)
	}
	if c.boxes[info.ID].deleted {
		t.Error("the live box was deleted")
	}
	hostedHelperAlive = func(string) bool { return false }
	if list := hostedLeftoverList(obs); len(list) != 1 {
		t.Errorf("the run with its helper gone is not listed: %+v", list)
	}
}

// TestHostedRoutes: the panel's read carries no credential value and calls
// no provider; every write needs the confirm token.
func TestHostedRoutes(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	hostedActiveForTest(t, true)
	rec := sandboxremote.NewIntent("r9", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "r9", time.Now(), time.Hour)
	rec.VendorID, rec.State = "box9", sandboxremote.StateRunning
	_ = hostedSaveRecord(obs, rec)
	routes := map[string]http.HandlerFunc{}
	load := func(context.Context) (config.TerminalSandboxConfig, error) {
		return config.Default().Terminal.Sandbox, nil
	}
	for _, rt := range hostedDashboardRoutes("") {
		routes[rt.Pattern] = rt.Handler
	}
	routes["GET /api/terminal/sandbox/hosted"] = func(w http.ResponseWriter, r *http.Request) { hostedGetHandler(w, r, load) }
	w := httptest.NewRecorder()
	routes["GET /api/terminal/sandbox/hosted"](w, httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/hosted", nil))
	body := w.Body.String()
	if w.Code != 200 || strings.Contains(body, "FAKEKEY") || !strings.Contains(body, `"credential":"env"`) || !strings.Contains(body, `"run_id":"r9"`) {
		t.Errorf("GET %d %s", w.Code, body)
	}
	if len(c.calls) != 0 {
		t.Errorf("a page read called the provider: %v", c.calls)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox/hosted/leftovers/delete", strings.NewReader(`{"run_id":"r9"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	routes["POST /api/terminal/sandbox/hosted/leftovers/delete"](w, req)
	if w.Code != http.StatusForbidden || len(c.calls) != 0 {
		t.Errorf("a delete without the confirm token: %d calls %v", w.Code, c.calls)
	}
	for _, rt := range hostedDashboardRoutes("") {
		if rt.Capability.String() != "local" {
			t.Errorf("%s is %s, want local (the read previews a workspace)", rt.Pattern, rt.Capability)
		}
	}
}

// hostedActiveForTest sets whether a hosted driver counts as active.
func hostedActiveForTest(t *testing.T, on bool) {
	t.Helper()
	old := hostedActive
	hostedActive = func(context.Context, string) bool { return on }
	t.Cleanup(func() { hostedActive = old })
}

// TestHostedInactiveAnswersNotFound (the SBX-P7 merge's audit finding 5):
// while no hosted driver is active every hosted route answers 404 (the
// workspace preview never runs) and every `observer sandbox hosted` verb
// refuses as not active, calling no provider.
func TestHostedInactiveAnswersNotFound(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	hostedActiveForTest(t, false)
	rec := sandboxremote.NewIntent("r7", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "r7", time.Now(), time.Hour)
	rec.VendorID, rec.State = "box7", sandboxremote.StateRunning
	_ = hostedSaveRecord(obs, rec)
	ws := t.TempDir()
	for _, rt := range hostedDashboardRoutes("") {
		method, path, _ := strings.Cut(rt.Pattern, " ")
		req := httptest.NewRequest(method, path+"?workspace="+ws, strings.NewReader(`{"run_id":"r7"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		rt.Handler(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d while no hosted driver is active", rt.Pattern, w.Code)
		}
	}
	for _, args := range [][]string{{"leftovers"}, {"delete", "r7"}, {"consent", "e2b", "--yes"}, {"disconnect", "e2b"}} {
		cmd := newSandboxHostedCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&strings.Builder{})
		cmd.SetErr(&strings.Builder{})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "not active") {
			t.Errorf("hosted %v while inactive: %v", args, err)
		}
	}
	if len(c.calls) != 0 {
		t.Errorf("an inactive hosted surface called the provider: %v", c.calls)
	}
	if hostedAnyActive(config.Default()) {
		t.Error("a config with no [components] block has a hosted driver active")
	}
}

// TestHostedDeleteForceStopsTheLiveHelper (live run 2026-10-23, finding F3):
// a delete of a run still live in its terminal is refused and names
// --force; the forced delete says what it stops, stops the helper, then
// deletes the box.
func TestHostedDeleteForceStopsTheLiveHelper(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	alive := true
	stopped := ""
	oldAlive, oldStop := hostedHelperAlive, hostedStopHelper
	hostedHelperAlive = func(pid string) bool { return alive && pid == "4242" }
	hostedStopHelper = func(pid string) error { stopped, alive = pid, false; return nil }
	t.Cleanup(func() { hostedHelperAlive, hostedStopHelper = oldAlive, oldStop })
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "live"}})
	rec := sandboxremote.NewIntent("live", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "live", time.Now(), time.Hour)
	rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
	rec.Extra = map[string]string{hostedHelperPIDKey: "4242"}
	_ = hostedSaveRecord(obs, rec)
	var out strings.Builder
	if err := hostedDeleteRun(ctx, obs, "live", false, &out); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("unforced delete of a live run: %v", err)
	}
	if stopped != "" || c.boxes[info.ID].deleted {
		t.Fatal("an unforced delete touched the live run")
	}
	if err := hostedDeleteRun(ctx, obs, "live", true, &out); err != nil {
		t.Fatal(err)
	}
	if stopped != "4242" || !strings.Contains(out.String(), "stopping the live helper of run live (pid 4242)") || !strings.Contains(out.String(), "ends the agent") {
		t.Errorf("stopped %q, said %q", stopped, out.String())
	}
	if !c.boxes[info.ID].deleted {
		t.Error("the forced delete left the box")
	}
	if recs := hostedLoadRecords(obs); len(recs) != 0 {
		t.Errorf("records %+v", recs)
	}
}
