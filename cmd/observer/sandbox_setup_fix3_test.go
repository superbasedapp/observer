//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// Fix round 3 (2026-11-07 live checks, "Still open"): one test per item.

// TestSandboxSetupLiveApplyAsksTheDaemon (item 1): a CLI asks the running
// daemon to apply over loopback with the double-submit pair; one row per
// answer.
func TestSandboxSetupLiveApplyAsksTheDaemon(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"the daemon applied it", http.StatusOK, `{"applied":true}`, sandboxLiveDaemonApplied},
		{"the daemon could not apply", http.StatusOK, `{"applied":false}`, sandboxLiveNoAnswer},
		{"the daemon refused", http.StatusForbidden, `{"error":"x"}`, sandboxLiveNoAnswer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ck, err := r.Cookie(setupApplyConfirmCookie)
				if r.Method != http.MethodPost || r.URL.Path != "/api/terminal/sandbox/setup/bwrap/apply" || err != nil ||
					ck.Value == "" || ck.Value != r.Header.Get(setupApplyConfirmHeader) || r.Header.Get("Content-Type") != "application/json" {
					http.Error(w, "bad request shape", http.StatusTeapot)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			if got := askDaemonSandboxApply(context.Background(), srv.URL+"/api/terminal/sandbox/setup/bwrap/apply"); got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("no daemon listens", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if got := askDaemonSandboxApply(context.Background(), "http://"+addr+"/api/terminal/sandbox/setup/bwrap/apply"); got != sandboxLiveNoDaemon {
			t.Fatalf("outcome = %q, want %q", got, sandboxLiveNoDaemon)
		}
	})
}

// TestSandboxSetupEnableSaysOnlyAnUnconfirmedApply (item 1): Enable and its
// undo name no restart, and say one sentence only when the running daemon
// did not confirm the apply.
func TestSandboxSetupEnableSaysOnlyAnUnconfirmedApply(t *testing.T) {
	requireComponents(t, sandboxComponent)
	for outcome, wantNote := range sandboxLiveApplyNotes {
		t.Run(outcome, func(t *testing.T) {
			r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = false\nbackends = [\"oci-runc\"]\n")
			var asked []string
			r.svc.run.applyLive = func(_ context.Context, backend string) string {
				asked = append(asked, backend)
				return outcome
			}
			ctx := context.Background()
			for _, action := range []string{dashapi.SandboxSetupActionRun, dashapi.SandboxSetupActionUndo} {
				p := r.plan(t, sandboxbackend.BackendBwrap)
				if st := stepOf(t, p, sandboxsetup.PrereqEnable); st.After != "" {
					t.Fatalf("enable step names %q afterwards", st.After)
				}
				started, err := r.svc.Run(ctx, sandboxbackend.BackendBwrap, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Action: action, Fingerprint: p.Fingerprint}, "dashboard")
				if err != nil {
					t.Fatalf("%s: %v", action, err)
				}
				if started.Note != wantNote {
					t.Fatalf("%s note = %q, want %q", action, started.Note, wantNote)
				}
			}
			if len(asked) != 2 || asked[0] != sandboxbackend.BackendBwrap {
				t.Fatalf("applyLive calls = %v, want one per write", asked)
			}
		})
	}
}

// TestSandboxSetupSettleRules (item 2) is one case per settle row.
func TestSandboxSetupSettleRules(t *testing.T) {
	cases := []struct {
		name      string
		c         sandboxSettleCtx
		checkDone bool
		wantFound string
		wantRule  string
		wantCheck int
	}{
		{"a passive fact present", sandboxSettleCtx{exitOK: true, hasPassive: true, passive: sandboxsetup.Fact{Present: true, Path: "/usr/bin/bwrap"}}, true, "/usr/bin/bwrap", "passive_fact", 0},
		{"a passive fact absent", sandboxSettleCtx{exitOK: true, hasPassive: true}, true, "", "passive_fact", 0},
		{"a failed step runs no check", sandboxSettleCtx{exitOK: false}, true, "", "exit_failed", 0},
		{"a probe-only step the check reads done", sandboxSettleCtx{exitOK: true}, true, "checked", "checked_done", 1},
		{"a probe-only step the check does not read done", sandboxSettleCtx{exitOK: true}, false, "", "checked_not_done", 1},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.wantRule] = true
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := tc.c
			c.checkDone = func() bool { calls++; return tc.checkDone }
			found, rule := sandboxSettleDecision(c)
			if found != tc.wantFound || rule != tc.wantRule || calls != tc.wantCheck {
				t.Fatalf("= (%q, %s, %d checks), want (%q, %s, %d)", found, rule, calls, tc.wantFound, tc.wantRule, tc.wantCheck)
			}
		})
	}
	for _, r := range sandboxSettleRules {
		if !covered[r.name] {
			t.Errorf("settle rule %q has no case", r.name)
		}
	}
}

// sandboxRecordStatus is the latest record status of a sandbox step.
func sandboxRecordStatus(t *testing.T, r *setupRig, name string) toolinstall.Status {
	t.Helper()
	rows, err := r.ledger.SandboxRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Tool == name {
			return toolinstall.Status(row.Status)
		}
	}
	t.Fatalf("no record of %s", name)
	return ""
}

// TestSandboxSetupProbeOnlyStepSettlesFromTheCheck (item 2, O-5): an image
// pull run from a setup terminal settles installed when the row's active
// check, run once after the exit 0, reads the step done; installed_not_found
// when it does not; install_failed with no check after a failed exit. The
// dashboard terminal and the CLI's foreground run settle the same way.
func TestSandboxSetupProbeOnlyStepSettlesFromTheCheck(t *testing.T) {
	cases := []struct {
		name       string
		code       int
		pulled     bool
		want       toolinstall.Status
		wantProbes int
	}{
		{"exit 0 and the check reads the image", 0, true, toolinstall.StatusInstalled, 1},
		{"exit 0 but the check does not read it", 0, false, toolinstall.StatusInstalledNotFound, 1},
		{"a failed pull", 1, false, toolinstall.StatusInstallFailed, 0},
	}
	ctx := context.Background()
	for _, surface := range []string{"dashboard", "cli"} {
		for _, tc := range cases {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				r := ociRigAfterInstall(t)
				checked, err := r.svc.Check(ctx, sandboxbackend.BackendOCIRunc)
				if err != nil {
					t.Fatal(err)
				}
				pull := func() {
					if tc.pulled {
						r.probe = sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictAvailable}
					}
				}
				if surface == "cli" {
					r.svc.o.Spawn = func(context.Context, []string, string) (string, int, error) {
						pull()
						return "", tc.code, nil
					}
				}
				before := 0
				if _, err := r.svc.Run(ctx, sandboxbackend.BackendOCIRunc, dashapi.SandboxSetupRunRequest{Step: "oci-image", Fingerprint: checked.Fingerprint}, surface); err != nil {
					t.Fatalf("run = %v", err)
				}
				if surface == "dashboard" {
					// The setup terminal ends.
					pull()
					before = r.probes
					r.ledger.observeExit("h-1", tc.code)
				} else {
					// The run's own probe (the click's) came before the
					// foreground child; the settle's check after it.
					before = 2
				}
				if got := sandboxRecordStatus(t, r, "oci-image"); got != tc.want {
					t.Fatalf("record = %s, want %s", got, tc.want)
				}
				if got := r.probes - before; got != tc.wantProbes {
					t.Fatalf("probes after the exit = %d, want %d", got, tc.wantProbes)
				}
			})
		}
	}
}

// TestSandboxSetupNextLineRows (item 5, O-3) is one case per Next row: a
// step Observer is running now reads "running now", never "Observer does
// not do this step".
func TestSandboxSetupNextLineRows(t *testing.T) {
	cases := []struct {
		row  string
		st   dashapi.SandboxSetupStep
		want string
	}{
		{"in_flight", dashapi.SandboxSetupStep{Label: "The sandbox image, pulled by digest", State: "in_flight", Class: "terminal"}, "The sandbox image, pulled by digest (running now)"},
		{"command", dashapi.SandboxSetupStep{Prereq: "oci-image", Label: "x", State: "missing", CanRun: true}, "observer sandbox setup run oci-runc --step oci-image"},
		{"not_ours", dashapi.SandboxSetupStep{Label: "Your user can reach Docker's socket", State: "blocked", Class: "never"}, "Your user can reach Docker's socket (Observer does not do this step)"},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.row] = true
		if got := sandboxSetupNextLine(sandboxbackend.BackendOCIRunc, tc.st); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.row, got, tc.want)
		}
	}
	for _, row := range sandboxSetupNextLines {
		if !covered[row.name] {
			t.Errorf("Next row %s has no case", row.name)
		}
	}
}

// TestSandboxSetupUndoRefusalSaysItOnce (item 5, O-4): the CLI's refused
// undo says "does not undo this step now" once, from the refusal's own
// sentence when it has one.
func TestSandboxSetupUndoRefusalSaysItOnce(t *testing.T) {
	for _, reason := range []string{
		"1 live sandboxed run(s) use this backend, so Observer does not undo this step now; end them or wait for them to finish first.",
		"",
	} {
		var out bytes.Buffer
		st := dashapi.SandboxSetupStep{Label: "The backend enabled", UndoRefused: sandboxsetup.UndoRefusedLiveRuns, Reason: reason}
		if got := sandboxSetupDescribeNoUndo(&out, st); got != sandboxSetupExitRefused {
			t.Fatalf("exit = %d", got)
		}
		if n := strings.Count(out.String(), "does not undo this step now"); n != 1 {
			t.Errorf("reason %q: the line says it %d times: %q", reason, n, out.String())
		}
		if !strings.HasPrefix(out.String(), "The backend enabled: refused") {
			t.Errorf("line = %q", out.String())
		}
	}
}

// TestSandboxSetupManagedPinnedDownload (item 8, D-L7-1): on a managed node
// a grounded pinned download never reaches a fetch without a file: the run
// is refused with the mirror sentence before the download seam; with
// from_file it runs, placing that file against the same pin.
func TestSandboxSetupManagedPinnedDownload(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	r.svc.host.snapshot = func(c config.Config) componentstate.Snapshot {
		return componentstate.ResolveGoverned(c.Components, nil, componentstate.Governed{OrgManaged: true})
	}
	var asked []sandboxDownloadRequest
	r.svc.run.download = func(_ context.Context, req sandboxDownloadRequest) (sandboxDownloadResult, error) {
		asked = append(asked, req)
		return sandboxDownloadResult{Path: req.FromFile, SHA256: "deadbeef", Source: sandboxSourceFromFile, Version: "v54", Bytes: 10}, nil
	}
	ctx := context.Background()
	p := r.plan(t, sandboxbackend.BackendCloudHypervisor)
	st := stepOf(t, p, "cloud-hypervisor")
	if !st.CanRun || st.Consent == nil || st.Consent.Source != sandboxsetup.SourceFromFile || !strings.Contains(st.Reason, "mirror") {
		t.Fatalf("managed pinned step = %+v", st)
	}
	req := dashapi.SandboxSetupRunRequest{Step: "cloud-hypervisor", Fingerprint: p.Fingerprint, Consent: st.Consent}
	_, err := r.svc.Run(ctx, sandboxbackend.BackendCloudHypervisor, req, "dashboard")
	if status, code := setupCodeOf(err); status != http.StatusConflict || code != dashapi.SandboxSetupCodeStepNotRunnable || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("run without a file = %d %s %v", status, code, err)
	}
	if len(asked) != 0 {
		t.Fatalf("a run without a file reached the download seam: %+v", asked)
	}
	req.FromFile = "/opt/tools/cloud-hypervisor"
	started, err := r.svc.Run(ctx, sandboxbackend.BackendCloudHypervisor, req, "dashboard")
	if err != nil || started.Kind != dashapi.SandboxSetupStartedOp {
		t.Fatalf("run with from_file = %+v %v", started, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if op, _ := r.svc.Op(ctx, started.OpID); op.Status != string(toolinstall.StatusInstalling) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(asked) != 1 || asked[0].FromFile != req.FromFile || !asked[0].Managed || asked[0].Pin != "cloud-hypervisor" {
		t.Fatalf("download requests = %+v", asked)
	}
}
