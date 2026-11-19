//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The first-start install (lane UX, item H4): the host helper checks the box
// for each install way's programs right after the box is up and before the
// workspace is uploaded, runs the first way that fits, and refuses in plain
// words when none does.

// hostedOpenCodeInstalls are OpenCode's install ways as Create plans them
// on E2B (both kept, npm first).
func hostedOpenCodeInstalls(t *testing.T) []sandboxremote.InstallChoice {
	t.Helper()
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	got, err := hostedToolDelivery("opencode", "", vocab.TierInternet, v)
	if err != nil || len(got) != 2 {
		t.Fatalf("OpenCode's install ways: %+v %v", got, err)
	}
	return got
}

// withInstallProbe makes the harness box answer the install check with the
// programs it has.
func withInstallProbe(hh *hostedHarness, have ...string) {
	inner := hh.client.execs
	hh.client.execs = func(b *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
		if len(spec.Argv) >= 3 && spec.Argv[0] == "sh" && spec.Argv[2] == sandboxremote.InstallProbeScript {
			var out []string
			for _, p := range spec.Argv[4:] {
				if slices.Contains(have, p) {
					out = append(out, p)
				}
			}
			hh.mu.Lock()
			hh.specs = append(hh.specs, spec)
			hh.mu.Unlock()
			return newFakeProcess(strings.Join(out, "\n")+"\n", 0), nil
		}
		return inner(b, spec)
	}
}

// TestHostedInstallCheckRefusesBeforeUpload: a box with none of what any
// install way needs refuses before a file is written, in plain words.
func TestHostedInstallCheckRefusesBeforeUpload(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorDaytona)
	hh.run.plan.Tool, hh.run.plan.ToolInstalls = "opencode", hostedOpenCodeInstalls(t)
	withInstallProbe(hh, "bash")
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	hh.run.vendor, hh.run.client = v, hh.client
	info, err := hh.client.Create(context.Background(), sandboxremote.BoxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	hh.run.rec.VendorID = info.ID
	err = hh.run.chooseToolInstall(context.Background())
	if err == nil {
		t.Fatal("a box with no installer was accepted")
	}
	msg, tech, _ := strings.Cut(err.Error(), " (technical details: ")
	for _, want := range []string{"OpenCode", "Daytona", "no npm", "curl or tar", "Nothing was uploaded"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "tool_unavailable") || !strings.Contains(tech, "tool_unavailable_in_image") {
		t.Errorf("internal code outside the technical detail: %q", err)
	}
	if n := len(hh.client.boxes[info.ID].files); n != 0 {
		t.Errorf("%d files written before the check", n)
	}
}

// TestHostedInstallFallsBackToTheVendorScript: a box with no npm (the
// Daytona live finding) runs the vendor script, after the upload.
func TestHostedInstallFallsBackToTheVendorScript(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	installs := hostedOpenCodeInstalls(t)
	hh.run.plan.ToolInstalls = installs
	withInstallProbe(hh, "bash", "curl", "tar")
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return hh.guests > 0 && len(hh.ptys) > 0 })
	_, _ = hh.termIn.Write([]byte("exit"))
	select {
	case <-code:
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	calls := strings.Join(hh.client.calls, "|")
	script := "exec " + strings.Join(installs[1].Argv, " ")
	probe := strings.Index(calls, "exec sh -c "+sandboxremote.InstallProbeScript)
	upload := strings.Index(calls, "|write")
	if probe < 0 || !strings.Contains(calls, script) || strings.Contains(calls, "exec "+strings.Join(installs[0].Argv, " ")) {
		t.Fatalf("calls %s", calls)
	}
	if upload < 0 || probe > upload {
		t.Errorf("the install check ran after the upload: %s", calls)
	}
	if strings.Index(calls, script) < probe {
		t.Errorf("the install ran before its check: %s", calls)
	}
}

// TestHostedInstallLegacyPlan: a plan written with the single argv of an
// earlier release still installs, its argv[0] the only need.
func TestHostedInstallLegacyPlan(t *testing.T) {
	got := hostedPlanInstallChoices(hostedPlanFile{ToolInstall: []string{"npm", "install", "-g", "x"}})
	if len(got) != 1 || got[0].Needs[0] != "npm" || got[0].Argv[3] != "x" {
		t.Errorf("legacy plan: %+v", got)
	}
	if got := hostedPlanInstallChoices(hostedPlanFile{}); got != nil {
		t.Errorf("no install: %+v", got)
	}
}
