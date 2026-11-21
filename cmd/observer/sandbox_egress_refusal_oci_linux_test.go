//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_egress_refusal_oci_linux_test.go is the OCI half of the egress
// refusal tests: it drives the OCI install gateway (ociStartInstallGateway,
// newOCITestTerm), which an sbo_omit_terminals_sandbox_oci build leaves out,
// so it carries the OCI driver's constraint. The shared helpers
// (refusalDaemon, refusedThroughGateway, waitForRefusal) stay in
// sandbox_egress_refusal_linux_test.go.

// TestOCIInstallGatewayRefusalsLand (F-009, audit finding N1-A11): the
// first-start install step's gateway reports its refusals over the run's
// real link into the table, under the install list's own key, so the
// owner is never offered to add the host to their own list.
func TestOCIInstallGatewayRefusalsLand(t *testing.T) {
	obs := relayShortDir(t)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "InStAlLrUnInStAlLrUn01", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}, ProjectRoot: "/p/install"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	st := refusalDaemon(t, obs)
	tt := newOCITestTerm()
	stop, dir, err := ociStartInstallGateway(context.Background(), &ociInstallStep{Hosts: []string{"registry.npmjs.org"}}, tt.term, obs, rec.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	body := refusedThroughGateway(t, dir, "evil.example.com:443")
	if body.Rule != string(sandboxnet.RefusalAllowListMiss) || body.Key != sandboxnet.KeyInstallHosts {
		t.Fatalf("403 body %+v", body)
	}
	// The next step never sends the user to their own host list (audit
	// finding FU5-A3).
	if body.NextStep != sandboxnet.NextStepFor(sandboxnet.RefusalAllowListMiss, sandboxnet.KeyInstallHosts) || strings.Contains(body.NextStep, sandboxnet.KeyEgressAllowHosts) {
		t.Fatalf("next_step %q", body.NextStep)
	}
	var rows []store.SandboxEgressRefusal
	waitForRefusal(t, func() bool {
		rows, _ = st.ListSandboxEgressRefusalsByRun(context.Background(), rec.RunID, 0, 0)
		return len(rows) == 1
	})
	if r := rows[0]; r.Host != "evil.example.com" || r.Key != sandboxnet.KeyInstallHosts || r.ProjectRoot != "/p/install" {
		t.Fatalf("row %+v", r)
	}
}
