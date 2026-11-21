//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestDashSecretMaskOutcome: the dashboard's view of the mask is counts and
// closed reason words, with the listed gaps and the ones past the list added,
// and no path leaves the daemon (decision D32).
func TestDashSecretMaskOutcome(t *testing.T) {
	t.Parallel()
	if dashSecretMaskOutcome(nil) != nil {
		t.Fatal("nil in, non-nil out")
	}
	got := dashSecretMaskOutcome(&termsvc.SecretMaskOutcome{
		Masked: 4, Complete: false, GapsDropped: 7,
		Gaps: []termsvc.SecretMaskGap{
			{Path: "/work/a/.env", Reason: "symlink"},
			{Path: "/work/b/.env", Reason: "symlink"},
			{Path: "/work/deep", Reason: "depth_limit"},
		},
	})
	if got == nil || got.Masked != 4 || got.Complete || got.Gaps != 10 || !reflect.DeepEqual(got.Reasons, map[string]int{"symlink": 2, "depth_limit": 1}) {
		t.Fatalf("outcome = %+v", got)
	}
	if clean := dashSecretMaskOutcome(&termsvc.SecretMaskOutcome{Masked: 2, Complete: true}); clean.Reasons != nil || clean.Gaps != 0 || !clean.Complete {
		t.Errorf("a complete outcome = %+v", clean)
	}
	if strings.Contains(strings.ToLower(reflect.TypeOf(*got).String()), "path") {
		t.Error("the dashboard outcome type names a path")
	}
	for i := 0; i < reflect.TypeOf(*got).NumField(); i++ {
		if strings.Contains(strings.ToLower(reflect.TypeOf(*got).Field(i).Name), "path") {
			t.Errorf("field %s carries a path", reflect.TypeOf(*got).Field(i).Name)
		}
	}
}

// TestSandboxBackendListCarriesTheMaskFlag: the probe row's flag is the
// registry's capability, for every row and never by name: the dashboard branches
// on it.
func TestSandboxBackendListCarriesTheMaskFlag(t *testing.T) {
	t.Parallel()
	cfg := config.TerminalSandboxConfig{Enabled: true}
	ok := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: "bwrap", BackendVersion: "0.9.0"}
	list := sandboxBackendList(cfg, ok, []string{"live"}, vocab.TierInternet)
	if len(list) == 0 {
		t.Fatal("no rows")
	}
	masking := 0
	for _, e := range list {
		row, _ := sandboxbackend.Get(e.ID)
		if e.MasksWorkspaceSecrets != row.CanMaskWorkspaceSecrets() {
			t.Errorf("%s: probe flag %v, registry %v", e.ID, e.MasksWorkspaceSecrets, row.CanMaskWorkspaceSecrets())
		}
		if e.MasksWorkspaceSecrets {
			masking++
		}
	}
	if masking != 1 {
		t.Errorf("%d rows can mask, want exactly the one that has a planner", masking)
	}
}
