package config

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// TestGuardModePinDecidesThePromptStance pins the operator ruling of
// 2026-11-08 ("it should be based on the enterprise's posture"): when the
// organization's guard.mode pin is in force, the prompt guard follows that
// mode instead of acting on its own (enforce_independent goes false and is
// reported as set by the organization). With no guard.mode pin in force the
// node's own setting stands. One case per row of the decision.
func TestGuardModePinDecidesThePromptStance(t *testing.T) {
	cases := []struct {
		name      string
		toml      string
		sidecar   string
		wantIndep bool
		wantMode  string
		wantKey   bool
	}{
		{
			name:      "no organization posture: the shipped default acts on its own",
			wantIndep: true, wantMode: "observe",
		},
		{
			name:      "org pins observe: the prompt guard follows observe",
			sidecar:   `{"schema":1,"state":"applied","pinned":{"guard.mode":"observe"}}`,
			wantIndep: false, wantMode: "observe", wantKey: true,
		},
		{
			name:      "org pins enforce: the prompt guard acts through the mode",
			sidecar:   `{"schema":1,"state":"applied","pinned":{"guard.mode":"enforce"}}`,
			wantIndep: false, wantMode: "enforce", wantKey: true,
		},
		{
			name:      "the org's mode replaces a developer's own independent prompt guard",
			toml:      "[guard.prompt]\nenforce_independent = true\n",
			sidecar:   `{"schema":1,"state":"applied","pinned":{"guard.mode":"observe"}}`,
			wantIndep: false, wantMode: "observe", wantKey: true,
		},
		{
			name:      "a pin without guard.mode leaves the node's own setting",
			sidecar:   `{"schema":1,"state":"applied","pinned":{"guard.enabled":true}}`,
			wantIndep: true, wantMode: "observe",
		},
		{
			name:      "a skipped guard.mode pin leaves the node's own setting",
			sidecar:   `{"schema":1,"state":"applied","pinned":{"guard.mode":"strict"}}`,
			wantIndep: true, wantMode: "observe",
		},
		{
			name:      "the developer's own follow-observe choice stands without an org pin",
			toml:      "[guard.prompt]\nenforce_independent = false\n",
			wantIndep: false, wantMode: "observe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbDir := t.TempDir()
			cfgPath := govTempConfig(t, dbDir, tc.toml)
			if tc.sidecar != "" {
				govWriteSidecar(t, dbDir, tc.sidecar)
			}
			cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
			if err != nil {
				t.Fatalf("LoadGovernance: %v", err)
			}
			if got := cfg.Guard.Prompt.EnforceIndependent; got != tc.wantIndep {
				t.Fatalf("enforce_independent = %v, want %v (applied %v, skipped %v)", got, tc.wantIndep, out.Applied, out.Skipped)
			}
			if cfg.Guard.Mode != tc.wantMode {
				t.Fatalf("guard.mode = %q, want %q", cfg.Guard.Mode, tc.wantMode)
			}
			if got := slices.Contains(out.Applied, "guard.prompt.enforce_independent"); got != tc.wantKey {
				t.Fatalf("applied %v: reports enforce_independent as the org's = %v, want %v", out.Applied, got, tc.wantKey)
			}
		})
	}
}

// TestOrgStoppingPromptPinKeepsThePromptGuardActing: under an org-pinned
// observe, an org prompt rule that can stop a prompt still makes the prompt
// lane act. The guard floor (applied after the pin overlay) raises
// enforce_independent back to true and records that it did.
func TestOrgStoppingPromptPinKeepsThePromptGuardActing(t *testing.T) {
	f := newFloorFixture(t, "")
	if err := os.WriteFile(f.sidecarPath, []byte(`{"schema":1,"state":"applied","pinned":{"guard.mode":"observe"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeLock(t, guardposture.OrgLock{Managed: true, Floor: guardposture.GuardFloor{
		Enabled: true, Mode: guardposture.ModeObserve, PromptEnabled: true, PromptEnforceIndependent: true,
	}})
	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: f.cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	if !slices.Contains(out.Applied, "guard.prompt.enforce_independent") {
		t.Fatalf("applied %v: the guard.mode pin did not set the prompt stance first", out.Applied)
	}
	if !cfg.Guard.Prompt.EnforceIndependent {
		t.Fatal("enforce_independent = false: the org's stopping prompt pin no longer keeps the prompt guard acting")
	}
	if cfg.Guard.Mode != "observe" {
		t.Fatalf("guard.mode = %q, want observe", cfg.Guard.Mode)
	}
	raised := false
	for _, o := range cfg.Guard.Lock.Overridden {
		if strings.HasPrefix(o, "guard.prompt.enforce_independent:") {
			raised = true
		}
	}
	if !raised {
		t.Fatalf("lock record %+v does not name the raise of guard.prompt.enforce_independent", cfg.Guard.Lock)
	}
}
