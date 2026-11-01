//go:build !sbo_omit_integration_shell_wrap

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// TestAddShellWrapPosture (CLI-1b): one case per reading. Only a node whose
// organization keeps command wrapping on reports shell_wrap_missing, and an
// unreadable state is never read as clean.
func TestAddShellWrapPosture(t *testing.T) {
	maintain := govern.ShellWrapPostureVerdict{Posture: govern.ShellWrapPostureMaintain, Source: govern.ShellWrapPostureSourceAdminOn}
	applied := shellwrap.Status{Enabled: true, Active: true, InSync: true}
	installed := true
	for _, tc := range []struct {
		name    string
		verdict govern.ShellWrapPostureVerdict
		st      shellwrap.Status
		err     error
		missing bool
	}{
		{"maintained and applied", maintain, applied, nil, false},
		{"maintained, not applied", maintain, shellwrap.Status{}, nil, true},
		{"maintained, out of sync", maintain, shellwrap.Status{Enabled: true, Active: true}, nil, true},
		{"maintained, a narrower choice made before the pin", maintain, shellwrap.Status{Enabled: true, Active: true, InSync: true, Tools: []shellwrap.ToolStatus{{Candidate: shellwrap.Candidate{ID: "codex", Kind: integration.LaunchKindTerminal}, Installed: &installed}}}, nil, true},
		{"maintained, state unreadable", maintain, shellwrap.Status{}, errors.New("boom"), true},
		{"developer decides", govern.ShellWrapPostureVerdict{Posture: govern.ShellWrapPostureNone}, shellwrap.Status{}, nil, false},
		{"organization released it", govern.ShellWrapPostureVerdict{Posture: govern.ShellWrapPostureRelease}, shellwrap.Status{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := shellWrapStatus
			shellWrapStatus = func(context.Context, string) (shellwrap.Status, error) { return tc.st, tc.err }
			defer func() { shellWrapStatus = restore }()
			var rep orgcontract.ManagedIntegrityReport
			addShellWrapPosture(context.Background(), tc.verdict, "", &rep)
			got := len(rep.CaptureRisks) == 1 && rep.CaptureRisks[0] == orgcontract.CaptureRiskShellWrapMissing
			if got != tc.missing || (!tc.missing && len(rep.CaptureRisks) != 0) {
				t.Fatalf("risks = %v, want missing %v", rep.CaptureRisks, tc.missing)
			}
		})
	}
}

// TestShellWrapMaintenanceInertOffManagedNodes: the step reads no posture
// on an unmanaged node and writes nothing when the developer decides.
func TestShellWrapMaintenanceInertOffManagedNodes(t *testing.T) {
	asked := 0
	step := newShellWrapMaintenance(filepath.Join(t.TempDir(), "config.toml"), func(context.Context) govern.ShellWrapPostureVerdict {
		asked++
		return govern.ShellWrapPostureVerdict{Posture: govern.ShellWrapPostureNone}
	}, io.Discard, io.Discard)
	if step(context.Background(), false) || asked != 0 {
		t.Fatalf("an unmanaged node ran the step (asked %d)", asked)
	}
	if step(context.Background(), true) || asked != 1 {
		t.Fatalf("an unset posture wrote (asked %d)", asked)
	}
}

// TestWithShellWrapMaintenance: both steps run on one heartbeat and a write
// by either reports a write.
func TestWithShellWrapMaintenance(t *testing.T) {
	var ran []string
	step := func(name string, wrote bool) routeMaintenanceStep {
		return func(context.Context, bool) bool { ran = append(ran, name); return wrote }
	}
	for _, tc := range []struct {
		routes, wrap bool
		want         bool
	}{{false, false, false}, {true, false, true}, {false, true, true}} {
		ran = nil
		if got := withShellWrapMaintenance(step("routes", tc.routes), step("wrap", tc.wrap))(context.Background(), true); got != tc.want {
			t.Errorf("routes %v wrap %v = %v", tc.routes, tc.wrap, got)
		}
		if !reflect.DeepEqual(ran, []string{"routes", "wrap"}) {
			t.Errorf("ran %v", ran)
		}
	}
	if withShellWrapMaintenance(nil, nil) != nil {
		t.Error("no step at all must stay nil")
	}
}

// TestShellWrapOrgMaintainedIndividualNode: a node with no managed org lock
// never opens a database and never refuses the developer.
func TestShellWrapOrgMaintainedIndividualNode(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if shellWrapOrgMaintained(cfg)() {
		t.Fatal("an individual node read as org-maintained")
	}
	if _, err := os.Stat(filepath.Join(dir, "observer.db")); err == nil {
		t.Fatal("the posture check opened a database on an individual node")
	}
}
