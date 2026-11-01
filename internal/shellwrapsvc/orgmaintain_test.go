package shellwrapsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

func (f *fixture) cfg() config.Config {
	f.t.Helper()
	cfg, err := f.svc.loadConfig(f.svc.configPath(f.home))
	if err != nil {
		f.t.Fatal(err)
	}
	return cfg
}

// TestOrgApplyRecordsProvenance (CLI-1b, D6): an organization's apply
// records [shell_wrap].org_applied, a developer's own apply clears it, and a
// release removes only a wrap the organization applied.
func TestOrgApplyRecordsProvenance(t *testing.T) {
	f := newFixture(t)
	f.env["SHELL"] = "/bin/bash"
	id := routedCLI(t).ID
	ctx := context.Background()

	if _, err := f.svc.Apply(ctx, Request{Tools: []string{id}, ByOrganization: true}); err != nil {
		t.Fatal(err)
	}
	if c := f.cfg(); !c.ShellWrap.Enabled || !c.ShellWrap.OrgApplied {
		t.Fatalf("org apply: enabled %v org_applied %v", c.ShellWrap.Enabled, c.ShellWrap.OrgApplied)
	}
	// The developer re-applies: the wrap is now theirs.
	f.apply([]string{id})
	if c := f.cfg(); !c.ShellWrap.Enabled || c.ShellWrap.OrgApplied {
		t.Fatalf("developer apply: enabled %v org_applied %v", c.ShellWrap.Enabled, c.ShellWrap.OrgApplied)
	}
	// A release leaves the developer's wrap alone.
	if _, released, err := f.svc.ReleaseOrganization(ctx); err != nil || released {
		t.Fatalf("release of a developer wrap: released %v err %v", released, err)
	}
	if !f.cfg().ShellWrap.Enabled {
		t.Fatal("the release removed the developer's wrap")
	}
	// Back to an organization wrap, then released.
	if _, err := f.svc.Apply(ctx, Request{Tools: []string{id}, ByOrganization: true}); err != nil {
		t.Fatal(err)
	}
	if _, released, err := f.svc.ReleaseOrganization(ctx); err != nil || !released {
		t.Fatalf("release of the org wrap: released %v err %v", released, err)
	}
	if c := f.cfg(); c.ShellWrap.Enabled || c.ShellWrap.OrgApplied {
		t.Fatalf("after release: enabled %v org_applied %v", c.ShellWrap.Enabled, c.ShellWrap.OrgApplied)
	}
	if st, err := f.svc.Status(ctx); err != nil || st.Active {
		t.Fatalf("after release the wrap is still active: %+v %v", st.Active, err)
	}
}

// TestOrgMaintainedRefusesDeveloperRemoval: while the organization maintains
// the wrap, the developer's disable (and an apply of no tool) is refused;
// the organization's own release, a developer apply that keeps a tool and
// the Windows bridge target are not.
func TestOrgMaintainedRefusesDeveloperRemoval(t *testing.T) {
	f := newFixture(t)
	f.env["SHELL"] = "/bin/bash"
	id := routedCLI(t).ID
	ctx := context.Background()
	f.svc.OrgMaintained = func() bool { return true }

	if _, err := f.svc.Apply(ctx, Request{Tools: []string{id}, ByOrganization: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Disable(ctx, false); !errors.Is(err, ErrOrgMaintained) {
		t.Fatalf("developer disable: %v", err)
	}
	if _, err := f.svc.Apply(ctx, Request{Tools: nil}); !errors.Is(err, ErrOrgMaintained) {
		t.Fatalf("developer apply of no tool: %v", err)
	}
	if !f.cfg().ShellWrap.Enabled {
		t.Fatal("a refused removal changed the recorded choice")
	}
	if !f.svc.orgBlocksRemoval(TargetNative, emptySelection(), true, false) || f.svc.orgBlocksRemoval(TargetWindows, emptySelection(), true, false) {
		t.Fatal("the gate must hold the native target only")
	}
	if _, _, err := f.svc.ReleaseOrganization(ctx); err != nil {
		t.Fatalf("the organization's own release was refused: %v", err)
	}
	f.svc.OrgMaintained = nil
	f.apply([]string{id})
	if _, err := f.svc.Disable(ctx, false); err != nil {
		t.Fatalf("an unmanaged disable was refused: %v", err)
	}
}

func emptySelection() shellwrap.Selection { return shellwrap.Selection{} }

// TestOrgMaintainedRefusesNarrowerApply (audit follow-up 2): while the
// organization maintains the wrap, a developer apply that selects anything
// but AllTools is refused (it would otherwise clear org_applied and read in
// sync, so the narrower wrap would never be put back); an apply of AllTools
// passes.
func TestOrgMaintainedRefusesNarrowerApply(t *testing.T) {
	f := newFixture(t)
	f.env["SHELL"] = "/bin/bash"
	id := routedCLI(t).ID
	ctx := context.Background()
	f.svc.OrgMaintained = func() bool { return true }
	if _, err := f.svc.Apply(ctx, Request{Tools: []string{shellwrap.AllTools}, ByOrganization: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Apply(ctx, Request{Tools: []string{id}}); !errors.Is(err, ErrOrgMaintained) {
		t.Fatalf("a narrower developer apply: %v", err)
	}
	if !f.cfg().ShellWrap.OrgApplied {
		t.Fatal("a refused apply cleared org_applied")
	}
	if _, err := f.svc.Apply(ctx, Request{Tools: []string{shellwrap.AllTools}}); err != nil {
		t.Fatalf("a developer apply of every tool was refused: %v", err)
	}
	if _, err := f.svc.Apply(ctx, Request{Tools: []string{id}, ByOrganization: true}); err != nil {
		t.Fatalf("the organization's own apply was refused: %v", err)
	}
}

// TestOrgSelectionCovered: one case per reading of the organization's
// selection (every installed or unknown CLI row, every detected shell).
func TestOrgSelectionCovered(t *testing.T) {
	yes, no := true, false
	cli := func(selected bool, installed *bool) shellwrap.ToolStatus {
		return shellwrap.ToolStatus{Candidate: shellwrap.Candidate{ID: "x", Kind: integration.LaunchKindTerminal}, Selected: selected, Installed: installed}
	}
	gui := shellwrap.ToolStatus{Candidate: shellwrap.Candidate{ID: "ide", Kind: integration.LaunchKindGUI}}
	for _, tc := range []struct {
		name string
		st   shellwrap.Status
		want bool
	}{
		{"every installed CLI row selected", shellwrap.Status{Tools: []shellwrap.ToolStatus{cli(true, &yes), cli(false, &no), gui}}, true},
		{"an installed CLI row not selected", shellwrap.Status{Tools: []shellwrap.ToolStatus{cli(true, &yes), cli(false, &yes)}}, false},
		{"an unknown-install CLI row not selected", shellwrap.Status{Tools: []shellwrap.ToolStatus{cli(false, nil)}}, false},
		{"a detected shell not planned", shellwrap.Status{DetectedShells: []shellwrap.Shell{"bash", "zsh"}, PlannedShells: []shellwrap.Shell{"bash"}}, false},
		{"every detected shell planned", shellwrap.Status{DetectedShells: []shellwrap.Shell{"bash"}, PlannedShells: []shellwrap.Shell{"bash", "fish"}}, true},
	} {
		if got := OrgSelectionCovered(tc.st); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}
