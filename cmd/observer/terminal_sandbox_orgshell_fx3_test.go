//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestOrgShellCloneRemoteConsent (FX3 item 3, live finding F-L6P4-1): the
// consent a clone-remote launch asks for can be recorded (CLI --clone-url,
// the dashboard's repository field), its scope is exactly the launch's, the
// screen shows the URL in full, and the launch then passes its consent step;
// a project consent does not stand in for it.
func TestOrgShellCloneRemoteConsent(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() { hostedListed.Store(false) })
	const url = "https://git.example.com/acme/app.git"
	cfg := orgShellPublishedConfig()
	cfg.Hosted.OpenShellOrg.LaptopRelay = true
	cfg.AllowRemoteClone = true
	cfg.RemoteAllowedHosts = []string{"git.example.com"}
	cfg.Hosted.OpenShellOrg.Published.CloneRepositories = []string{url}
	d := orgShellFX1Driver(t, cfg)
	d.r.cfg = cfg
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	req := termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: root, WorkspaceSource: string(workspace.SourceCloneRemote), WorkspaceRemote: url}

	// A project consent is not the clone's.
	scr, err := hostedConsentFor(context.Background(), cfg, d.r.observerDir, d.vendor, root, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := hostedSaveConsent(d.r.observerDir, sandboxremote.NewConsent(scr.Facts, "2026-11-05T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(context.Background(), req); err == nil || !strings.Contains(err.Error(), verdictHostedConsentRequired) {
		t.Fatalf("a project consent let a clone-remote launch through: %v", err)
	}

	scr, err = hostedConsentFor(context.Background(), cfg, d.r.observerDir, d.vendor, root, url, "")
	if err != nil {
		t.Fatal(err)
	}
	if scr.Facts.ScopeKey != sandboxremote.RemoteCloneScopeKey(url) {
		t.Fatalf("recorded scope %q, the launch's %q", scr.Facts.ScopeKey, sandboxremote.RemoteCloneScopeKey(url))
	}
	if !slices.ContainsFunc(scr.Lines, func(l sandboxremote.ConsentLine) bool { return strings.Contains(l.Value, url) }) {
		t.Errorf("the screen does not show the URL in full: %+v", scr.Lines)
	}
	if err := hostedSaveConsent(d.r.observerDir, sandboxremote.NewConsent(scr.Facts, "2026-11-05T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(context.Background(), req); err != nil && strings.Contains(err.Error(), "consent") {
		t.Fatalf("the recorded clone consent was not the launch's: %v", err)
	}
	// A URL the launch would refuse cannot be agreed to either.
	if _, err := hostedConsentFor(context.Background(), cfg, d.r.observerDir, d.vendor, root, "https://elsewhere.example.org/x.git", ""); err == nil {
		t.Error("a consent was computed for a host the launch refuses")
	}
	// The dashboard's picker lists the organization's repositories.
	if got := hostedVendorRegs[d.vendor.ID].cloneRepositories(cfg.Hosted); !slices.Equal(got, []string{url}) {
		t.Errorf("clone repositories %v", got)
	}
}

// TestOrgShellStatusAfterRevoke (FX3 item 12, live finding F-L4P5-6): after
// an admin revoke the node's status said "signed in until ..."; a sign-in
// refusal a mint answered after the sign-in now shows as refused, and a
// sign-in saved after the refusal shows signed in again.
func TestOrgShellStatusAfterRevoke(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	var o config.TerminalSandboxHostedOrgShellConfig
	o.Published.Offered = true
	save := func(at time.Time) {
		t.Helper()
		if err := hostedWithState(dir, true, func() error {
			return hostedWriteOwned(orgShellSignInPath(dir), orgShellSignIn{OrgURL: "https://org.example.com", ExpiresAt: now.Add(8 * time.Hour), SignedInAt: at})
		}); err != nil {
			t.Fatal(err)
		}
	}
	save(now.Add(-time.Hour))
	if s := orgShellStatusText(o, dir, now); !strings.Contains(s, "signed in until") {
		t.Fatalf("before the revoke: %s", s)
	}
	orgShellNoteRefusal(dir, &orgclient.OpenShellRefusal{Reason: string(osorg.ReasonSigninRevoked), Rule: "T3-T4"}, now.Add(-10*time.Minute))
	if s := orgShellStatusText(o, dir, now); strings.Contains(s, "signed in until") || !strings.Contains(s, "refused by your organization") {
		t.Fatalf("after the revoke: %s", s)
	}
	// Another refusal (not a sign-in one) is not a revoke.
	orgShellNoteRefusal(dir, &orgclient.OpenShellRefusal{Reason: string(osorg.ReasonQuotaConcurrent)}, now)
	save(now.Add(-5 * time.Minute))
	if s := orgShellStatusText(o, dir, now); !strings.Contains(s, "signed in until") {
		t.Fatalf("after signing in again: %s", s)
	}
}

// TestOrgShellStatusAsksTheOrganization (FX4 fix round 1, F-L4P5-6 still
// present live): after a drain or an admin revoke, with no launch from this
// machine since, the status still said "signed in until ...": FX3's fix
// read only a refusal a launch had cached, and a drain's refusal
// (org_openshell_draining) was not counted. The status now asks the
// organization (one probe mint) when this machine holds an unexpired
// sign-in, and says what it answered.
func TestOrgShellStatusAsksTheOrganization(t *testing.T) {
	now := time.Now()
	var o config.TerminalSandboxHostedOrgShellConfig
	o.Published.Offered = true
	signIn := func(t *testing.T, dir string) {
		t.Helper()
		if err := hostedWithState(dir, true, func() error {
			return hostedWriteOwned(orgShellSignInPath(dir), orgShellSignIn{OrgURL: "https://org.example.com", ExpiresAt: now.Add(8 * time.Hour), SignedInAt: now.Add(-time.Hour)})
		}); err != nil {
			t.Fatal(err)
		}
	}
	refusal := func(r osorg.Reason) func(context.Context) error {
		return func(context.Context) error { return &orgclient.OpenShellRefusal{Reason: string(r), Rule: "T1"} }
	}
	cases := []struct {
		name  string
		probe func(context.Context) error
		want  string
		not   string
	}{
		{"a drain", refusal(osorg.ReasonDraining), "refused by your organization", "signed in until"},
		{"an admin revoke", refusal(osorg.ReasonSigninRevoked), "refused by your organization", "signed in until"},
		{"a disabled member", refusal(osorg.ReasonMemberNotAllowed), "refused by your organization", "signed in until"},
		{"accepted", func(context.Context) error { return nil }, "signed in until", "refused"},
		{"another refusal is not the sign-in's", refusal(osorg.ReasonQuotaConcurrent), "signed in until", "refused"},
		{"no answer", func(context.Context) error { return errors.New("dial tcp: connection refused") }, "sign-in not confirmed now", "refused by"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			signIn(t, dir)
			s := orgShellStatus(context.Background(), o, dir, now, tc.probe)
			if !strings.Contains(s, tc.want) || strings.Contains(s, tc.not) {
				t.Fatalf("status said (want %q, not %q):\n%s", tc.want, tc.not, s)
			}
		})
	}
	// Offline (and not signed in) never asks.
	dir := t.TempDir()
	asked := false
	probe := func(context.Context) error { asked = true; return nil }
	if s := orgShellStatus(context.Background(), o, dir, now, probe); asked || !strings.Contains(s, "not signed in") {
		t.Fatalf("not signed in: asked %v, said %s", asked, s)
	}
	signIn(t, dir)
	if s := orgShellStatus(context.Background(), o, dir, now, nil); !strings.Contains(s, "signed in until") {
		t.Fatalf("offline: %s", s)
	}
	// A refusal cached earlier is cleared by an accepting answer.
	orgShellNoteRefusal(dir, &orgclient.OpenShellRefusal{Reason: string(osorg.ReasonMemberNotAllowed)}, now.Add(-time.Minute))
	if s := orgShellStatus(context.Background(), o, dir, now, probe); !asked || !strings.Contains(s, "signed in until") {
		t.Fatalf("accepted after a refusal: asked %v, said %s", asked, s)
	}
}
