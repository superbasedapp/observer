//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

const orgShellSentinelToken = "sbo-run-token-SENTINEL-0000"

// orgShellPublishedConfig is a sandbox config whose verified body publishes
// the org gateway, with the row listed.
func orgShellPublishedConfig() config.TerminalSandboxConfig {
	c := hostedTestConfig(sandboxbackend.BackendOpenShellOrg)
	c.Hosted.OpenShellOrg.Provider = config.TerminalSandboxHostedProviderConfig{Endpoint: "https://sandbox.example.com", OrgPublished: true, Region: "eu-west"}
	c.Hosted.OpenShellOrg.Published = config.TerminalSandboxOrgShellPublished{
		Offered: true, FrontURL: "https://sandbox.example.com", GatewayID: "gw1", Version: "0.1.6", Tiers: []string{"proxy_only"},
		LaptopRelay: "allowed", HoldPolicy: "on_disconnect", MaxHoldHours: 24, ReturnToNode: true, MaxRunMinutes: 120,
	}
	return c
}

// orgShellTestDriver is a hosted driver for the org row with its real hooks
// and a counting client factory and mint source.
func orgShellTestDriver(t *testing.T, cfg config.TerminalSandboxConfig, clientCalls, mintCalls *int) *hostedDriver {
	t.Helper()
	d := hostedTestDriver(t, sandboxbackend.BackendOpenShellOrg, cfg, clientCalls)
	d.reg.localProbe = orgShellLocalProbe
	d.reg.mintSource = func(context.Context, hostedPlanFile) (sandboxremote.CredentialSource, error) {
		*mintCalls++
		return nil, errors.New("no org server in tests")
	}
	d.homeRelayOK, d.homeKey.OrgRoute = true, true
	return d
}

// TestOrgShellNoOrgCallWithoutUserAction extends
// TestHostedNoVendorCallWithoutUserAction to the org row (lane G4, invariant
// I6): the probe and a Create that stops at the consent step never mint a
// token and never build the wire client.
func TestOrgShellNoOrgCallWithoutUserAction(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() { hostedListed.Store(false) })
	clientCalls, mintCalls := 0, 0
	cfg := orgShellPublishedConfig()
	cfg.Hosted.OpenShellOrg.LaptopRelay = true
	d := orgShellTestDriver(t, cfg, &clientCalls, &mintCalls)
	if err := hostedWithState(d.r.observerDir, true, func() error {
		return hostedWriteOwned(orgShellSignInPath(d.r.observerDir), orgShellSignIn{OrgURL: "https://org.example.com", ExpiresAt: time.Now().Add(time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	p := d.probe(context.Background())
	if p.Verdict != "available" {
		t.Fatalf("probe %s %s", p.Verdict, p.Reason)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = d.Create(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: root})
	if err == nil || !strings.Contains(err.Error(), verdictHostedConsentRequired) {
		t.Fatalf("Create did not stop at consent: %v", err)
	}
	if clientCalls != 0 || mintCalls != 0 {
		t.Errorf("a user-less path built the client %d times and minted %d times", clientCalls, mintCalls)
	}
}

// TestOrgShellProbeRows: the row's local verdicts through the driver.
func TestOrgShellProbeRows(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() { hostedListed.Store(false) })
	cases := []struct {
		name   string
		change func(*config.TerminalSandboxConfig)
		signIn bool
		want   string
	}{
		{"not offered", func(c *config.TerminalSandboxConfig) {
			c.Hosted.OpenShellOrg.Published = config.TerminalSandboxOrgShellPublished{}
		}, true, osorg.VerdictNotOffered},
		{"not opted in", func(*config.TerminalSandboxConfig) {}, true, osorg.VerdictLaptopRelayNoOptIn},
		{"forbidden", func(c *config.TerminalSandboxConfig) {
			c.Hosted.OpenShellOrg.LaptopRelay = true
			c.Hosted.OpenShellOrg.Published.LaptopRelay = "forbidden"
		}, true, osorg.VerdictLaptopRelayForbid},
		{"custody", func(c *config.TerminalSandboxConfig) {
			c.Hosted.OpenShellOrg.LaptopRelay = true
			c.Hosted.KeyCustody = "in_box_api_key"
		}, true, osorg.VerdictCustodyNotOffered},
		{"not signed in", func(c *config.TerminalSandboxConfig) { c.Hosted.OpenShellOrg.LaptopRelay = true }, false, osorg.VerdictSigninRequired},
		{"available", func(c *config.TerminalSandboxConfig) { c.Hosted.OpenShellOrg.LaptopRelay = true }, true, "available"},
	}
	for _, tc := range cases {
		cfg := orgShellPublishedConfig()
		tc.change(&cfg)
		a, b := 0, 0
		d := orgShellTestDriver(t, cfg, &a, &b)
		if tc.signIn {
			_ = hostedWithState(d.r.observerDir, true, func() error {
				return hostedWriteOwned(orgShellSignInPath(d.r.observerDir), orgShellSignIn{ExpiresAt: time.Now().Add(time.Hour)})
			})
		}
		if p := d.probe(context.Background()); p.Verdict != tc.want {
			t.Errorf("%s: verdict %s (%s)", tc.name, p.Verdict, p.Reason)
		}
	}
}

// TestOrgShellTokenSource: the first mint names the box, a token is reused
// until 60 s before its expiry, each purpose mints its own, and the source
// never prints a token.
func TestOrgShellTokenSource(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	var minted []string
	mint := func(_ context.Context, r orgclient.OpenShellMintRequest) (orgclient.OpenShellMint, error) {
		minted = append(minted, r.Purpose)
		if r.GrantHandle != "h" || r.RunID != "r1" || (r.Purpose != "resume" && r.BoxRunID != "") {
			return orgclient.OpenShellMint{}, errors.New("bad request")
		}
		return orgclient.OpenShellMint{Token: orgShellSentinelToken + r.Purpose, BoxName: "obsabc", ExpiresAt: now.Add(10 * time.Minute), FrontURL: "https://sandbox.example.com"}, nil
	}
	clock := now
	s, err := newOrgShellTokens(context.Background(), mint, orgclient.OpenShellMintRequest{GrantHandle: "h", RunID: "r1", BoxRunID: "old"}, "create", func() time.Time { return clock })
	if err != nil || s.BoxName() != "obsabc" || s.RunID() != "r1" {
		t.Fatalf("source %v %v", s, err)
	}
	ctx := context.Background()
	if tok, _ := s.Token(sandboxremote.WithTokenPurpose(ctx, "create")); tok != orgShellSentinelToken+"create" {
		t.Errorf("create token %q", tok)
	}
	if tok, _ := s.Token(ctx); tok != orgShellSentinelToken+"attach" {
		t.Errorf("default purpose token %q", tok)
	}
	clock = now.Add(9*time.Minute + 30*time.Second) // inside the 60 s slack
	_, _ = s.Token(ctx)
	if got := strings.Join(minted, ","); got != "create,attach,attach" {
		t.Errorf("mints %s", got)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %s", s, s, s), orgShellSentinelToken) {
		t.Error("the source prints a token")
	}
}

// TestOrgShellGrantCustody: the handle is kept in the keystore only, bound
// to the enrolment; a marker holds no secret; another member's or an expired
// grant is refused.
func TestOrgShellGrantCustody(t *testing.T) {
	keys := &fakeHostedKeys{m: map[string]string{}}
	old := orgShellKeystoreOpen
	orgShellKeystoreOpen = func(string) keystore.Store { return keys }
	t.Cleanup(func() { orgShellKeystoreOpen = old })
	dir := t.TempDir()
	enr := &orgShellTestEnrolment
	if err := orgShellSaveGrant(dir, enr, orgclient.OpenShellGrant{GrantHandle: "sbo-grant-handle-SENTINEL-0000", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(orgShellSignInPath(dir))
	if strings.Contains(string(b), "SENTINEL") {
		t.Error("the marker holds the handle")
	}
	rec, err := orgShellLoadGrant(dir, enr, time.Now())
	if err != nil || rec.Handle != "sbo-grant-handle-SENTINEL-0000" || strings.Contains(rec.String(), "SENTINEL") {
		t.Fatalf("grant %v %v", rec, err)
	}
	other := *enr
	other.UserID = "someone-else"
	if _, err := orgShellLoadGrant(dir, &other, time.Now()); err == nil {
		t.Error("a grant bound to another member was used")
	}
	if _, err := orgShellLoadGrant(dir, enr, time.Now().Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired grant: %v", err)
	}
	if err := orgShellForgetGrant(dir); err != nil || orgShellLoadSignIn(dir) != nil {
		t.Errorf("forget %v", err)
	}
	if _, err := orgShellLoadGrant(dir, enr, time.Now()); !errors.Is(err, errOrgShellSignIn) {
		t.Errorf("after logout: %v", err)
	}
}

var orgShellTestEnrolment = store.Enrolment{OrgServerURL: "https://org.example.com", OrgID: "org-1", UserID: "m-1"}
