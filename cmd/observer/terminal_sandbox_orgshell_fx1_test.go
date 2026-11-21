//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// orgShellFX1Driver is the org row's driver with its REAL registration (the
// hooks registerHostedVendor recorded), a signed-in marker and the laptop
// relay opted in, so its probe answers available.
func orgShellFX1Driver(t *testing.T, cfg config.TerminalSandboxConfig) *hostedDriver {
	t.Helper()
	calls := 0
	d := hostedTestDriver(t, sandboxbackend.BackendOpenShellOrg, cfg, &calls)
	real, ok := hostedVendorRegs[sandboxremote.VendorOpenShellOrg]
	if !ok {
		t.Fatal("the org row is not registered")
	}
	newClient := d.reg.newClient
	d.reg = real
	d.reg.newClient = newClient
	d.homeRelayOK, d.homeKey.OrgRoute = true, true
	if err := hostedWithState(d.r.observerDir, true, func() error {
		return hostedWriteOwned(orgShellSignInPath(d.r.observerDir), orgShellSignIn{OrgURL: "https://org.example.com", ExpiresAt: time.Now().Add(time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestOrgShellProbeVersionIsAuthenticatedFromTheSignedBody (FX1 item 1,
// live finding F-L3-5): the openshell-org row pins
// RequireAuthenticatedVersion, and its version comes from the org's SIGNED
// managed body (Published, composed only from a verified body). The probe
// carries that version as authenticated, so selection rule S2b no longer
// refuses every launch backend_version_untested. A config without a verified
// body (Offered false) never authenticates a version.
func TestOrgShellProbeVersionIsAuthenticatedFromTheSignedBody(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() { hostedListed.Store(false) })
	cases := []struct {
		name     string
		change   func(*config.TerminalSandboxConfig)
		wantAuth bool
		wantVer  string
	}{
		{"signed body", func(*config.TerminalSandboxConfig) {}, true, "0.1.6"},
		{"no signed body", func(c *config.TerminalSandboxConfig) {
			c.Hosted.OpenShellOrg.Published.Offered = false
		}, false, ""},
		{"signed body without a version", func(c *config.TerminalSandboxConfig) {
			c.Hosted.OpenShellOrg.Published.Version = ""
		}, false, ""},
	}
	for _, tc := range cases {
		cfg := orgShellPublishedConfig()
		cfg.Hosted.OpenShellOrg.LaptopRelay = true
		tc.change(&cfg)
		d := orgShellFX1Driver(t, cfg)
		p := d.probe(context.Background())
		if p.VersionAuthenticated != tc.wantAuth {
			t.Errorf("%s: VersionAuthenticated %v, want %v (verdict %s)", tc.name, p.VersionAuthenticated, tc.wantAuth, p.Verdict)
		}
		if tc.wantVer != "" && p.Version != tc.wantVer {
			t.Errorf("%s: version %q, want %q", tc.name, p.Version, tc.wantVer)
		}
		if !tc.wantAuth {
			continue
		}
		if p.Verdict != sandboxselect.VerdictAvailable {
			t.Fatalf("%s: probe %s %s", tc.name, p.Verdict, p.Reason)
		}
		res := sandboxselect.Select(sandboxselect.Input{
			Request: sandboxselect.Request{Backend: sandboxbackend.BackendOpenShellOrg, Tier: vocab.TierProxyOnly, Custody: vocab.CustodyHomeRelay},
			Host:    sandboxbackend.HostLinux,
			Enabled: cfg.Backends,
			Probes:  map[string]sandboxselect.Probe{sandboxbackend.BackendOpenShellOrg: p},
		})
		for _, drop := range res.Drops {
			if drop.Rule == "S2b" {
				t.Errorf("%s: selection still refuses at S2b: %s %s", tc.name, drop.Verdict, drop.Reason)
			}
		}
	}
}

// TestHostedRowsPinningAnAuthenticatedVersionHaveASource (FX1 item 1): every
// registered hosted vendor whose registry row pins
// RequireAuthenticatedVersion registers an authenticated version source;
// without one, S2b refuses every launch of that row. E2B, Modal and Vercel
// do not pin the flag (their version is the client contract's own), so they
// need none.
func TestHostedRowsPinningAnAuthenticatedVersionHaveASource(t *testing.T) {
	for id, reg := range hostedVendorRegs {
		row, ok := sandboxbackend.Get(id)
		if !ok {
			t.Errorf("%s: registered but not in the registry", id)
			continue
		}
		if row.Control.Pins.RequireAuthenticatedVersion && reg.authVersion == nil {
			t.Errorf("%s: the row pins RequireAuthenticatedVersion but its driver registers no authenticated version source", id)
		}
	}
}

// orgShellFX1Body is a valid managed sandbox body whose org_openshell field
// publishes the org gateway.
func orgShellFX1Body(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(orgcontract.SandboxManagedPolicyV1{
		Schema: orgcontract.SandboxManagedSchema,
		OrgOpenShell: &orgcontract.SandboxManagedOrgOpenShellV1{
			FrontURL: "https://sandbox.example.com", GatewayID: "gw1", Issuer: "https://org.example.com/openshell", Version: "0.1.6",
			Image: "registry.example.com/box@sha256:" + strings.Repeat("0", 64), IsoClass: "container", Region: "eu-west",
			Tiers: []string{"proxy_only"}, BoxBinary: "upload", LaptopRelay: "allowed", HoldPolicy: "on_disconnect",
			MaxHoldHours: 24, ReturnToNode: true, MaxRunMinutes: 120,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// orgShellRowVerdict is the openshell-org row as a probe answer renders it
// (the New Terminal picker's row on the daemon, the CLI's refusal source).
func orgShellRowVerdict(t *testing.T, rt *sandboxRuntime) (bool, string) {
	t.Helper()
	av := rt.ProbeSandbox(context.Background())
	for _, b := range av.Backends {
		if b.ID == sandboxbackend.BackendOpenShellOrg {
			return b.Available, b.Verdict
		}
	}
	t.Fatalf("no openshell-org row in %+v", av.Backends)
	return false, ""
}

// TestOrgShellDaemonAndCLIComposeTheSameRow (FX1 item 2, live finding
// F-L3-1): with a managed body in force that publishes the org gateway, the
// daemon's runtime (the holder's reload, behind GET /api/terminal/sandbox
// and POST /api/terminal/launch) and the CLI launch's runtime build their
// drivers from the same composed block, so the row's verdict is the same on
// both and is never org_gateway_not_offered.
func TestOrgShellDaemonAndCLIComposeTheSameRow(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() {
		hostedListed.Store(false)
		processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	})
	full := config.Default()
	full.Components.Add = append(full.Components.Add, orgShellComponent)
	full.Terminal.Sandbox = hostedTestConfig(sandboxbackend.BackendOpenShellOrg)
	full.Terminal.Sandbox.Hosted.OpenShellOrg.LaptopRelay = true
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 2, ExpiresAt: time.Now().Add(time.Hour).Unix(), Body: orgShellFX1Body(t)})
	eff := effectiveSandboxConfig(full)
	if !eff.Hosted.OpenShellOrg.Published.Offered {
		t.Fatal("the composed block does not publish the org gateway; the fixture body is wrong")
	}
	dir := t.TempDir()
	// The daemon path.
	h := &sandboxHolder{observerDir: dir, observerBin: "/usr/local/bin/observer"}
	h.reload(full)
	if msg := h.initErr.Load(); msg != nil {
		t.Fatalf("daemon runtime: %s", *msg)
	}
	daemon := h.rt.Load()
	if daemon == nil {
		t.Fatal("no daemon runtime")
	}
	// The CLI path: the composed block written into the config, then the
	// same builder runSandboxCLI calls.
	cliCfg := full
	cliCfg.Terminal.Sandbox = eff
	cli, err := newComposedSandboxRuntime(cliCfg, cliCfg.Terminal.Sandbox, false, dir, "/usr/local/bin/observer", nil)
	if err != nil {
		t.Fatal(err)
	}
	dOK, dVerdict := orgShellRowVerdict(t, daemon)
	cOK, cVerdict := orgShellRowVerdict(t, cli)
	t.Logf("daemon available %v %q, CLI available %v %q", dOK, dVerdict, cOK, cVerdict)
	if dVerdict == verdictModuleInactive {
		t.Fatal("the org row component is not active in the fixture")
	}
	if dVerdict == osorg.VerdictNotOffered {
		t.Errorf("the daemon's row answers %s although the in-force body publishes the gateway", dVerdict)
	}
	if dOK != cOK || dVerdict != cVerdict {
		t.Errorf("daemon (available %v, %q) and CLI (available %v, %q) disagree", dOK, dVerdict, cOK, cVerdict)
	}
}

// TestOrgShellNotOfferedSaysEnforceSandboxIsMissing (FX1 item 7, live
// finding F-B2): on a managed node whose enrolment grant does not hold
// enforce.sandbox, the daemon's composed block records that, and the row's
// not-offered reason says the sandbox body is not applied for that reason.
func TestOrgShellNotOfferedSaysEnforceSandboxIsMissing(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() {
		hostedListed.Store(false)
		processSandboxManaged.bindGovernance(nil)
	})
	full := config.Default()
	full.Terminal.Sandbox = hostedTestConfig(sandboxbackend.BackendOpenShellOrg)
	for _, tc := range []struct {
		name      string
		authority []string
		want      bool
	}{
		{"managed without enforce.sandbox", []string{"extract.managed"}, true},
		{"managed with enforce.sandbox", []string{"extract.managed", "enforce.sandbox"}, false},
	} {
		processSandboxManaged.bindGovernance(fixedGov{govern.Effective{Active: true, Managed: true, Authority: tc.authority}})
		eff := effectiveSandboxConfig(full)
		if got := eff.Hosted.OpenShellOrg.Published.SandboxAuthorityMissing; got != tc.want {
			t.Errorf("%s: SandboxAuthorityMissing %v, want %v", tc.name, got, tc.want)
		}
		d := orgShellFX1Driver(t, eff)
		p := d.probe(context.Background())
		if p.Verdict != osorg.VerdictNotOffered {
			t.Fatalf("%s: verdict %s", tc.name, p.Verdict)
		}
		if strings.Contains(p.Reason, "does not hold enforce.sandbox") != tc.want {
			t.Errorf("%s: reason %q", tc.name, p.Reason)
		}
	}
}

// TestSandboxCLIRefusalDropsAnotherRowsReason (FX1 item 8, live finding
// F-L3-4): a named row's refusal carries its own verdict and reason, not the
// overall answer's reason when that is about another row (the legacy bwrap
// probe's uid-map refusal on the G-L3 VMs). The overall reason is kept when
// it speaks about the named row too (the per-platform list of every row,
// pinned by TestSandboxCLIRefusalNamesTheRequestedRow).
func TestSandboxCLIRefusalDropsAnotherRowsReason(t *testing.T) {
	av := dashapi.SandboxAvailability{
		Backend: sandboxbackend.BackendBwrap, Verdict: "userns_blocked",
		Reason: "bwrap created a user namespace but could not write its uid map (exit 1): a container runtime or a security module forbids it here",
		Backends: []dashapi.SandboxBackendAvail{
			{ID: sandboxbackend.BackendBwrap, Verdict: "userns_blocked", Reason: "uid map"},
			{ID: sandboxbackend.BackendOpenShellOrg, Verdict: osorg.VerdictLaptopRelayNoOptIn, Reason: "opt in first"},
		},
	}
	got := sandboxCLIRefusal(sandboxbackend.BackendOpenShellOrg, true, av)
	if got != "openshell-org is not available here ("+osorg.VerdictLaptopRelayNoOptIn+"): opt in first" {
		t.Fatalf("refusal %q", got)
	}
	// The list of every row (a structured flag, FX1-A4) is appended.
	av.ReasonListsRows = true
	if got := sandboxCLIRefusal(sandboxbackend.BackendOpenShellOrg, true, av); !strings.HasSuffix(got, ". "+av.Reason) {
		t.Fatalf("the list of every row was not appended: %q", got)
	}
	// The flag is the overall rules' own: set by platform_rows (no row of
	// this host available), never by answered_here (a row's own answer).
	legacy := sandbox.Availability{Verdict: "userns_blocked", Reason: "uid map", Backend: sandboxbackend.BackendBwrap}
	if got := sandboxPlatformOverall(legacy, av.Backends, sandboxbackend.HostLinux); got.ReasonListsRows {
		t.Errorf("answered_here set the flag: %+v", got)
	}
	rows := []dashapi.SandboxBackendAvail{{ID: sandboxbackend.BackendMXCProcess, Verdict: "backend_missing", Reason: "no MXC"}}
	if got := sandboxPlatformOverall(legacy, rows, sandboxbackend.HostWindows); !got.ReasonListsRows {
		t.Errorf("platform_rows did not set the flag: %+v", got)
	}
}

// TestOrgShellWithdrawnBodyIsNeverAuthenticated (FX1-A5): every shape of a
// body that is not a verified, in-force publication, fed through the
// managed overlay's sink (observe) the way the pull loop feeds it, leaves the
// probe's version unauthenticated and the launch refused: a signed body
// without org_openshell (withdrawal, D-016), InForce false (not
// preauthorized), Version 0 (a stored document that no longer verifies
// against the pinned key) and an expired body. The in-force row is the
// control.
func TestOrgShellWithdrawnBodyIsNeverAuthenticated(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	t.Cleanup(func() {
		hostedListed.Store(false)
		processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	})
	full := config.Default()
	full.Components.Add = append(full.Components.Add, orgShellComponent)
	full.Terminal.Sandbox = hostedTestConfig(sandboxbackend.BackendOpenShellOrg)
	full.Terminal.Sandbox.Hosted.OpenShellOrg.LaptopRelay = true
	future, past := time.Now().Add(time.Hour).Unix(), time.Now().Add(-time.Minute).Unix()
	body := orgShellFX1Body(t)
	withdrawn := []byte(`{"schema":"` + orgcontract.SandboxManagedSchema + `"}`)
	cases := []struct {
		name string
		out  orgclient.ManagedPullOutcome
		auth bool
	}{
		{"in force (control)", orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 3, ExpiresAt: future, Body: body}, true},
		{"withdrawn: no org_openshell", orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 4, ExpiresAt: future, Body: withdrawn}, false},
		{"not in force", orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: false, Version: 5, ExpiresAt: future, Body: body}, false},
		{"unverified: version 0", orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 0, ExpiresAt: future, Body: body}, false},
		{"expired", orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 6, ExpiresAt: past, Body: body}, false},
	}
	for _, tc := range cases {
		processSandboxManaged.observe(tc.out)
		eff := effectiveSandboxConfig(full)
		d := orgShellFX1Driver(t, eff)
		p := d.probe(context.Background())
		if p.VersionAuthenticated != tc.auth {
			t.Errorf("%s: VersionAuthenticated %v, want %v (%s %s)", tc.name, p.VersionAuthenticated, tc.auth, p.Verdict, p.Reason)
		}
		res := sandboxselect.Select(sandboxselect.Input{
			Request: sandboxselect.Request{Backend: sandboxbackend.BackendOpenShellOrg, Tier: vocab.TierProxyOnly, Custody: vocab.CustodyHomeRelay},
			Host:    sandboxbackend.HostLinux, Enabled: eff.Backends,
			Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendOpenShellOrg: p},
		})
		if !tc.auth && res.Chosen != nil {
			t.Errorf("%s: the launch was not refused", tc.name)
		}
		for _, drop := range res.Drops {
			if tc.auth && drop.Rule == "S2b" {
				t.Errorf("%s: the in-force body still refuses at S2b", tc.name)
			}
		}
	}
}
