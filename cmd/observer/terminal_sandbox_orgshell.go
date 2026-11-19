//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/openshellorg"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// terminal_sandbox_orgshell.go registers the org-hosted OpenShell driver
// (tracker F-019, g1-design.md section 11.4, lane G4) with the shared hosted
// core (terminal_sandbox_hosted*.go): the one place that names the row's
// wire client. Its "vendor" is the organization's own gateway behind its
// validating front; the core reads the vendor row's capability flags
// (MintedCredential, UploadViaExec, BoundedStdin, Deliveries), never this
// row's id. terminal_sandbox_orgshell_omit.go is its twin in a build
// without it.

// orgShellComponent is the driver's component id.
const orgShellComponent = "terminals.sandbox.openshell-org"

func init() {
	// The row's provider table is composed from the verified managed body
	// (sandbox_orgshell_managed.go), never read from a file.
	hostedVendorConfigTable = append(hostedVendorConfigTable, hostedVendorConfigRow{
		vendor: sandboxremote.VendorOpenShellOrg,
		read: func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig {
			return c.OpenShellOrg.Provider
		},
	})
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorOpenShellOrg, component: orgShellComponent,
		newClient: newOrgShellClient,
		// The row's own hooks: the minted run tokens, the local probe rows
		// R0 to R3 with R2b, and the end branch of design 3.2 step 10.
		mintSource: orgShellMintSource, localProbe: orgShellLocalProbe, endRun: orgShellEndRun,
		resumeBox: orgShellResumeTarget, resumeArgs: orgShellResumeArgs,
		cloneSpec: orgShellCloneSpec, runCap: orgShellRunCap,
		// The gateway version from the signed body (F-L3-5).
		authVersion: orgShellAuthVersion,
		// The organization's per-member daily quota, for the consent screen.
		dailyQuota: orgShellDailyQuota,
		// The repositories the organization lets this member clone in a box,
		// for the clone-remote consent picker (FX3 item 3).
		cloneRepositories: orgShellCloneRepositories,
	})
}

// orgShellCloneRepositories are the clone_repositories of the verified body
// (none while no body is in force).
func orgShellCloneRepositories(c config.TerminalSandboxHostedConfig) []string {
	if !c.OpenShellOrg.Published.Offered {
		return nil
	}
	return append([]string(nil), c.OpenShellOrg.Published.CloneRepositories...)
}

// orgShellDailyQuota is the organization's daily_box_minutes_per_member
// from the verified body (0 when the body names none or is not in force).
func orgShellDailyQuota(c config.TerminalSandboxHostedConfig) int {
	if !c.OpenShellOrg.Published.Offered {
		return 0
	}
	return c.OpenShellOrg.Published.DailyBoxMinutesPerMember
}

// orgShellAuthVersion is the row's authenticated version source (FX1 item 1,
// live finding F-L3-5): the gateway version the organization's SIGNED
// managed body publishes. Published is composed only from a verified,
// in-force body (sandbox_orgshell_managed.go; it is never read from a file),
// so Offered with a version is a version read from an authenticated
// identity. Without a verified body, or with no version in it, nothing is
// authenticated and selection rule S2b refuses the row.
func orgShellAuthVersion(d *hostedDriver) (string, bool) {
	p := d.cfg.OpenShellOrg.Published
	if !p.Offered || p.Version == "" {
		return "", false
	}
	return p.Version, true
}

// orgShellRunFacts is what the minted credential source knows about the run
// the wire client needs (the box name the org named at mint, the run id).
type orgShellRunFacts interface {
	BoxName() string
	RunID() string
}

// newOrgShellClient builds the wire client over a minted credential: the
// token source, the org-published front URL and its pin. It dials nothing.
func newOrgShellClient(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
	if cred.Minted == nil {
		return nil, errors.New("the org-hosted row needs a minted run token; sign in with `observer sandbox org-shell login`")
	}
	facts, ok := cred.Minted.(orgShellRunFacts)
	if !ok {
		return nil, errors.New("the org-hosted row's token source names no box")
	}
	return openshellorg.New(openshellorg.Options{
		FrontURL: endpoint, SPKISHA256: cred.SPKISHA256, Source: cred.Minted,
		RunID: facts.RunID(), BoxName: facts.BoxName(),
	})
}

// orgShellProbeFacts are the probe's local facts for the effective org-shell
// block (no network call, no keychain: the sign-in marker only).
func orgShellProbeFacts(o config.TerminalSandboxHostedOrgShellConfig, custody string, observerDir string, now time.Time) osorg.ProbeFacts {
	f := osorg.ProbeFacts{
		Offered: o.Published.Offered, SandboxAuthorityMissing: o.Published.SandboxAuthorityMissing,
		ComponentActive: true, Listed: true, PlatformOK: true, HomeRelayOK: true,
		Custody: custody, LaptopRelay: o.LaptopRelay, OrgLaptopRelay: osorg.LaptopRelay(o.Published.LaptopRelay),
	}
	if s := orgShellLoadSignIn(observerDir); s != nil {
		f.SignedIn = true
		f.SignInExpired = !s.ExpiresAt.After(now)
	}
	return f
}

// orgShellLocalProbe is the row's local probe rows R0 to R3 with R2b
// (design 3.5), walked before the shared hosted ladder.
func orgShellLocalProbe(d *hostedDriver) (string, string) {
	// auto resolves to home_relay on this row, which keeps every key home
	// (decision SBXD-1); an explicit in-box value still meets R2.
	row, _ := sandboxbackend.Get(d.vendor.ID)
	f := orgShellProbeFacts(d.cfg.OpenShellOrg, string(hostedSelectionCustody(vocab.KeyCustody(d.cfg.KeyCustody), row)), d.r.observerDir, d.now())
	f.Listed = d.listed()
	f.PlatformOK = row.RunsOn(sandboxHostKind())
	f.HomeRelayOK = d.homeRelayOK
	_, v, why := osorg.Probe(f)
	return v, why
}

// orgShellLocalVerdict is the local rows an explicit check walks first (the
// driver's own facts are a launch's; the check has the effective block).
func orgShellLocalVerdict(o config.TerminalSandboxHostedOrgShellConfig, observerDir string, _ *store.Enrolment, now time.Time) (string, string) {
	_, v, why := osorg.Probe(orgShellProbeFacts(o, "", observerDir, now))
	return v, why
}

// orgShellMintSource is the host helper's run-token source (design 3.2 step
// 2): it opens the node's org client, reads the grant bound to this
// enrolment, and mints the run's first token (create, or resume for a resume
// launch) with every input the org's compile narrows (G1-R1). No box exists
// before it answers.
func orgShellMintSource(ctx context.Context, plan hostedPlanFile) (sandboxremote.CredentialSource, error) {
	c, enr, cfg, _, err := orgShellOrgClient(ctx)
	if err != nil {
		return nil, err
	}
	// The client stays open for the helper's life: a token is refreshed
	// before its expiry, and the end report is sent through it.
	rec, err := orgShellLoadGrant(filepath.Dir(cfg.Observer.DBPath), enr, time.Now())
	if err != nil {
		return nil, err
	}
	src := plan.Source
	if src == "" {
		src = string(osorg.SourceCloneLocal)
	}
	base := orgclient.OpenShellMintRequest{
		GrantHandle: rec.Handle, RunID: plan.RunID, Tier: plan.Tier, Source: src, CloneURL: plan.CloneURL,
		NodeEgressAllowHosts:   cfg.Terminal.Sandbox.EgressAllowHosts,
		NodeRemoteAllowedHosts: cfg.Terminal.Sandbox.RemoteAllowedHosts,
		LaptopRelay:            cfg.Terminal.Sandbox.Hosted.OpenShellOrg.LaptopRelay,
		BoxRunID:               plan.ResumeBoxRunID,
	}
	first := string(osorg.PurposeCreate)
	if plan.ResumeBoxRunID != "" {
		first = string(osorg.PurposeResume)
	}
	tokens, err := newOrgShellTokens(ctx, c.OpenShellMintToken, base, first, time.Now)
	if err != nil {
		orgShellNoteRefusal(filepath.Dir(cfg.Observer.DBPath), err, time.Now())
		return nil, err
	}
	if f := tokens.First(); !strings.EqualFold(strings.TrimSuffix(f.FrontURL, "/"), strings.TrimSuffix(plan.Endpoint, "/")) {
		return nil, fmt.Errorf("the organization's mint names the front %s, but its published body names %s; launch again once the managed body refreshes", f.FrontURL, plan.Endpoint)
	}
	orgShellRunState.Store(plan.RunID, &orgShellRun{client: c, tokens: tokens, holdOnEnd: cfg.Terminal.Sandbox.Hosted.OpenShellOrg.HoldOnEnd})
	return tokens, nil
}

// orgShellRun is the helper's per-run org-shell state, read by the end
// branch: the org client, the token source and the member's H1 preference.
type orgShellRun struct {
	client    *orgclient.Client
	tokens    *orgShellTokens
	holdOnEnd bool
}

// orgShellRunState maps a run id to its state (one owner: the mint source
// writes it, the end branch reads and removes it).
var orgShellRunState sync.Map

// orgShellCloneSpec is the box-side clone (ruling A1): the org core's
// CloneArgv and CloneEnv, the one owner the mint records and the front
// compares byte for byte, sent as the run's first exec under a create
// token (row F4a admits the clone only with one).
func orgShellCloneSpec(url string) ([]string, map[string]string, string) {
	return osorg.CloneArgv(url), osorg.CloneEnv(), string(osorg.PurposeCreate)
}

// orgShellRunCap is the organization's max_run_minutes from the verified
// body (0 when none is published).
func orgShellRunCap(d *hostedDriver) int {
	return d.cfg.OpenShellOrg.Published.MaxRunMinutes
}
