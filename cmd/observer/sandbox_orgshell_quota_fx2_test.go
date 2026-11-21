//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestConsentNamesBothDailyQuantities (G-L3 rerun copy finding): the
// consent screen said "today's 240 box-minutes" (this machine's own cap)
// while the org's approve page said 480 a day (the org's per-member
// quota). The consent screen now names the machine's cap as the
// machine's, and adds the org's quota in the approve page's wording, for
// a row whose endpoint only an organization publishes. One case per row.
func TestConsentNamesBothDailyQuantities(t *testing.T) {
	org, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	facts := sandboxremote.ConsentFacts{Provider: org.ID, Region: "eu", MaxRunMinutes: 60, DailyBoxMinutes: 240}
	for _, tc := range []struct {
		name      string
		v         sandboxremote.Vendor
		perMember int
		want      string // "" no org line
	}{
		{"the org row with a published quota", org, 480, vocab.OrgDailyBoxMinutesPhrase(480)},
		{"the org row whose body names none", org, 0, ""},
		{"a vendor row (no organization)", e2b, 480, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := facts
			f.Provider = tc.v.ID
			scr := sandboxremote.BuildConsentScreen(tc.v, f, sandboxremote.Manifest{Root: "/w"}, tc.v.EstimateCost(60))
			hostedApplyOrgQuota(&scr, tc.v, tc.perMember)
			var spend, quota int = -1, -1
			for i, l := range scr.Lines {
				switch l.Label {
				case "Spend cap":
					spend = i
					if !strings.Contains(l.Value, "this machine's own cap of 240 box-minutes a day") || strings.Contains(l.Value, "today's 240") {
						t.Fatalf("the spend cap does not name the machine's cap: %q", l.Value)
					}
				case "Organization quota":
					quota = i
					if !strings.Contains(l.Value, tc.want) {
						t.Fatalf("org line %q, want %q", l.Value, tc.want)
					}
				}
			}
			if tc.want == "" {
				if quota != -1 {
					t.Fatalf("an org quota line where none applies: %+v", scr.Lines)
				}
				return
			}
			if spend < 0 || quota != spend+1 {
				t.Fatalf("the org quota is not under the spend cap: %+v", scr.Lines)
			}
		})
	}
}

// TestOrgShellComposeCarriesTheDailyQuota: the verified body's
// quota_summary reaches the published facts the consent screen reads.
func TestOrgShellComposeCarriesTheDailyQuota(t *testing.T) {
	o := &orgcontract.SandboxManagedOrgOpenShellV1{
		FrontURL: "https://sandbox.example.com", FrontTLSSPKISHA256: "ab", Region: "eu-west",
		QuotaSummary: orgcontract.SandboxOrgOpenShellQuotaV1{DailyBoxMinutesPerMember: 480},
	}
	var dst config.TerminalSandboxConfig
	if set, why := sandboxManagedComposePublished(&dst, orgcontract.SandboxManagedPolicyV1{OrgOpenShell: o}, sandboxManagedEnv{}); !set || why != "" {
		t.Fatalf("not composed: %q", why)
	}
	if got := dst.Hosted.OpenShellOrg.Published.DailyBoxMinutesPerMember; got != 480 {
		t.Fatalf("daily quota %d", got)
	}
}
