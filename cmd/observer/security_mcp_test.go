//go:build !sbo_omit_security && !sbo_omit_integration_mcp_server

package main

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secmcp"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secsignal"
)

// TestSecurityMCPToolsGate (security pillar plan section 11.1 C: "the MCP
// tools are absent when the module or MCP is off"): registered while the
// module is active and [security.mcp].tools is on, absent otherwise.
func TestSecurityMCPToolsGate(t *testing.T) {
	cfg := config.Default()
	// The module active: by default, or selected where this edition leaves
	// it inert with no block (managed).
	selectIfInactive(t, &cfg, "security")
	if got := securityMCPTools(cfg, nil, nil); len(got) != 2 {
		t.Fatalf("module active, tools on: %d tools, want 2", len(got))
	}
	off := cfg
	off.Security.MCP.Tools = false
	if got := securityMCPTools(off, nil, nil); len(got) != 0 {
		t.Fatalf("tools off: %d tools", len(got))
	}
	minimal := cfg
	minimal.Components = config.ComponentsConfig{Distro: "minimal"}
	if got := securityMCPTools(minimal, nil, nil); len(got) != 0 {
		t.Fatalf("module not selected: %d tools", len(got))
	}
}

// TestSecurityMCPEnrichment pins the honest shape of reach, kev and epss on
// the MCP answer: unavailable KEV data is omitted (never "not listed"), an
// unscored finding carries no epss, and the reach token is the tier's.
func TestSecurityMCPEnrichment(t *testing.T) {
	imported := secreach.Tier{Level: secreach.Imported, Source: secreach.SourceGoImports}
	score := &secexploit.Score{Score: 0.944, ScoreMilli: 944, PercentileMilli: 1000}
	cases := []struct {
		name      string
		sig       secsignal.Signal
		reach     string
		kev       *secmcp.KEV
		epss      bool
		epssValue float64
	}{
		{"nothing known", secsignal.Signal{Reach: secreach.UnknownTier(secreach.ReasonNoAdvisory)}, "unknown", nil, false, 0},
		{"listed and scored", secsignal.Signal{Reach: imported, Exploit: secexploit.Exploit{
			KEVAvailable: true, EPSSAvailable: true, KEV: &secexploit.KEVEntry{CVE: "CVE-2021-44228", DateAdded: "2021-12-10"}, EPSS: score,
		}}, "imported", &secmcp.KEV{Listed: true, DateAdded: "2021-12-10"}, true, 0.944},
		{
			"catalog in date, not listed, not scored",
			secsignal.Signal{Reach: secreach.Tier{Level: secreach.NotImportedDirectly}, Exploit: secexploit.Exploit{KEVAvailable: true, EPSSAvailable: true}},
			"not_imported_directly", &secmcp.KEV{}, false, 0,
		},
		{"KEV unavailable, EPSS scored", secsignal.Signal{Reach: imported, Exploit: secexploit.Exploit{EPSSAvailable: true, EPSS: score}}, "imported", nil, true, 0.944},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := securityMCPEnrichment(tc.sig)
			if got.Reach != tc.reach || !reflect.DeepEqual(got.KEV, tc.kev) || (got.EPSS != nil) != tc.epss || (tc.epss && *got.EPSS != tc.epssValue) {
				t.Fatalf("got %+v (kev %+v)", got, got.KEV)
			}
		})
	}
}
