//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestComposeSandboxManagedBackendsNeverAddExplicitOnly pins lane FU8
// (ledger OSH-45, sweep G-L1): a managed body's backends list may filter an
// ExplicitOnly row the developer listed but never add one they did not.
// One case per row of the rule.
func TestComposeSandboxManagedBackendsNeverAddExplicitOnly(t *testing.T) {
	os, ok := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	if !ok || !os.ExplicitOnly {
		t.Fatal("the openshell row must be ExplicitOnly")
	}
	cases := []struct {
		name     string
		local    []string
		managed  []string
		want     string
		refused  string
		applied  bool
		disabled bool
	}{
		{name: "adds openshell beside bwrap: left off, rest applies", local: []string{"bwrap"}, managed: []string{"openshell", "bwrap"}, want: "bwrap", refused: sandboxRefusedExplicitOnly, applied: true},
		{name: "only openshell, not listed: whole key refused, local list stays", local: []string{"bwrap", "docker"}, managed: []string{"openshell"}, want: "bwrap,docker", refused: sandboxRefusedExplicitOnly},
		{name: "no local list at all", local: nil, managed: []string{"openshell"}, want: "", refused: sandboxRefusedExplicitOnly},
		{name: "listed by the developer: kept", local: []string{"openshell", "bwrap"}, managed: []string{"openshell"}, want: "openshell", applied: true},
		{name: "filters openshell away", local: []string{"openshell", "bwrap"}, managed: []string{"bwrap"}, want: "bwrap", applied: true},
		{name: "plain rows still replace the list", local: []string{"bwrap"}, managed: []string{"docker", "bwrap"}, want: "docker,bwrap", applied: true},
		{name: "empty list still enables nothing", local: []string{"bwrap"}, managed: []string{}, want: "", applied: true, disabled: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local := config.TerminalSandboxConfig{Enabled: true, Backends: c.local}
			managed := append([]string{}, c.managed...)
			body := orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Backends: &managed}
			got, refused := composeSandboxManaged(local, body, sandboxManagedEnv{})
			if s := strings.Join(got.Backends, ","); s != c.want {
				t.Fatalf("backends = %q, want %q", s, c.want)
			}
			if got.Enabled == c.disabled {
				t.Fatalf("enabled = %v", got.Enabled)
			}
			var reason string
			for _, r := range refused {
				if r.Key == "terminal.sandbox.backends" {
					reason = r.Reason
				}
			}
			if reason != c.refused {
				t.Fatalf("refusal = %q, want %q (%+v)", reason, c.refused, refused)
			}
			if slices.Contains(c.local, "openshell") == false && slices.Contains(got.Backends, "openshell") {
				t.Fatal("a managed body added openshell")
			}
			applied := slices.Contains(sandboxManagedApplied(body, sandboxManagedEnv{}, refused), "terminal.sandbox.backends")
			if applied != c.applied {
				t.Fatalf("applied = %v, want %v", applied, c.applied)
			}
		})
	}
}

// TestExplicitOnlyReasonOlderServersDrop pins that the new reason is on
// this build's wire set and that a clamp without it (an older server)
// drops the row rather than storing an unknown reason.
func TestExplicitOnlyReasonOlderServersDrop(t *testing.T) {
	row := orgcontract.SandboxManagedRefusedKeyRow{Key: "backends", Reason: sandboxRefusedExplicitOnly}
	if got := orgcontract.ClampSandboxManagedRefused([]orgcontract.SandboxManagedRefusedKeyRow{row}); len(got) != 1 {
		t.Fatalf("this build must keep the reason: %+v", got)
	}
	old := orgcontract.SandboxNodeRefusalReasons
	t.Cleanup(func() { orgcontract.SandboxNodeRefusalReasons = old })
	orgcontract.SandboxNodeRefusalReasons = slices.DeleteFunc(slices.Clone(old), func(r string) bool { return r == sandboxRefusedExplicitOnly })
	if got := orgcontract.ClampSandboxManagedRefused([]orgcontract.SandboxManagedRefusedKeyRow{row}); len(got) != 0 {
		t.Fatalf("an older server's clamp must drop the row: %+v", got)
	}
}
