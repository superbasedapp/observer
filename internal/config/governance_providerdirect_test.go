package config

import (
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestProviderDirectPinRow pins the terminal.sandbox.provider_direct row
// (DEC-9, OBS-8a): a DirFree enum pin the overlay applies in either
// direction, a value outside the closed set skipped, and Validate refusing
// one written to the file.
func TestProviderDirectPinRow(t *testing.T) {
	if got := Default().Terminal.Sandbox.ProviderDirect; got != "" {
		t.Fatalf("default = %q, want empty (capture_rule)", got)
	}
	for _, v := range []string{"refuse_all", "capture_rule", "allow"} {
		got, out := ApplyGovernancePinsTo(Default(), map[string]any{SandboxProviderDirectKey: v})
		if got.Terminal.Sandbox.ProviderDirect != v || len(out.Skipped) != 0 {
			t.Fatalf("pin %q: value %q, skipped %v", v, got.Terminal.Sandbox.ProviderDirect, out.Skipped)
		}
	}
	if _, out := ApplyGovernancePinsTo(Default(), map[string]any{SandboxProviderDirectKey: "block"}); len(out.Skipped) == 0 {
		t.Fatal("an out-of-set pin applied")
	}
	bad := Default()
	bad.Terminal.Sandbox.ProviderDirect = "block"
	if err := validateTerminalSandbox(bad.Terminal.Sandbox); err == nil {
		t.Fatal("Validate accepted an unknown provider_direct")
	}
}

// TestSandboxProviderDirectInForce: one case per rule of the resolver. Only
// an applied pin on a node whose verified org lock records managed tenancy
// takes effect; an individual node and an unpinned managed node keep
// capture_rule, and the local file value is never read.
func TestSandboxProviderDirectInForce(t *testing.T) {
	cfg := func(local string, lock GuardOrgLock) Config {
		c := Default()
		c.Terminal.Sandbox.ProviderDirect = local
		c.Guard.Lock = lock
		return c
	}
	managed := GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true}
	individual := GuardOrgLock{State: "valid", TenancyKnown: true}
	applied := GovernanceOutcome{Applied: []string{SandboxProviderDirectKey}}
	for _, tc := range []struct {
		name string
		cfg  Config
		out  GovernanceOutcome
		want sandboxvocab.ProviderDirect
	}{
		{"managed, pinned allow", cfg("allow", managed), applied, sandboxvocab.ProviderDirectAllow},
		{"managed, pinned refuse_all", cfg("refuse_all", managed), applied, sandboxvocab.ProviderDirectRefuseAll},
		{"managed, local value only is never read", cfg("allow", managed), GovernanceOutcome{Applied: []string{"guard.mode"}}, sandboxvocab.ProviderDirectCaptureRule},
		{"individual, pinned allow keeps capture_rule", cfg("allow", individual), applied, sandboxvocab.ProviderDirectCaptureRule},
		{"no verified tenancy keeps capture_rule", cfg("refuse_all", GuardOrgLock{State: "tampered", Managed: true}), applied, sandboxvocab.ProviderDirectCaptureRule},
		{"a discarded overlay keeps capture_rule", cfg("allow", managed), GovernanceOutcome{Applied: []string{SandboxProviderDirectKey}, Discarded: true}, sandboxvocab.ProviderDirectCaptureRule},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sandboxProviderDirectInForce(tc.cfg, tc.out)
			if sandboxvocab.ProviderDirect(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			c := tc.cfg
			c.Terminal.Sandbox.ProviderDirectInForce = got
			if c.Terminal.Sandbox.EffectiveProviderDirect() != tc.want {
				t.Fatalf("EffectiveProviderDirect = %q", c.Terminal.Sandbox.EffectiveProviderDirect())
			}
		})
	}
	if Default().Terminal.Sandbox.EffectiveProviderDirect() != sandboxvocab.ProviderDirectCaptureRule {
		t.Fatal("the default config does not read capture_rule")
	}
}

// TestProviderDirectLoadGovernanceRoundTrip (audit follow-up 7): the whole
// Load path with the daemon's MAC-signed org lock carrying the governance
// posture, one case per tenancy reading. Only a verified managed lock whose
// posture pins provider_direct puts the pin in force; an individual lock, a
// managed lock without the pin (even with a local file value) and a lock
// that does not verify all read capture_rule.
func TestProviderDirectLoadGovernanceRoundTrip(t *testing.T) {
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"terminal.sandbox.provider_direct":"allow"}}`
	unpinned := `{"schema":1,"state":"applied","effective_hash":"h2","pinned":{"tasks.enabled":true}}`
	for _, tc := range []struct {
		name      string
		localTOML string
		lock      guardposture.OrgLock
		badKey    bool
		want      sandboxvocab.ProviderDirect
	}{
		{"managed, signed pin", "", guardposture.OrgLock{Managed: true, GovernanceKnown: true, Governance: pinned}, false, sandboxvocab.ProviderDirectAllow},
		{"individual, signed pin", "", guardposture.OrgLock{GovernanceKnown: true, Governance: pinned}, false, sandboxvocab.ProviderDirectCaptureRule},
		{"managed, no pin, a local value", "[terminal.sandbox]\nprovider_direct = \"allow\"\n", guardposture.OrgLock{Managed: true, GovernanceKnown: true, Governance: unpinned}, false, sandboxvocab.ProviderDirectCaptureRule},
		{"managed, a lock that does not verify", "", guardposture.OrgLock{Managed: true, GovernanceKnown: true, Governance: pinned}, true, sandboxvocab.ProviderDirectCaptureRule},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, tc.localTOML)
			if err := os.WriteFile(f.sidecarPath, []byte(tc.lock.Governance), 0o600); err != nil {
				t.Fatal(err)
			}
			key := f.key
			if tc.badKey {
				key = append([]byte(nil), f.key...)
				key[0] ^= 0xff
			}
			tc.lock.WrittenAt = time.Now()
			if _, err := guardposture.WriteOrgLock(guardposture.OrgLockPath(f.cfgPath), tc.lock, key); err != nil {
				t.Fatal(err)
			}
			cfg, gout, err := LoadGovernance(LoadOptions{GlobalPath: f.cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Terminal.Sandbox.EffectiveProviderDirect(); got != tc.want {
				t.Fatalf("in force = %q, want %q (lock %+v, applied %v)", got, tc.want, cfg.Guard.Lock, gout.Applied)
			}
		})
	}
}
