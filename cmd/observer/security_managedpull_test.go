//go:build !sbo_omit_security

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

func withSecurityManaged(t *testing.T, o orgclient.ManagedPullOutcome) securityManagedState {
	t.Helper()
	prev := securityManagedCurrent()
	t.Cleanup(func() {
		secManaged.mu.Lock()
		secManaged.cur = prev
		secManaged.mu.Unlock()
	})
	return applySecurityManagedPull(o)
}

// TestDecideSecurityManagedPull: the body applies only in force; a body the
// closed decoder refuses (a credential field, git hooks) never applies.
func TestDecideSecurityManagedPull(t *testing.T) {
	cases := []struct {
		name       string
		o          orgclient.ManagedPullOutcome
		wantPolicy bool
		wantRefuse string
	}{
		{"inert: no authority", orgclient.ManagedPullOutcome{InForce: false, Version: 1, Body: []byte(`{"version":1,"components":["security.deps"]}`)}, false, ""},
		{"in force", orgclient.ManagedPullOutcome{InForce: true, Version: 2, Body: []byte(`{"version":1,"components":["security.deps"]}`)}, true, ""},
		{"in force, empty", orgclient.ManagedPullOutcome{InForce: true, Version: 3, Body: []byte(`{}`)}, false, ""},
		{"credential refused", orgclient.ManagedPullOutcome{InForce: true, Version: 4, Body: []byte(`{"version":1,"token":"x"}`)}, false, "unknown field"},
		{"git hooks refused", orgclient.ManagedPullOutcome{InForce: true, Version: 5, Body: []byte(`{"version":1,"components":["security.githooks"]}`)}, false, "components"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := decideSecurityManagedPull(c.o)
			if (st.Policy != nil) != c.wantPolicy {
				t.Fatalf("policy = %v, want %v", st.Policy, c.wantPolicy)
			}
			if c.wantRefuse == "" && st.Refused != "" || c.wantRefuse != "" && !strings.Contains(st.Refused, c.wantRefuse) {
				t.Fatalf("refused = %q, want %q", st.Refused, c.wantRefuse)
			}
		})
	}
}

// TestSecurityManagedOnlineWaitsForDisclosure: the pull never switches the
// online check on before the disclosure was shown on this node.
func TestSecurityManagedOnlineWaitsForDisclosure(t *testing.T) {
	withSecurityManaged(t, orgclient.ManagedPullOutcome{InForce: true, Version: 1, Body: []byte(`{"version":1,"online_checks":"on"}`)})
	off := config.DefaultSecurityConfig()
	off.Deps.Online = false
	if securityManagedOverlay(off, false).Deps.Online {
		t.Fatal("online switched on before the disclosure was shown")
	}
	if !securityManagedOverlay(off, true).Deps.Online {
		t.Fatal("online not switched on after the disclosure")
	}
	lines := strings.Join(securityManagedKeyLines(securityManagedCurrent().Policy, false, func(string) bool { return true }), "\n")
	// Before the disclosure the key does nothing and says why; after it,
	// the checks go to the org relay only (lane SEC-E4).
	if !strings.Contains(lines, "online_checks = on: not_applicable: disclosure_not_shown") || strings.Contains(lines, "online_checks = on: applied") {
		t.Fatalf("status before the disclosure: %s", lines)
	}
	lines = strings.Join(securityManagedKeyLines(securityManagedCurrent().Policy, true, func(string) bool { return true }), "\n")
	// Since lane SEC-H2 the dependency scanners' online matching goes to the
	// org relay too, and the line says both paths and that no public host
	// is reached.
	if !strings.Contains(lines, "online_checks = on: applied to the install gate and the dependency scanners' online matching") ||
		!strings.Contains(lines, "org relay only, never to a public host") {
		t.Fatalf("status after the disclosure must name both relayed paths: %s", lines)
	}
}

// TestSecurityManagedPrivacyFloorWins: allow.online_checks = forbidden (a
// floor) beats the pull's online_checks = on.
func TestSecurityManagedPrivacyFloorWins(t *testing.T) {
	withSecurityScanningNode(t, true, config.DefaultSecurityConfig(), "security.deps")
	secScanning.mu.Lock()
	load := secScanning.load
	secScanning.load = func(ctx context.Context) (securityScanningBase, error) {
		b, err := load(ctx)
		b.Disclosure = true
		return b, err
	}
	secScanning.mu.Unlock()
	withSecurityManaged(t, orgclient.ManagedPullOutcome{InForce: true, Version: 1, Body: []byte(`{"version":1,"online_checks":"on"}`)})
	off := config.DefaultSecurityConfig()
	off.Deps.Online = false
	if !securityFloorsApplied(off).Deps.Online {
		t.Fatal("the pull alone must switch online on (disclosure shown)")
	}
	installFloor(t, `{"allow":{"online_checks":"forbidden"}}`, 1, true)
	if securityFloorsApplied(off).Deps.Online {
		t.Fatal("the privacy floor must win over the pull")
	}
}

func TestSecurityManagedComponents(t *testing.T) {
	st := decideSecurityManagedPull(orgclient.ManagedPullOutcome{
		InForce: true, Version: 1,
		Body: []byte(`{"version":1,"components":["security.deps","security.trust"],"drivers":["osv","scalibr"]}`),
	})
	got := strings.Join(securityManagedComponents(st.Policy), ",")
	if want := "security.deps,security.scan.osv,security.scan.scalibr,security.trust"; got != want {
		t.Fatalf("components %s, want %s", got, want)
	}
	if securityManagedComponents(nil) != nil {
		t.Fatal("nothing in force switches nothing on")
	}
}
