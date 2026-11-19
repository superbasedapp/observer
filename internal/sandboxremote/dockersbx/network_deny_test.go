package dockersbx

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestCreateRendersPrivateRangeDeny (SBXD-7): on the internet tier the
// table's deny is one inline NetworkPolicy {mode: denyAll, denyNetworks:
// ranges} with no allow rule (the account's own allows still decide the
// rest; deny rules win over allows, live 2026-11-11), IPv6 ranges included;
// with no deny the create sends no inline policy, as before; a ranges deny
// below internet is refused. The deny-only inline shape on an open account
// is doc-grounded plus one account's live smoke, not run with these ranges.
func TestCreateRendersPrivateRangeDeny(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDockerSandboxes)
	deny := sandboxremote.PrivateRangeDeny(v, vocab.TierInternet, false).CIDRs
	if !slices.Contains(deny, "fc00::/7") || !slices.Contains(deny, "169.254.0.0/16") {
		t.Fatalf("the table's Docker deny %v", deny)
	}
	f := newFake(t)
	c := f.client(t)
	s := spec("run-1", vocab.TierInternet)
	s.DenyCIDRs = deny
	if _, err := c.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	b := f.creates[0]
	if len(b.NetworkPolicies) != 1 || b.NetworkPolicies[0].Mode != "denyAll" || !slices.Equal(b.NetworkPolicies[0].DenyNetworks, deny) {
		t.Fatalf("network policies %+v", b.NetworkPolicies)
	}

	f2 := newFake(t)
	if _, err := f2.client(t).Create(context.Background(), spec("run-2", vocab.TierInternet)); err != nil {
		t.Fatal(err)
	}
	if len(f2.creates[0].NetworkPolicies) != 0 {
		t.Errorf("no deny asked, an inline policy sent: %+v", f2.creates[0].NetworkPolicies)
	}

	s = spec("run-3", vocab.TierNone)
	s.DenyCIDRs = deny
	if _, err := c.Create(context.Background(), s); !errors.Is(err, sandboxremote.ErrDenyNotRenderable) {
		t.Errorf("a ranges deny below internet: %v", err)
	}
}
