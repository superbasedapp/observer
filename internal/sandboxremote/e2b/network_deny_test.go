package e2b

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestCreateRendersPrivateRangeDeny (SBXD-7): on the internet tier the
// table's deny is NewSandboxV2.network.denyOut (SandboxNetworkConfig, with
// no allowOut, which would take precedence) beside allow_internet_access
// true; with no deny the body has no network block; a deny below internet is
// refused before any call. Doc-grounded only (spec/openapi.yml), no live box.
func TestCreateRendersPrivateRangeDeny(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	deny := sandboxremote.PrivateRangeDeny(v, vocab.TierInternet, false).CIDRs
	if len(deny) == 0 {
		t.Fatal("the table gives E2B no deny")
	}
	f := newFakeE2B(t)
	c := f.client(t)
	s := spec()
	s.Tier, s.DenyCIDRs = vocab.TierInternet, deny
	if _, err := c.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	net, _ := f.lastCreate["network"].(map[string]any)
	got, _ := net["denyOut"].([]any)
	if f.lastCreate["allow_internet_access"] != true || len(net) != 1 || len(got) != len(deny) {
		t.Fatalf("create body %v", f.lastCreate)
	}
	for i, d := range deny {
		if got[i] != d {
			t.Errorf("denyOut[%d] = %v, want %s", i, got[i], d)
		}
	}

	s.RunID, s.Labels, s.DenyCIDRs = "run2", map[string]string{sandboxremote.LabelKey: "run2"}, nil
	if _, err := c.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.lastCreate["network"]; ok {
		t.Errorf("no deny asked, a network block sent: %v", f.lastCreate)
	}

	s.RunID, s.Tier, s.DenyCIDRs = "run3", vocab.TierProxyOnly, deny
	if _, err := c.Create(context.Background(), s); !errors.Is(err, sandboxremote.ErrDenyNotRenderable) {
		t.Errorf("a deny below internet: %v", err)
	}
}
