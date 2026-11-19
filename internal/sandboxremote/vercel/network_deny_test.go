package vercel

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestCreateRendersPrivateRangeDeny (SBXD-7): on the internet tier the
// table's deny is the policy object the vendor SDK sends to POST
// /v3/sandboxes, {"allow": ["*"], "subnets": {"allow": ["0.0.0.0/0"],
// "deny": ranges}} (subnet denies "take precedence over allowed domains and
// CIDRs"); with no deny it stays mode allow-all; a deny below internet is
// refused. Grounded in the vendor's SDK source only, no live box.
func TestCreateRendersPrivateRangeDeny(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorVercel)
	deny := sandboxremote.PrivateRangeDeny(v, vocab.TierInternet, false).CIDRs
	if len(deny) == 0 {
		t.Fatal("the table gives Vercel no deny")
	}
	f := newFakeVercel(t)
	c := f.client(t)
	if _, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-a", TimeoutSeconds: 600, Tier: vocab.TierInternet, DenyCIDRs: deny}); err != nil {
		t.Fatal(err)
	}
	denyAny := make([]any, len(deny))
	for i, d := range deny {
		denyAny[i] = d
	}
	want := map[string]any{
		"allow":   []any{"*"},
		"subnets": map[string]any{"allow": []any{"0.0.0.0/0"}, "deny": denyAny},
	}
	if got := f.creates[0]["networkPolicy"]; !reflect.DeepEqual(got, want) {
		t.Errorf("networkPolicy %#v, want %#v", got, want)
	}

	if _, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-b", TimeoutSeconds: 600, Tier: vocab.TierInternet}); err != nil {
		t.Fatal(err)
	}
	if got := f.creates[1]["networkPolicy"]; !reflect.DeepEqual(got, map[string]any{"mode": "allow-all"}) {
		t.Errorf("no deny: networkPolicy %#v", got)
	}

	if _, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-c", TimeoutSeconds: 600, Tier: vocab.TierNone, DenyCIDRs: deny}); !errors.Is(err, sandboxremote.ErrDenyNotRenderable) {
		t.Errorf("a deny below internet: %v", err)
	}
}
