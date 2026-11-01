package sandboxselect

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestNativeConflictOutcomes is one case per row of conflictOutcomes (lane
// SBX-P3D), on a conflict (N11 on bwrap), plus a forced sandbox that nests.
func TestNativeConflictOutcomes(t *testing.T) {
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	vm := sandboxbackend.Capability{Iso: sandboxbackend.Isolation{Class: vocab.ClassHWVM}, GuestUnprivUserns: true}
	base := NativeSandbox{Present: true, NeedsFreshProc: true}
	with := func(f func(*NativeSandbox)) NativeSandbox { n := base; f(&n); return n }
	cases := []struct {
		name   string
		layer  sandboxbackend.Capability
		n      NativeSandbox
		out    NativeOutcome
		state  vocab.NativeSandboxState
		reason string
	}{
		{"forced, nest_or_refuse", bw, with(func(n *NativeSandbox) {
			n.VendorForced, n.ForcedPolicy, n.PerRunDisable = true, VendorForcedNestOrRefuse, true
		}), NativeRefuse, "", "vendor_forced_native = nest_or_refuse"},
		{"forced, refuse", bw, with(func(n *NativeSandbox) { n.VendorForced, n.ForcedPolicy = true, VendorForcedRefuse }), NativeRefuse, "", "vendor_forced_native = refuse"},
		{"weak when the user turned it on", bw, with(func(n *NativeSandbox) { n.UserOn, n.PerRunWeak, n.PerRunDisable = true, true, true }), NativeWeakMode, vocab.NativeWeak, "weaker nested mode"},
		{"no weak without the user's setting", bw, with(func(n *NativeSandbox) { n.PerRunWeak, n.PerRunDisable = true, true }), NativeDisable, vocab.NativeDisabledByObserver, ""},
		{"disable", bw, with(func(n *NativeSandbox) { n.PerRunDisable = true }), NativeDisable, vocab.NativeDisabledByObserver, ""},
		{"refuse", bw, base, NativeRefuse, "", "no per-run off switch"},
		{"forced and nesting runs, recorded org_forced", vm, with(func(n *NativeSandbox) { n.VendorForced = true }), NativeKept, vocab.NativeOrgForced, ""},
	}
	for _, tc := range cases {
		got := NativeNesting(tc.layer, vocab.TierInternet, tc.n)
		if got.Outcome != tc.out || NativeStateFor(got) != tc.state || !strings.Contains(got.Reason, tc.reason) {
			t.Errorf("%s: %+v (state %q)", tc.name, got, NativeStateFor(got))
		}
	}
	if len(conflictOutcomes) != 4 {
		t.Fatalf("conflictOutcomes has %d rows; add a case for each new row", len(conflictOutcomes))
	}
}

// TestForcedConflictOffersTheVMRowOnlyWhereItRuns (audit finding 9): the
// nest_or_refuse refusal names the Linux-only microVM row on Linux and
// never on macOS or Windows.
func TestForcedConflictOffersTheVMRowOnlyWhereItRuns(t *testing.T) {
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	for goos, offered := range map[string]bool{"linux": true, "darwin": false, "windows": false} {
		n := NativeSandbox{Present: true, NeedsFreshProc: true, VendorForced: true, ForcedPolicy: VendorForcedNestOrRefuse, HostOS: goos}
		v := NativeNesting(bw, vocab.TierInternet, n)
		if v.Outcome != NativeRefuse || strings.Contains(v.Reason, sandboxbackend.BackendCloudHypervisor) != offered || !strings.Contains(v.Reason, VerdictToolConflict) {
			t.Errorf("%s: %+v", goos, v)
		}
	}
}
