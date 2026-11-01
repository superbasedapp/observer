package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestNativeNesting: one case per nesting row N11 to N14, plus the default
// and the no-native case.
func TestNativeNesting(t *testing.T) {
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	vm := sandboxbackend.Capability{Iso: sandboxbackend.Isolation{Class: vocab.ClassHWVM}, GuestUnprivUserns: true}
	mxc := sandboxbackend.Capability{Iso: sandboxbackend.Isolation{Class: vocab.ClassProcess}, AppContainer: true}
	freshProc := NativeSandbox{Present: true, NeedsFreshProc: true}
	tun := NativeSandbox{Present: true, NeedsDevNetTUN: true}
	for _, tc := range []struct {
		name  string
		layer sandboxbackend.Capability
		tier  vocab.Tier
		n     NativeSandbox
		out   NativeOutcome
		rule  string
	}{
		{"no native sandbox", bw, vocab.TierInternet, NativeSandbox{}, NativeNone, ""},
		{"N11 fresh /proc, no switch", bw, vocab.TierInternet, freshProc, NativeRefuse, "N11"},
		{"N11 fresh /proc, per-run switch", bw, vocab.TierInternet, NativeSandbox{Present: true, NeedsFreshProc: true, PerRunDisable: true}, NativeDisable, "N11"},
		{"N12 TUN on a private network", bw, vocab.TierInternet, tun, NativeRefuse, "N12"},
		{"N12 does not apply on the host network", bw, vocab.TierHost, tun, NativeKept, "N-native-default"},
		{"N13 a VM with unprivileged userns keeps it", vm, vocab.TierNone, freshProc, NativeKept, "N13"},
		{"N14 AppContainer in AppContainer", mxc, vocab.TierNone, NativeSandbox{Present: true, AppContainer: true}, NativeRefuse, "N14"},
		{"default keeps a sandbox with no known conflict", bw, vocab.TierInternet, NativeSandbox{Present: true}, NativeKept, "N-native-default"},
	} {
		got := NativeNesting(tc.layer, tc.tier, tc.n)
		if got.Outcome != tc.out || got.Rule != tc.rule {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	if len(nativeRules) != 4 {
		t.Fatalf("nativeRules has %d rows; add a case above for each new row", len(nativeRules))
	}
	if NativeStateFor(NativeVerdict{Outcome: NativeDisable}) != vocab.NativeDisabledByObserver ||
		NativeStateFor(NativeVerdict{Outcome: NativeNone}) != vocab.NativeNotApplicable ||
		NativeStateFor(NativeVerdict{Outcome: NativeKept}) != "" {
		t.Fatal("native state mapping")
	}
}

// TestN9LandlockStacksInnermost: a Landlock ruleset nests under any layer,
// including a process layer that N7 otherwise keeps innermost.
func TestN9LandlockStacksInnermost(t *testing.T) {
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	ll, _ := sandboxbackend.Get(sandboxbackend.BackendProcessLite)
	if !ll.Landlock {
		t.Fatal("the process_lite row is not marked Landlock")
	}
	v := ValidateStack([]Layer{{Row: bw, OwnsNetwork: true}, {Row: ll}})
	if !v.OK {
		t.Fatalf("bwrap around Landlock refused: %+v", v)
	}
	plain := ll
	plain.Landlock = false
	if v := ValidateStack([]Layer{{Row: bw, OwnsNetwork: true}, {Row: plain}}); v.OK || v.Rule != "N7" {
		t.Fatalf("a non-Landlock process inside a process: %+v", v)
	}
}
