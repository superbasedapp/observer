package config

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// TestPinnableKeysMirrorInSyncWithPolicyfam pins internal/config's hand copy
// of the pinnable-key table to internal/policyfam/nodegov.PinnableKeys, the
// one owner.
//
// The copy exists because internal/config must not import the policy layer
// at runtime (see governancePinnableKeys' doc comment), and it is the exact
// shape that drifted before: TestPolicyResourceSupportedFamiliesMatchesPolicyfam
// in this package was written after gateway.providers shipped in policyfam
// and was missing here, which made accept_families reject the family so
// every gateway resource landed delivered_unaccepted. A test-only import
// closes the drift class without coupling the packages.
//
// A drift here is worse than that one: a key present in nodegov but missing
// here compiles cleanly at publish, reaches the sidecar, and is then SKIPPED
// by every reader — a node that reports `effective` while ignoring the pin,
// which is precisely the false compliance claim Phase 1b exists to remove.
func TestPinnableKeysMirrorInSyncWithPolicyfam(t *testing.T) {
	if len(governancePinnableKeys) != len(nodegov.PinnableKeys) {
		t.Fatalf("the config mirror has %d pinnable keys, policyfam/nodegov has %d — a key present only in nodegov would be published, delivered, and then silently skipped by every reader",
			len(governancePinnableKeys), len(nodegov.PinnableKeys))
	}
	for _, want := range nodegov.PinnableKeys {
		got, ok := governancePinnableByKey[want.Key]
		if !ok {
			t.Errorf("policyfam/nodegov pins %q but the config mirror does not", want.Key)
			continue
		}
		if got.Kind != want.Kind {
			t.Errorf("%q: mirror Kind %q, nodegov Kind %q", want.Key, got.Kind, want.Kind)
		}
		if got.Direction != string(want.Direction) {
			t.Errorf("%q: mirror Direction %q, nodegov Direction %q", want.Key, got.Direction, want.Direction)
		}
		if !reflect.DeepEqual(got.Enum, want.Enum) {
			t.Errorf("%q: mirror Enum %v, nodegov Enum %v", want.Key, got.Enum, want.Enum)
		}
		if !governanceValuesEqual(got.Safe, want.Safe) && !(got.Safe == nil && want.Safe == nil) {
			t.Errorf("%q: mirror Safe %v, nodegov Safe %v", want.Key, got.Safe, want.Safe)
		}
		if got.Format != want.Format {
			t.Errorf("%q: mirror Format %q, nodegov Format %q", want.Key, got.Format, want.Format)
		}
		if got.Min != want.Min || got.Max != want.Max {
			t.Errorf("%q: mirror bounds %d..%d, nodegov bounds %d..%d", want.Key, got.Min, got.Max, want.Min, want.Max)
		}
		if got.Hot != want.Hot {
			t.Errorf("%q: mirror Hot %v, nodegov Hot %v", want.Key, got.Hot, want.Hot)
		}
	}
}

// TestGovernancePushIntervalCeiling walks the org push-interval pin through
// the config overlay (2026-10-02 budget-latency arc). The org value is a
// CEILING: it lowers a slower node, never raises a faster one, and a value
// outside the row's bounds is skipped rather than applied.
func TestGovernancePushIntervalCeiling(t *testing.T) {
	cases := []struct {
		name    string
		local   int
		pinned  any
		want    int
		applied bool
		skipped bool
	}{
		{name: "enrol-written 900 lowered to the org's 120", local: 900, pinned: float64(120), want: 120, applied: true},
		{name: "default 120 lowered to 60", local: 120, pinned: float64(60), want: 60, applied: true},
		{name: "faster local value survives a slower org ceiling", local: 45, pinned: float64(300), want: 45, applied: true},
		{name: "org cannot raise the default", local: 120, pinned: float64(900), want: 120, applied: true},
		{name: "below the 30 s floor is skipped", local: 900, pinned: float64(5), want: 900, skipped: true},
		{name: "above the 3600 s bound is skipped", local: 900, pinned: float64(7200), want: 900, skipped: true},
		{name: "non-integer is skipped", local: 900, pinned: 12.5, want: 900, skipped: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.OrgClient.PushIntervalSeconds = tc.local
			var out GovernanceOutcome
			applyGovernancePins(&cfg, map[string]any{"org_client.push_interval_seconds": tc.pinned}, &out)
			if cfg.OrgClient.PushIntervalSeconds != tc.want {
				t.Fatalf("push interval = %d, want %d", cfg.OrgClient.PushIntervalSeconds, tc.want)
			}
			if got := len(out.Applied) == 1; got != tc.applied {
				t.Fatalf("applied = %v (%v), want %v", got, out.Applied, tc.applied)
			}
			if _, got := out.Skipped["org_client.push_interval_seconds"]; got != tc.skipped {
				t.Fatalf("skipped = %v (%v), want %v", got, out.Skipped, tc.skipped)
			}
		})
	}
}

// TestGovernancePinnedPushIntervalAndLowerInt pins the two helpers the
// daemon's hot path uses, so the restart-time overlay and the live value are
// computed by one definition.
func TestGovernancePinnedPushIntervalAndLowerInt(t *testing.T) {
	if got := GovernancePinnedPushInterval(nil); got != 0 {
		t.Fatalf("no pin = %d, want 0", got)
	}
	if got := GovernancePinnedPushInterval(map[string]any{"org_client.push_interval_seconds": int64(60)}); got != 60 {
		t.Fatalf("int64 pin = %d, want 60", got)
	}
	if got := GovernancePinnedPushInterval(map[string]any{"org_client.push_interval_seconds": float64(10)}); got != 0 {
		t.Fatalf("out-of-range pin = %d, want 0", got)
	}
	for _, c := range []struct{ local, org, want int64 }{
		{900, 120, 120}, {45, 120, 45}, {0, 120, 120}, {900, 0, 900}, {-1, 60, 60},
	} {
		if got := GovernanceLowerInt(c.local, c.org); got != c.want {
			t.Errorf("GovernanceLowerInt(%d, %d) = %d, want %d", c.local, c.org, got, c.want)
		}
	}
	if !GovernanceHotKey("org_client.push_interval_seconds") || GovernanceHotKey("guard.mode") {
		t.Fatal("GovernanceHotKey must mark only the push-interval ceiling hot")
	}
}
