package update

import "testing"

// TestEvaluateSkewTable walks the decision table row by row.
//
// The two rows that are NOT arithmetic are the ones that matter:
//
//   - an empty floor must be byte-for-byte today's behaviour, or upgrading a
//     server would break the documented v1.7-agent compat invariant on its own;
//   - a version this package cannot ORDER must never be refused, because
//     refusing an unknown strands a node whose version the admin cannot even
//     see - and a package-manager-owned node has no automatic remediation.
func TestEvaluateSkewTable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     SkewPolicy
		version    string
		wantBelow  bool
		wantRefuse bool
		wantUnkn   bool
		wantRule   string
	}{
		{
			name:     "no floor configured accepts anything",
			policy:   SkewPolicy{Action: SkewActionRefuse},
			version:  "0.0.1",
			wantRule: "no-floor-configured",
		},
		{
			name:     "compliant",
			policy:   SkewPolicy{MinVersion: "v1.30.0"},
			version:  "1.30.0",
			wantRule: "compliant",
		},
		{
			name:     "ahead of the floor",
			policy:   SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionRefuse},
			version:  "v1.33.1",
			wantRule: "compliant",
		},
		{
			name:      "below the floor under warn is flagged, not refused",
			policy:    SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionWarn},
			version:   "1.29.9",
			wantBelow: true,
			wantRule:  "below-floor",
		},
		{
			name:       "below the floor under refuse",
			policy:     SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionRefuse},
			version:    "1.29.9",
			wantBelow:  true,
			wantRefuse: true,
			wantRule:   "below-floor",
		},
		{
			name:     "a dev build is never refused",
			policy:   SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionRefuse},
			version:  "dev",
			wantUnkn: true,
			wantRule: "dev-build",
		},
		{
			name:     "an empty version is never refused",
			policy:   SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionRefuse},
			version:  "",
			wantUnkn: true,
			wantRule: "dev-build",
		},
		{
			name:     "a malformed version is never refused",
			policy:   SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionRefuse},
			version:  "1.30",
			wantUnkn: true,
			wantRule: "unorderable",
		},
		{
			name:     "a malformed FLOOR refuses nothing",
			policy:   SkewPolicy{MinVersion: "latest", Action: SkewActionRefuse},
			version:  "1.0.0",
			wantUnkn: true,
			wantRule: "unorderable",
		},
		{
			name:     "a pre-release below the floor compares on its core",
			policy:   SkewPolicy{MinVersion: "v1.30.0", Action: SkewActionWarn},
			version:  "1.30.0-rc.1",
			wantRule: "compliant",
		},
		{
			name:      "an unknown ACTION never refuses",
			policy:    SkewPolicy{MinVersion: "v1.30.0", Action: SkewAction("block")},
			version:   "1.0.0",
			wantBelow: true,
			wantRule:  "below-floor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateSkew(tc.policy, tc.version)
			if got.BelowMin != tc.wantBelow || got.Refuse != tc.wantRefuse ||
				got.UnknownVersion != tc.wantUnkn || got.Rule != tc.wantRule {
				t.Fatalf("EvaluateSkew(%+v, %q) = %+v", tc.policy, tc.version, got)
			}
		})
	}
}

// TestUnknownVersionsAreNeverRefused restates the safety property over the
// whole unorderable class, so a future rule row cannot quietly acquire the
// power to strand a node whose version nobody can read.
func TestUnknownVersionsAreNeverRefused(t *testing.T) {
	p := SkewPolicy{MinVersion: "v9.9.9", Action: SkewActionRefuse}
	// Note "1.0.0.0" is deliberately absent: ParseSemver ignores parts beyond
	// the third (semver.go's documented port of the shipped frontend rule), so
	// it IS orderable and its refusal is correct, not a stranding.
	for _, v := range []string{"", "dev", "1.30", "vNext", "1.x.0", "-1.0.0"} {
		if got := EvaluateSkew(p, v); got.Refuse {
			t.Errorf("EvaluateSkew(%q).Refuse = true; an unorderable version must never be refused (%+v)", v, got)
		}
	}
}

func TestSkewPolicyDefaults(t *testing.T) {
	var zero SkewPolicy
	if zero.Configured() {
		t.Error("the zero policy must report unconfigured — that is what makes the feature inert by default")
	}
	if zero.EffectiveAction() != SkewActionWarn {
		t.Errorf("EffectiveAction() = %q, want warn", zero.EffectiveAction())
	}
	if zero.EffectiveMaxSkewMinors() != DefaultMaxSkewMinors {
		t.Errorf("EffectiveMaxSkewMinors() = %d, want %d", zero.EffectiveMaxSkewMinors(), DefaultMaxSkewMinors)
	}
	if !KnownSkewAction(SkewActionWarn) || !KnownSkewAction(SkewActionRefuse) || KnownSkewAction("nope") {
		t.Error("KnownSkewAction must accept exactly warn and refuse")
	}
}

func TestMinorDistance(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.30.0", "1.30.9", 0, true},
		{"1.30.0", "1.33.0", 3, true},
		{"1.33.0", "1.30.0", 3, true},
		{"1.9.0", "1.10.0", 1, true},
		{"1.9.0", "2.0.0", 991, true},
		{"dev", "1.30.0", 0, false},
		{"", "1.30.0", 0, false},
	} {
		got, ok := MinorDistance(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("MinorDistance(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// TestMethodSelfUpdatableCoversEveryMethod pins the stranding table: only a
// writable standalone binary can apply an update on its own, and an
// unrecognised method answers false so it is counted INTO the warning rather
// than out of it.
func TestMethodSelfUpdatableCoversEveryMethod(t *testing.T) {
	want := map[Method]bool{
		MethodBinary:         true,
		MethodBinaryReadOnly: false,
		MethodNPM:            false,
		MethodPip:            false,
		MethodVSCode:         false,
		MethodBrew:           false,
		MethodAPT:            false,
		MethodRPM:            false,
		MethodUnknown:        false,
	}
	for m, w := range want {
		if got := MethodSelfUpdatable(m); got != w {
			t.Errorf("MethodSelfUpdatable(%q) = %v, want %v", m, got, w)
		}
		if !KnownMethod(m) {
			t.Errorf("KnownMethod(%q) = false; every declared method must be in the table", m)
		}
	}
	if MethodSelfUpdatable(Method("snap")) {
		t.Error("an unrecognised method must answer false — 'we do not know it can fix itself' is the safe reading")
	}
	if KnownMethod(Method("snap")) {
		t.Error("KnownMethod must reject a method this agent never publishes")
	}
	// Cross-check against Detect()'s own verdict for the one self-applying
	// row, so the two tables cannot drift apart silently.
	d := Detect(PathProbe{ExecPath: "/usr/local/bin/observer", GOOS: "linux", Writable: true})
	if d.Method != MethodBinary || !d.SelfApply || !MethodSelfUpdatable(d.Method) {
		t.Fatalf("Detect gave %+v; the method table and the path table must agree", d)
	}
}
