package update

import "testing"

// TestParseSemverParity walks the cases the TypeScript implementation
// documents and exercises (web/src/lib/version.ts:293-340). The two
// implementations must agree case for case: a node that thinks it is
// behind while the dashboard says it is current — or the reverse — is
// the bug this table exists to prevent.
func TestParseSemverParity(t *testing.T) {
	cases := []struct {
		in    string
		want  Semver
		wantK bool
	}{
		{"1.33.0", Semver{1, 33, 0}, true},
		{"v1.33.0", Semver{1, 33, 0}, true},
		{"v1.8.2-rc.1", Semver{1, 8, 2}, true},   // suffix stripped, not ordered
		{"1.8.2+build.7", Semver{1, 8, 2}, true}, // build metadata stripped
		{"v1.33.0.1", Semver{1, 33, 0}, true},    // extra parts ignored, as in TS
		{"v0.0.0", Semver{0, 0, 0}, true},
		{"", Semver{}, false},
		{"dev", Semver{}, false},
		{"1.33", Semver{}, false},
		{"v1.x.0", Semver{}, false},
		{"v-1.0.0", Semver{}, false},
		{"v1.-2.0", Semver{}, false},
		{"vNaN.0.0", Semver{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseSemver(tc.in)
			if ok != tc.wantK {
				t.Fatalf("ParseSemver(%q) ok = %v, want %v", tc.in, ok, tc.wantK)
			}
			if ok && got != tc.want {
				t.Fatalf("ParseSemver(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCompareSemverParity mirrors compareSemver's documented contract:
// -1 / 0 / 1, and "not comparable" for any malformed input.
func TestCompareSemverParity(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v1.32.0", "v1.33.0", -1, true},
		{"v1.33.0", "v1.32.0", 1, true},
		{"v1.33.0", "v1.33.0", 0, true},
		{"1.33.0", "v1.33.0", 0, true}, // leading v is cosmetic
		{"v1.9.0", "v1.10.0", -1, true},
		{"v2.0.0", "v1.99.99", 1, true},
		{"v1.33.0-rc.1", "v1.33.0", 0, true}, // pre-release is STRIPPED, not ordered
		{"dev", "v1.33.0", 0, false},
		{"", "v1.33.0", 0, false},
		{"v1.33.0", "garbage", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			got, ok := CompareSemver(tc.a, tc.b)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("CompareSemver(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestIsUpdateAvailableParity is the exact table isUpdateAvailable
// (version.ts:328-340) documents, including the two "defaults to no
// pill on uncertainty" rules.
func TestIsUpdateAvailableParity(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"v1.32.0", "v1.33.0", true},
		{"1.32.0", "1.33.0", true},
		{"v1.33.0", "v1.33.0", false},
		{"v1.34.0", "v1.33.0", false},
		{"dev", "v1.33.0", false},          // a dev build is never nagged
		{"v1.33.0-rc.1", "v1.33.0", false}, // a pre-release is effectively ahead
		{"1.8.2+build", "v1.9.0", false},   // build metadata counts as pre-release here
		{"", "v1.33.0", false},
		{"v1.32.0", "", false},
		{"v1.32.0", "not-a-version", false},
	}
	for _, tc := range cases {
		t.Run(tc.current+" -> "+tc.latest, func(t *testing.T) {
			if got := IsUpdateAvailable(tc.current, tc.latest); got != tc.want {
				t.Fatalf("IsUpdateAvailable(%q,%q) = %v, want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

// TestPreReleaseAndDevPredicates covers the two helpers the verifier
// branches on directly.
func TestPreReleaseAndDevPredicates(t *testing.T) {
	for _, v := range []string{"v1.8.2-rc.1", "1.8.2+build", "v1.8.2-0"} {
		if !HasPreRelease(v) {
			t.Errorf("HasPreRelease(%q) = false", v)
		}
	}
	for _, v := range []string{"v1.8.2", "1.8.2", ""} {
		if HasPreRelease(v) {
			t.Errorf("HasPreRelease(%q) = true", v)
		}
	}
	if !IsDevBuild("dev") || !IsDevBuild("") {
		t.Error("IsDevBuild missed an unstamped build")
	}
	if IsDevBuild("v1.33.0") {
		t.Error("IsDevBuild flagged a stamped release")
	}
}

// TestSameVersion pins UPD-9: an org manifest names a release "v1.42.0" while
// a release build stamps itself "1.42.0", and the two must read as the same
// version wherever the updater compares them (the child's self-check, the
// boot-time recovery and the staged-binary probe).
func TestSameVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v1.42.0", "1.42.0", true},
		{"1.42.0", "v1.42.0", true},
		{"v1.42.0", "v1.42.0", true},
		{"1.42.0", "1.42.0", true},
		{" v1.42.0\n", "1.42.0", true},
		{"V1.42.0", "1.42.0", true},
		{"v1.42.0-rc.1", "1.42.0-rc.1", true},
		{"v1.42.0", "1.42.1", false},
		{"v1.42.0", "1.42.0-rc.1", false},
		{"vv1.42.0", "1.42.0", false},
		{"v1.42.0", "", false},
		{"", "", false},
		{"v", "", false},
		{"dev", "dev", true},
	} {
		if got := SameVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("SameVersion(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestParentKeepsSupervision: the new binary reads the parent's version from
// the apply row, and anything it cannot place counts as a release that does
// not hand over.
func TestParentKeepsSupervision(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{FirstSupervisedHandoverRelease, true},
		{"v" + FirstSupervisedHandoverRelease, true},
		{"v1.43.0", true},
		{"2.0.0", true},
		{"1.42.0", false},
		{"v1.42.0", false},
		{"1.41.99", false},
		{"dev", false},
		{"", false},
	} {
		if got := ParentKeepsSupervision(tc.v); got != tc.want {
			t.Errorf("ParentKeepsSupervision(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
