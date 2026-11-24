package update

import (
	"testing"
	"time"
)

// backoff_test.go pins FR-SEC-12: an apply that fails the same way on the
// same target backs off exponentially, durably and up to a cap, instead of
// re-running a download, a drain, a swap and a rollback every auto-apply
// interval for as long as the manifest stays published.

func TestBackoffStep(t *testing.T) {
	for _, tc := range []struct {
		name    string
		applied bool
		class   ErrorClass
		want    BackoffAction
	}{
		{"applied clears", true, ErrorNone, BackoffClear},
		{"healthcheck rollback advances (FR-SEC-12)", false, ErrorHealthcheck, BackoffAdvance},
		{"hash advances", false, ErrorHash, BackoffAdvance},
		{"signature advances", false, ErrorSignature, BackoffAdvance},
		{"probe advances", false, ErrorProbe, BackoffAdvance},
		{"swap advances", false, ErrorSwap, BackoffAdvance},
		{"permission advances", false, ErrorPermission, BackoffAdvance},
		{"a failed download is transient", false, ErrorDownload, BackoffKeep},
		{"a busy drain is transient", false, ErrorDrain, BackoffKeep},
		{"a closed window is transient", false, ErrorWindow, BackoffKeep},
		{"a defer or block keeps it", false, ErrorNone, BackoffKeep},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BackoffStep(tc.applied, tc.class); got != tc.want {
				t.Fatalf("BackoffStep(%v, %q) = %v, want %v", tc.applied, tc.class, got, tc.want)
			}
		})
	}
}

func TestNextApplyBackoffIsExponentialWithACap(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	base, ceiling := 10*time.Minute, 6*time.Hour
	var b ApplyBackoff
	want := []time.Duration{20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 320 * time.Minute, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		b = NextApplyBackoff(b, BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}, 17, ErrorHealthcheck, "", now, base, ceiling)
		if b.Failures != i+1 {
			t.Fatalf("attempt %d: failures = %d", i+1, b.Failures)
		}
		if got := b.NextAttempt.Sub(now); got != w {
			t.Fatalf("attempt %d: waits %s, want %s", i+1, got, w)
		}
	}
	// A huge count never overflows into a past (or zero) wait.
	b.Failures = 200
	b = NextApplyBackoff(b, BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}, 17, ErrorHealthcheck, "", now, base, ceiling)
	if got := b.NextAttempt.Sub(now); got != ceiling {
		t.Fatalf("an overflowing count waits %s, want the cap", got)
	}
}

func TestApplyBackoffHoldsOnlyItsOwnTarget(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	key := BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}
	b := NextApplyBackoff(ApplyBackoff{}, key, 17, ErrorHealthcheck, "systemd_unit_predates_handover", now, 10*time.Minute, 6*time.Hour)
	for _, tc := range []struct {
		name string
		key  BackoffKey
		at   time.Time
		want bool
	}{
		{"same target, inside the wait", key, now.Add(time.Minute), true},
		{"the bare spelling is the same target", BackoffKey{Target: "1.43.0", ArtifactSHA256: "aa"}, now.Add(time.Minute), true},
		{"same target, after the wait", key, now.Add(21 * time.Minute), false},
		{"a different target clears it", BackoffKey{Target: "v1.43.1", ArtifactSHA256: "bb"}, now.Add(time.Minute), false},
		{"a corrected artifact for the same version clears it", BackoffKey{Target: "v1.43.0", ArtifactSHA256: "cc"}, now.Add(time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.Holds(tc.key, tc.at); got != tc.want {
				t.Fatalf("Holds = %v, want %v", got, tc.want)
			}
		})
	}
	if (ApplyBackoff{}).Holds(key, now) {
		t.Fatal("the zero backoff holds nothing")
	}
	// Advancing for a DIFFERENT target starts the count again.
	other := NextApplyBackoff(b, BackoffKey{Target: "v1.44.0", ArtifactSHA256: "dd"}, 18, ErrorHash, "", now, 10*time.Minute, 6*time.Hour)
	if other.Failures != 1 || other.Refusal != "" || other.ManifestVersion != 18 {
		t.Fatalf("a new target inherited the old count: %+v", other)
	}
}

func TestApplyBackoffRoundTrips(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	b := NextApplyBackoff(ApplyBackoff{}, BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}, 17, ErrorHealthcheck, "launch_agent_does_not_restart", now, 10*time.Minute, 6*time.Hour)
	js, err := EncodeApplyBackoff(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeApplyBackoff(js)
	if err != nil {
		t.Fatal(err)
	}
	if got != b {
		t.Fatalf("round trip: %+v, want %+v", got, b)
	}
	if js, _ := EncodeApplyBackoff(ApplyBackoff{}); js != "" {
		t.Fatalf("the zero backoff encodes as %q, want empty (no record)", js)
	}
	if z, err := DecodeApplyBackoff(""); err != nil || z != (ApplyBackoff{}) {
		t.Fatalf("empty decodes to %+v, %v", z, err)
	}
	if _, err := DecodeApplyBackoff("{not json"); err == nil {
		t.Fatal("a corrupt record must not decode silently")
	}
}
