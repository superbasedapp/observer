package update

import "testing"

// TestAutoApplyDefault is the §3.9 table. The default is the whole surface
// of the managed carve-out, so every combination is a row rather than a
// spot check.
func TestAutoApplyDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   ManagedPosture
		want bool
	}{
		{"BYO node is notify-only", ManagedPosture{}, false},
		{"admin_managed is zero-touch", ManagedPosture{AdminManaged: true}, true},
		{"enterprise grant is zero-touch", ManagedPosture{EnterpriseGranted: true}, true},
		{"both", ManagedPosture{AdminManaged: true, EnterpriseGranted: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AutoApplyDefault(tc.in); got != tc.want {
				t.Errorf("AutoApplyDefault(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestAutoApplyReasonNamesTheDecider: a surface that says "off" without
// saying who decided is something an admin cannot act on. Each reason must
// name either the node's own config or the managed default.
func TestAutoApplyReasonNamesTheDecider(t *testing.T) {
	for _, tc := range []struct {
		name        string
		explicitSet bool
		effective   bool
		posture     ManagedPosture
		mustContain string
	}{
		{"explicit on", true, true, ManagedPosture{}, "[update].auto_apply"},
		{"explicit off overrides a managed default", true, false, ManagedPosture{AdminManaged: true}, "[update].auto_apply"},
		{"managed default on", false, true, ManagedPosture{AdminManaged: true}, "admin_managed"},
		{"enterprise default on", false, true, ManagedPosture{EnterpriseGranted: true}, "enterprise-posture"},
		{"BYO default off", false, false, ManagedPosture{}, "BYO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AutoApplyReason(tc.explicitSet, tc.effective, tc.posture)
			if got == "" {
				t.Fatal("AutoApplyReason returned an empty string")
			}
			if !contains(got, tc.mustContain) {
				t.Errorf("AutoApplyReason = %q, want it to name %q", got, tc.mustContain)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
