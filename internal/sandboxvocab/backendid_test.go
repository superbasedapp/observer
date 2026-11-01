package sandboxvocab

import "testing"

// TestValidBackendID is the shared id rule, one case per row (LIN-1 F1: the
// underscore of process_lite is in).
func TestValidBackendID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"bwrap", true},
		{"process_lite", true},
		{"oci-runc", true},
		{"k8s-agent-sandbox", true},
		{"", false},
		{"Bwrap", false},
		{"oci runc", false},
		{"oci.runc", false},
		{"a/b", false},
		{"abcdefghijklmnopqrstuvwxyz0123456", false},
		{"abcdefghijklmnopqrstuvwxyz012345", true},
	}
	for _, c := range cases {
		if got := ValidBackendID(c.id); got != c.want {
			t.Errorf("ValidBackendID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}
