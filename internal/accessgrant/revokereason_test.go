package accessgrant

import "testing"

// TestRevokeReasonWords pins the one mapping of a stored revoke reason to the
// developer's words: only an extension's exact reason reads "replaced by".
func TestRevokeReasonWords(t *testing.T) {
	cases := []struct {
		reason string
		by     string
		ok     bool
		words  string
	}{
		{"superseded by G-6", "G-6", true, "replaced by G-6"},
		{" superseded by G-1234 ", "G-1234", true, "replaced by G-1234"},
		{"replaced by G-7", "G-7", true, "replaced by G-7"},
		{ReplacedReason(9), "G-9", true, "replaced by G-9"},
		{"superseded by the new policy", "", false, "superseded by the new policy"},
		{"superseded by G-6 because of a typo", "", false, "superseded by G-6 because of a typo"},
		{"Superseded by G-6", "", false, "Superseded by G-6"},
		{"budget deleted", "", false, "budget deleted"},
		{"", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			by, ok := ReplacedBy(tc.reason)
			if by != tc.by || ok != tc.ok {
				t.Errorf("ReplacedBy(%q) = %q, %v; want %q, %v", tc.reason, by, ok, tc.by, tc.ok)
			}
			if got := RevokeReasonWords(tc.reason); got != tc.words {
				t.Errorf("RevokeReasonWords(%q) = %q, want %q", tc.reason, got, tc.words)
			}
		})
	}
}
