package terminalsisolation

import "testing"

// TestFloorLabelWithKey (lane FU10, F-050): a known floor reads as its
// quoted admin label with the key in parentheses; an unknown key as itself.
func TestFloorLabelWithKey(t *testing.T) {
	t.Parallel()
	cases := []struct{ key, want string }{
		{"require_refusal_audit", `"Require refusal audit" (require_refusal_audit)`},
		{"require_full_capture", `"Require full capture" (require_full_capture)`},
		{"no_such_floor", "no_such_floor"},
	}
	for _, c := range cases {
		if got := FloorLabelWithKey(c.key); got != c.want {
			t.Fatalf("FloorLabelWithKey(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}
