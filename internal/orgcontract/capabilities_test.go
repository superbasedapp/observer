package orgcontract

import "testing"

func TestModeCapabilityTokenRoundTrip(t *testing.T) {
	if got := ModeCapabilityToken(1); got != "mode_capability:v1" {
		t.Fatalf("token = %q", got)
	}
	if got := ModeCapabilityToken(0); got != "" {
		t.Fatalf("zero version token = %q, want empty", got)
	}
	cases := []struct {
		caps []string
		want int64
	}{
		{nil, 0},
		{[]string{"judge", "mode_capability:v1"}, 1},
		{[]string{"MODE_CAPABILITY:V2 ", "mode_capability:v1"}, 2}, // case/space tolerant, highest wins
		{[]string{"mode_capability:vX", "other"}, 0},               // malformed ignored
	}
	for _, c := range cases {
		if got := ParseModeCapabilityVersion(c.caps); got != c.want {
			t.Fatalf("ParseModeCapabilityVersion(%v) = %d, want %d", c.caps, got, c.want)
		}
	}
}
