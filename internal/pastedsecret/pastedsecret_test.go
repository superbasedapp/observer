package pastedsecret

import "testing"

func TestClean(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "ik_a.fakeValue", "ik_a.fakeValue"},
		{"edge white space and newline", "  ik_a.fakeValue\r\n", "ik_a.fakeValue"},
		{"bracketed paste markers", "\x1b[200~ik_a.fakeValue\x1b[201~", "ik_a.fakeValue"},
		{"byte-order mark and zero-width", "\uFEFF\u200Bik_a.fakeValue\u2060", "ik_a.fakeValue"},
		{"inner space is kept for the caller to judge", "ik_a.fake Value", "ik_a.fake Value"},
		{"inner newline is kept", "ik_a.x\nik_b.y", "ik_a.x\nik_b.y"},
		{"nothing", "\x1b[200~\x1b[201~\n", ""},
	}
	for _, tc := range cases {
		if got := Clean(tc.in); got != tc.want {
			t.Errorf("%s: Clean(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
