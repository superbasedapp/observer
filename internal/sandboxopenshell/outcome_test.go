package sandboxopenshell

import "testing"

// TestClassifyGet: the not-found row is keyed to v0.1.6's exact live text
// (fact 4 of lane O0's verdict); any other text, and any untested version,
// reads unknown, never gone.
func TestClassifyGet(t *testing.T) {
	t.Parallel()
	v016 := Version{Major: 0, Minor: 1, Patch: 6}
	v017 := Version{Major: 0, Minor: 1, Patch: 7}
	live := "Error:   × code: 'Some requested entity was not found', message: \"sandbox not found\"\n"
	wrapped := "Error:   × code: 'Some requested entity was not found', message:\n  │ \"sandbox not found\"\n"
	cases := []struct {
		name   string
		v      Version
		exit   int
		stderr string
		want   Outcome
	}{
		{"present", v016, 0, "", OutcomePresent},
		{"live not-found text", v016, 1, live, OutcomeGone},
		{"bare text", v016, 1, `code: 'Some requested entity was not found', message: "sandbox not found"`, OutcomeGone},
		{"wrapped by miette", v016, 1, wrapped, OutcomeGone},
		{"source-derived text is not the live one", v016, 1, `status: 'Some requested entity was not found', self: "sandbox not found"`, OutcomeUnknown},
		{"another entity", v016, 1, `code: 'Some requested entity was not found', message: "gateway not found"`, OutcomeUnknown},
		{"permission denied", v016, 1, "Error: permission denied", OutcomeUnknown},
		{"timeout", v016, -1, "", OutcomeUnknown},
		{"untested version", v017, 1, live, OutcomeUnknown},
	}
	for _, tc := range cases {
		if got := ClassifyGet(tc.v, tc.exit, tc.stderr); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
