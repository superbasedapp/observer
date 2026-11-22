package adapter

import (
	"reflect"
	"testing"
)

// TestNoteMalformedRows pins the one-warning-per-pass rule: a positive
// count adds exactly one warning naming the tool, the store's base name
// and the count; zero, a negative count or a nil result adds nothing.
func TestNoteMalformedRows(t *testing.T) {
	cases := []struct {
		name string
		n    int64
		want []string
	}{
		{"none skipped", 0, nil},
		{"negative is ignored", -1, nil},
		{"one skipped", 1, []string{"opencode: opencode.db: skipped 1 row(s) whose JSON data is malformed"}},
		{"several skipped", 7, []string{"opencode: opencode.db: skipped 7 row(s) whose JSON data is malformed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var res ParseResult
			NoteMalformedRows(&res, "opencode", "/home/dev/.local/share/opencode/opencode.db", tc.n)
			if !reflect.DeepEqual(res.Warnings, tc.want) {
				t.Fatalf("warnings = %q, want %q", res.Warnings, tc.want)
			}
		})
	}
	NoteMalformedRows(nil, "opencode", "opencode.db", 3) // must not panic
}
