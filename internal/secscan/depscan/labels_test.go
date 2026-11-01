package depscan

import (
	"slices"
	"testing"
)

// TestRunLabels pins the one label table the CLI and the Scanners card read
// (lane SEC-DEPS3 item 6): a label per fixed note prefix, in table order,
// each once; other notes add none.
func TestRunLabels(t *testing.T) {
	cases := []struct {
		name  string
		notes []string
		want  []string
	}{
		{"none", nil, nil},
		{"other note", []string{"something else"}, nil},
		{"not isolated", []string{NotIsolatedPrefix + ": why."}, []string{"not isolated"}},
		{"both, once each, table order", []string{UntestedVersionPrefix + ": a.", NotIsolatedPrefix + ": b.", NotIsolatedPrefix + ": c."}, []string{"not isolated", "untested engine version"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RunLabels(c.notes); !slices.Equal(got, c.want) {
				t.Fatalf("RunLabels(%q) = %q, want %q", c.notes, got, c.want)
			}
		})
	}
}
