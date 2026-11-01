//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestMXCNarrowDesktopFailsClosed (WINFIX2 audit finding 2): the run's
// desktop admits ALL APPLICATION PACKAGES until the box's SID is read, so a
// SID that is not read or a narrowing that fails ends the run with the named
// reason; before, both were only logged and the run went on with its
// desktop open.
func TestMXCNarrowDesktopFailsClosed(t *testing.T) {
	const sid = "S-1-15-2-1-2-3-4-5-6-7"
	cases := []struct {
		name      string
		wait      func(context.Context) (string, error)
		narrowErr error
		cancel    bool
		state     string
		ends      bool
	}{
		{"narrowed", func(context.Context) (string, error) { return sid, nil }, nil, false, mxcDesktopNarrowed, false},
		{"sid not read in time", func(context.Context) (string, error) { return "", errors.New("searched for 30s") }, nil, false, mxcDesktopNotNarrowed, true},
		{"empty sid", func(context.Context) (string, error) { return "", nil }, nil, false, mxcDesktopNotNarrowed, true},
		{"narrowing failed", func(context.Context) (string, error) { return sid, nil }, errors.New("access denied"), false, mxcDesktopNotNarrowed, true},
		{"run already ended", func(context.Context) (string, error) { return "", errors.New("the run ended") }, nil, true, mxcDesktopRunEnded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			narrowed := ""
			state, reason := mxcNarrowDesktop(ctx, tc.wait, func(s string) error { narrowed = s; return tc.narrowErr })
			if state != tc.state {
				t.Fatalf("state = %q, want %q", state, tc.state)
			}
			if (reason != "") != tc.ends {
				t.Fatalf("reason = %q, ends = %v", reason, tc.ends)
			}
			if tc.ends && !strings.HasPrefix(reason, mxcDesktopNotNarrowed+": ") {
				t.Fatalf("reason %q does not name %s", reason, mxcDesktopNotNarrowed)
			}
			if tc.state == mxcDesktopNarrowed && narrowed != sid {
				t.Fatalf("narrowed to %q", narrowed)
			}
		})
	}
}
