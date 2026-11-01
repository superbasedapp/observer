package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestNodeControlLinesPerOS is WINNODE item 3, one row per OS: where the
// process cutoff has no backend the enrol/org-status line and the guard
// status line say it is not supported on that OS and what still works; on
// Linux a failed authority read keeps the verification wording; a node with
// no managed authority prints no policy-control line anywhere.
func TestNodeControlLinesPerOS(t *testing.T) {
	ctx := context.Background()
	_, unmanaged := identTestStore(t) // no enrolment: not managed
	cases := []struct {
		name       string
		goos       string
		unmanaged  bool
		wantPolicy string // "" means no Policy control line
		wantStatus string
	}{
		{"linux authority read fails", "linux", false, "managed authority could not be verified", "no live controller report"},
		// A failed authority read is a failure on every OS (audit F6); the
		// OS line is only for an authorized node (TestNodeControlPreamble).
		{"windows authority read fails", "windows", false, "managed authority could not be verified", "not supported on Windows"},
		{"macos authority read fails", "darwin", false, "managed authority could not be verified", "not supported on macOS"},
		{"linux unmanaged", "linux", true, "", "no live controller report"},
		{"windows unmanaged", "windows", true, "", "not supported on Windows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := unmanaged
			if !tc.unmanaged {
				st = nil // the authority read fails: inputs unavailable
			}
			dbPath := filepath.Join(t.TempDir(), "observer.db")
			var out bytes.Buffer
			printEnrolledNodeControlOn(ctx, &out, st, dbPath, tc.goos)
			got := out.String()
			if tc.wantPolicy == "" {
				if strings.Contains(got, "Policy control") {
					t.Fatalf("unexpected policy-control line: %q", got)
				}
			} else if !strings.Contains(got, "Policy control: ") || !strings.Contains(got, tc.wantPolicy) {
				t.Fatalf("policy-control line = %q, want %q", got, tc.wantPolicy)
			}
			if tc.goos != "linux" && strings.Contains(got, "not supported on") {
				t.Fatalf("a failed authority read must not read as an unsupported OS: %q", got)
			}
			line := nodeInterventionStatusLineOn(ctx, unmanaged, dbPath, tc.goos)
			if !strings.Contains(line, tc.wantStatus) {
				t.Fatalf("guard status line = %q, want %q", line, tc.wantStatus)
			}
			if tc.goos != "linux" && strings.Contains(line, "could not be verified") {
				t.Fatalf("an unsupported OS must not read as an identity failure: %q", line)
			}
		})
	}
}

// TestNodeControlPreamble (WINNODE merge follow-up, audit F6), one row per
// case: a failed authority read keeps the failure wording on every OS; "not
// supported" is said only to an authorized node on an OS with no
// process-control backend; an unauthorized node prints nothing; an
// authorized Linux node goes on to the controller self-test.
func TestNodeControlPreamble(t *testing.T) {
	readFailed := errors.New("authority inputs unavailable")
	cases := []struct {
		name       string
		goos       string
		authorized bool
		err        error
		want       string // "" means no line
		done       bool
	}{
		{"windows read fails", "windows", false, readFailed, "managed authority could not be verified", true},
		{"windows authorized", "windows", true, nil, "not supported on Windows", true},
		{"windows unauthorized", "windows", false, nil, "", true},
		{"macos authorized", "darwin", true, nil, "not supported on macOS", true},
		{"linux read fails", "linux", false, readFailed, "managed authority could not be verified", true},
		{"linux unauthorized", "linux", false, nil, "", true},
		{"linux authorized", "linux", true, nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, done := nodeControlPreamble(tc.goos, tc.authorized, tc.err)
			if done != tc.done {
				t.Fatalf("done = %v, want %v", done, tc.done)
			}
			if tc.want == "" {
				if line != "" {
					t.Fatalf("line = %q, want none", line)
				}
				return
			}
			if !strings.HasPrefix(line, "Policy control: ") || !strings.Contains(line, tc.want) {
				t.Fatalf("line = %q, want %q", line, tc.want)
			}
			if strings.Contains(tc.want, "not supported") && !strings.Contains(line, "hooks, the proxy route and launch admission") {
				t.Fatalf("the line must say what still works: %q", line)
			}
		})
	}
}
