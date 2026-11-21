//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestReadoptAttachCheck pins the check behind the dashboard's "Re-attach in
// a terminal" (dashboard CLI parity plan item B-G3): only an id this piece
// offers now passes, one row per refusal.
func TestReadoptAttachCheck(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, time.Minute)
	ra := raSetup(t, f, "run0000000000000301")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	oldDir := readoptCLIObserverDir
	readoptCLIObserverDir = func() (string, error) { return ra.obs, nil }
	t.Cleanup(func() { readoptCLIObserverDir = oldDir })

	cases := []struct {
		name string
		run  string
		want string // a word of the refusal; "" passes
	}{
		{"an offered run passes", ra.runID, ""},
		{"a malformed id", "../etc", "not a run id"},
		{"a run that is not offered", "run0000000000000399", "not offered for re-adoption"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := readoptAttachCheck(context.Background(), tc.run)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check = %v, want %q", err, tc.want)
			}
		})
	}

	raSettings(t, false, time.Minute)
	if err := readoptAttachCheck(context.Background(), ra.runID); err == nil || !strings.Contains(err.Error(), readoptComponent) {
		t.Fatalf("check with the component off = %v, want it named", err)
	}
}
