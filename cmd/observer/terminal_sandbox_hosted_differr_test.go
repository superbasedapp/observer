//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestHostedDiffErrorOutlivesTheRecord (P-094 residual, lane
// SHR-FOLLOWUPS): when teardown removes a confirmed-gone run's record, the
// reason its staged diff was not saved is kept, and `observer sandbox
// hosted status` prints it; a run that saved its diff keeps no line.
func TestHostedDiffErrorOutlivesTheRecord(t *testing.T) {
	obs := t.TempDir()
	rec := sandboxremote.NewIntent("r1", sandboxremote.VendorVercel, "https://api.vercel.com", "iad1", "r1", time.Now().Add(-time.Hour), time.Hour)
	rec.State, rec.DiffError = sandboxremote.StateGone, "git add refused"
	ok := sandboxremote.NewIntent("r2", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "r2", time.Now(), time.Hour)
	ok.State = sandboxremote.StateGone
	for _, r := range []sandboxremote.Record{rec, ok} {
		if err := hostedSaveRecord(obs, r); err != nil {
			t.Fatal(err)
		}
		if err := hostedRemoveRecord(obs, r); err != nil {
			t.Fatal(err)
		}
	}
	if left := hostedLoadRecords(obs); len(left) != 0 {
		t.Fatalf("records left: %+v", left)
	}
	lines := hostedLoadDiffErrors(obs)
	if len(lines) != 1 || lines[0].RunID != "r1" || lines[0].Error != "git add refused" || lines[0].Provider != sandboxremote.VendorVercel {
		t.Fatalf("kept lines %+v", lines)
	}
	var out strings.Builder
	renderHostedStatus(&out, nil, lines)
	if s := out.String(); !strings.Contains(s, "none") || !strings.Contains(s, "r1 ("+sandboxremote.VendorVercel+"): git add refused") {
		t.Fatalf("status:\n%s", s)
	}
}
