//go:build !sbo_omit_org_update

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_status_handover_test.go: `observer update status` names a refused
// hand-over and its fix, and an auto-apply backoff, from the node's own
// ledger (UPD-9 interlock, FR-SEC-12), including a refusal an older parent
// recorded from a newer binary's self-check.

func TestUpdateStatusNamesTheHandoverRefusalAndTheBackoff(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	rec := update.NextApplyBackoff(update.ApplyBackoff{}, update.BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}, 17,
		update.ErrorHealthcheck, string(service.RefuseUnitPredatesHandover), now, updateAutoApplyInterval, autoApplyMaxBackoff)
	js, _ := update.EncodeApplyBackoff(rec)
	events := []store.UpdateEventRow{{
		FromVersion: "1.42.0", ToVersion: "v1.43.0", State: update.StateRolledBack, ErrorClass: update.ErrorHealthcheck,
		Detail: "the new binary reported a failed self-check: " + strings.Join(strings.Fields(service.RefuseUnitPredatesHandover.Explain()), " ") + "; restoring the previous binary",
	}}
	var rep updateStatusReport
	applyHandoverStatus(&rep, "v1.43.0", js, events)
	if rep.HandoverRefusal != string(service.RefuseUnitPredatesHandover) || !strings.Contains(rep.HandoverFix, "observer service upgrade") {
		t.Fatalf("refusal not surfaced: %+v", rep)
	}
	if rep.Backoff == nil || rep.Backoff.Failures != 1 || rep.Backoff.ErrorClass != string(update.ErrorHealthcheck) {
		t.Fatalf("backoff not surfaced: %+v", rep.Backoff)
	}
	var out bytes.Buffer
	writeUpdateStatus(&out, rep)
	for _, want := range []string{"hand-over refused", "systemd_unit_predates_handover", "observer service upgrade", "auto-apply backoff", "observer update apply"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}

	// A backoff about another target, and an applied newest event, say nothing.
	var quiet updateStatusReport
	applyHandoverStatus(&quiet, "v1.44.0", js, []store.UpdateEventRow{{State: update.StateApplied, Detail: "the new binary passed its self-check"}})
	if quiet.Backoff != nil || quiet.HandoverRefusal != "" {
		t.Fatalf("stale facts surfaced: %+v", quiet)
	}
}
