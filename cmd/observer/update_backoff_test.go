//go:build !sbo_omit_org_update

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_backoff_test.go pins FR-SEC-12: a target that fails its hand-over
// (a healthcheck rollback, the interlock's refusal included) is backed off
// durably, so the next auto-apply tick does not repeat the drain, the swap
// and the rollback, and the backoff survives the exit a failed hand-over ends
// with.

func TestAHealthcheckRollbackBacksOffTheTarget(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{Detail: "the new binary reported a failed self-check: " + service.RefuseUnitPredatesHandover.Explain(), Started: true}, errTestHandshake
	}
	// A rollback is an outcome, not an error: runUpdateApply reports it on
	// the outcome and records it in the ledger.
	out, _ := f.run()
	if !out.RolledBack || out.ErrorClass != update.ErrorHealthcheck {
		t.Fatalf("want a healthcheck rollback, got %+v", out)
	}
	b, err := update.DecodeApplyBackoff(f.st.backoff)
	if err != nil || b.Failures != 1 || b.ErrorClass != update.ErrorHealthcheck {
		t.Fatalf("a healthcheck rollback was not backed off: %+v, %v", b, err)
	}
	if b.Refusal != string(service.RefuseUnitPredatesHandover) || !update.SameVersion(b.Target, fixtureTargetVersion) || b.ManifestVersion != 17 {
		t.Fatalf("record: %+v", b)
	}
	key := applyBackoffKey(f.opts)
	still := func() service.HandoverRefusal { return service.RefuseUnitPredatesHandover }
	if held, _ := applyBackoffGate(context.Background(), f.st, key, true, still, time.Now()); !held {
		t.Fatal("the next auto-apply tick was not held")
	}
}

var errTestHandshake = errorString("observer update: the new binary failed its self-check")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestApplyBackoffGate(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	key := update.BackoffKey{Target: "v1.43.0", ArtifactSHA256: "aa"}
	plain := update.NextApplyBackoff(update.ApplyBackoff{}, key, 17, update.ErrorHealthcheck, "", now, updateAutoApplyInterval, autoApplyMaxBackoff)
	refused := update.NextApplyBackoff(update.ApplyBackoff{}, key, 17, update.ErrorHealthcheck, string(service.RefuseUnitPredatesHandover), now, updateAutoApplyInterval, autoApplyMaxBackoff)
	stillRefused := func() service.HandoverRefusal { return service.RefuseUnitPredatesHandover }
	allowedNow := func() service.HandoverRefusal { return service.HandoverAllowed }
	for _, tc := range []struct {
		name       string
		rec        update.ApplyBackoff
		key        update.BackoffKey
		auto       bool
		refusalNow func() service.HandoverRefusal
		at         time.Time
		wantHeld   bool
		wantKept   bool
	}{
		{"auto, inside the wait", plain, key, true, allowedNow, now.Add(time.Minute), true, true},
		{"auto, after the wait", plain, key, true, allowedNow, now.Add(time.Hour), false, true},
		{"auto, another target", plain, update.BackoffKey{Target: "v1.43.1", ArtifactSHA256: "bb"}, true, allowedNow, now.Add(time.Minute), false, true},
		{"operator apply clears it", plain, key, false, allowedNow, now.Add(time.Minute), false, false},
		{"refusal still in force holds", refused, key, true, stillRefused, now.Add(time.Minute), true, true},
		{"refusal gone (service upgraded and restarted) re-arms", refused, key, true, allowedNow, now.Add(time.Minute), false, false},
		{"no record", update.ApplyBackoff{}, key, true, allowedNow, now, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeUpdateStore()
			js, _ := update.EncodeApplyBackoff(tc.rec)
			st.backoff = js
			held, _ := applyBackoffGate(context.Background(), st, tc.key, tc.auto, tc.refusalNow, tc.at)
			if held != tc.wantHeld {
				t.Fatalf("held = %v, want %v", held, tc.wantHeld)
			}
			if kept := st.backoff != ""; kept != tc.wantKept {
				t.Fatalf("record kept = %v, want %v", kept, tc.wantKept)
			}
		})
	}
}

// TestApplyBackoffSurvivesTheProcessThatRecordedIt: the record is written
// through one handle on the node database and holds the auto-apply of a
// runtime opened later on the same file, as the daemon that a failed
// hand-over restarts is.
func TestApplyBackoffSurvivesTheProcessThatRecordedIt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	open := func() (*store.Store, func()) {
		database, err := dbtemplate.Open(ctx, db.Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return store.New(database), func() { _ = database.Close() }
	}
	opts := applyOptions{
		Manifest: update.Manifest{Version: "v1.43.0", ManifestVersion: 17},
		Artifact: update.Artifact{SHA256: "aa"},
	}
	first, done := open()
	recordApplyBackoff(ctx, first, opts, applyOutcome{State: update.StateRolledBack, RolledBack: true, ErrorClass: update.ErrorHealthcheck}, time.Now(), discardLogger())
	done()

	restarted, done2 := open()
	defer done2()
	held, b := applyBackoffGate(ctx, restarted, applyBackoffKey(opts), true, func() service.HandoverRefusal { return service.HandoverAllowed }, time.Now())
	if !held || b.Failures != 1 {
		t.Fatalf("after a restart the auto-apply is not held: held=%v %+v", held, b)
	}
}
