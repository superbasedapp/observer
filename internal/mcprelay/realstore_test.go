package mcprelay_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// faultyStore wraps the REAL record.SQLStore and can fail Append.
type faultyStore struct {
	record.Store
	fail error
}

func (f *faultyStore) Append(ctx context.Context, rec record.Record) (record.AppendResult, error) {
	if f.fail != nil {
		return record.AppendResult{}, f.fail
	}
	return f.Store.Append(ctx, rec)
}

// TestRelayAgainstRealRecordStore drives the relay through Lane N-M's real
// SQLite-backed chain (node migration 131): decision before forward,
// completion after, fail-open with the sidecar, the gap fold inside the
// store's next Append, and a clean chain verification at the end.
func TestRelayAgainstRealRecordStore(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "node.db")})
	mustNoErr(t, err)
	t.Cleanup(func() { _ = d.Close() })
	real := record.NewSQLStore(d, "fp-node-w4b")
	fs := &faultyStore{Store: real}
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	front.deny["rm"] = true
	sidecar := filepath.Join(t.TempDir(), mcprelay.SidecarName)
	r, _ := newRelay(t, sts, front, fs, func(o *mcprelay.Options) { o.SidecarPath = sidecar })

	call := func(id int, tool string) {
		c := mcprelay.Call{
			Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(id, tool), Transport: localpdp.TransportLoopbackHTTP,
			Corr: mcprelay.Correlation{CodingSessionID: "sess_real_store"},
		}
		v := r.Decide(ctx, c)
		if !v.Forward {
			t.Fatalf("call %d refused: %s", id, v.Refuse)
		}
		rp, err := r.ForwardHTTP(ctx, c, v)
		mustNoErr(t, err)
		r.Complete(ctx, v, rp.Outcome(), rp.Body, "")
	}
	call(1, "search")
	call(2, "rm") // denied at the front: completion is an error row
	head, err := real.Head(ctx)
	mustNoErr(t, err)
	if head.Seq != 4 {
		t.Fatalf("head seq %d", head.Seq)
	}
	// Two failed appends -> sidecar, fail-open forwards.
	fs.fail = errors.New("simulated append failure")
	call(3, "search")
	call(4, "search")
	if r.PendingLoss().Count != 2 {
		t.Fatalf("pending loss %+v", r.PendingLoss())
	}
	if p, _ := real.PendingLoss(ctx, record.DefaultFamily); p.Count != 2 {
		t.Fatalf("store twin %+v", p)
	}
	// Recovery: the store folds the gap FIRST in the next Append's tx.
	fs.fail = nil
	call(5, "search")
	rows, err := real.ReadAfter(ctx, 4, 0)
	mustNoErr(t, err)
	if len(rows) != 3 || rows[0].Kind != record.KindGap || *rows[0].LostCount != 2 || rows[1].Kind != record.KindDecision || rows[2].Kind != record.KindCompletion {
		var kinds []record.Kind
		for _, x := range rows {
			kinds = append(kinds, x.Kind)
		}
		t.Fatalf("after recovery: %v", kinds)
	}
	if p, _ := real.PendingLoss(ctx, record.DefaultFamily); p.Count != 0 {
		t.Fatalf("pending loss not zeroed: %+v", p)
	}
	res, err := real.Verify(ctx)
	mustNoErr(t, err)
	if !res.OK() || res.Records != 7 {
		t.Fatalf("chain verify %+v", res)
	}
	// Restart over the same DB with no sidecar: nothing pending, chain intact.
	r2, _ := newRelay(t, sts, front, fs, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	if r2.PendingLoss().Count != 0 {
		t.Fatalf("restart pending %+v", r2.PendingLoss())
	}
}
