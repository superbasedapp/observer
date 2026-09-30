package mcprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// record.go is the relay's write path into the node's ONE hash-chained
// mcp_relay_record store (doc3 §12.4, R12.7/R14.2/R14.4): the decision
// record BEFORE the forward, the completion AFTER, and the durable loss
// sidecar that makes an append failure accountable before the call
// proceeds. The store (table, chain, genesis, gap folding inside Append,
// launch journal rows) is Lane N-M's record.Store; this file owns only the
// ORDERING:
//
//	async (default):  append decision -> forward -> append completion
//	   on append failure: fsync+rename the sidecar FIRST, forward only after
//	   that commits (fail OPEN once loss is durable); block if the sidecar
//	   write fails too; the pending loss is handed to the store before the
//	   next append, whose transaction folds it into a `gap` row.
//	strict:           append decision, BLOCK the call on any failure.

// Audit modes ([mcp_relay].audit_mode, doc3 §8.2).
const (
	AuditAsync  = "async"
	AuditStrict = "strict"
)

// Correlation is the relay's sbo_corr anchor set (R11.8) minus call_id,
// which the relay mints per call.
type Correlation struct {
	CodingSessionID string
	TurnRef         string
	ActionRef       string
}

// Recording errors.
var (
	// ErrRecordBlocked: the call must not proceed because its decision could
	// not be made accountable (strict mode, or async with an unwritable
	// sidecar).
	ErrRecordBlocked = errors.New("mcprelay: call blocked: decision record could not be made durable")
)

// LossSidecar is the durable pending-loss state (`mcp-relay-loss.json`,
// doc3 §12.4): written atomically (temp + fsync + rename, 0600) BEFORE a call
// whose decision append failed is forwarded. It is the file twin of
// record.PendingLoss.
type LossSidecar struct {
	Count            int64    `json:"count"`
	FirstAt          int64    `json:"first_at"`
	LastAt           int64    `json:"last_at"`
	Reason           string   `json:"reason"`
	AttemptedCallIDs []string `json:"attempted_call_ids"`
}

func (l LossSidecar) pending() record.PendingLoss {
	return record.PendingLoss{Count: l.Count, FirstAt: l.FirstAt, LastAt: l.LastAt, Reason: l.Reason, CallIDs: append([]string(nil), l.AttemptedCallIDs...)}
}

func sidecarFrom(p record.PendingLoss) LossSidecar {
	return LossSidecar{Count: p.Count, FirstAt: p.FirstAt, LastAt: p.LastAt, Reason: p.Reason, AttemptedCallIDs: append([]string(nil), p.CallIDs...)}
}

// SidecarName is the loss sidecar's file name, beside the node DB.
const SidecarName = "mcp-relay-loss.json"

// recorder owns the ordering + the in-memory twin of the pending-loss
// state. One per relay.
type recorder struct {
	store   record.Store
	sidecar string // path; "" disables the sidecar (then any failure blocks)
	strict  bool
	now     func() time.Time

	mu sync.Mutex
	// loss is the in-memory pending-loss twin; dirty marks loss the STORE
	// has not been told about yet (the sidecar holds it durably).
	loss  LossSidecar
	dirty bool
}

// newRecorder loads the store's pending loss and any present sidecar (the
// larger total wins: the sidecar is always written with the full state),
// so a crash after a sidecar commit is folded by the next successful
// append (§12.4 step 4).
func newRecorder(ctx context.Context, store record.Store, sidecarPath, mode string, now func() time.Time) (*recorder, error) {
	r := &recorder{store: store, sidecar: sidecarPath, strict: mode == AuditStrict, now: now}
	if p, err := store.PendingLoss(ctx, record.DefaultFamily); err == nil {
		r.loss = sidecarFrom(p)
	}
	if sidecarPath != "" {
		raw, err := os.ReadFile(sidecarPath)
		switch {
		case err == nil:
			var sc LossSidecar
			if jerr := json.Unmarshal(raw, &sc); jerr != nil {
				sc = LossSidecar{Count: r.loss.Count + 1, FirstAt: now().Unix(), LastAt: now().Unix(), Reason: "sidecar unreadable: " + jerr.Error()}
				if r.loss.FirstAt > 0 {
					sc.FirstAt = r.loss.FirstAt
				}
			}
			if sc.Count >= r.loss.Count {
				r.loss, r.dirty = sc, true
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("mcprelay: read loss sidecar: %w", err)
		}
	}
	return r, nil
}

// pendingLoss reports the in-memory pending-loss state.
func (r *recorder) pendingLoss() LossSidecar {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loss
}

// handoffLocked tells the store about sidecar-only loss so its next Append
// folds it into a gap row. Failure leaves it dirty (the sidecar keeps it).
func (r *recorder) handoffLocked(ctx context.Context) error {
	if !r.dirty {
		return nil
	}
	if err := r.store.SetPendingLoss(ctx, record.DefaultFamily, r.loss.pending()); err != nil {
		return err
	}
	r.dirty = false
	return nil
}

// Handoff is the startup fold (§12.4 step 4): hand a present sidecar's
// loss to the store BEFORE serving.
func (r *recorder) handoff(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handoffLocked(ctx)
}

// appendLocked runs one store append with the fold protocol: pending loss
// is handed to the store first; on success the store has folded it, so the
// in-memory twin and the sidecar are cleared.
func (r *recorder) appendLocked(ctx context.Context, rec record.Record) (record.AppendResult, error) {
	if err := r.handoffLocked(ctx); err != nil {
		return record.AppendResult{}, fmt.Errorf("pending-loss handoff: %w", err)
	}
	res, err := r.store.Append(ctx, rec)
	if err != nil {
		return record.AppendResult{}, err
	}
	if r.loss.Count > 0 {
		r.loss = LossSidecar{}
		if r.sidecar != "" {
			if rerr := os.Remove(r.sidecar); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				// The gap is committed; a lingering zero-loss sidecar is a
				// no-op at next start (its count never exceeds the store's).
				_ = rerr
			}
		}
	}
	return res, nil
}

// noteLossLocked accounts one failed append in memory + the sidecar.
func (r *recorder) noteLossLocked(reason, callID string) error {
	now := r.now().Unix()
	if r.loss.Count == 0 {
		r.loss.FirstAt = now
	}
	r.loss.Count++
	r.loss.LastAt = now
	r.loss.Reason = reason
	if callID != "" && len(r.loss.AttemptedCallIDs) < record.MaxPendingLossCallIDs {
		r.loss.AttemptedCallIDs = append(r.loss.AttemptedCallIDs, callID)
	}
	r.dirty = true
	if err := r.writeSidecarLocked(); err != nil {
		return err
	}
	// Best-effort twin in the store (mcp_relay_state.pending_loss_*): the
	// sidecar is the durable copy; a store that is down keeps it dirty and
	// the handoff happens before the next append.
	_ = r.handoffLocked(context.Background())
	return nil
}

// decision appends the decision record and returns its seq. On failure it
// applies the audit mode: strict -> ErrRecordBlocked; async -> the sidecar
// is committed FIRST and (only then) the call may proceed with seq 0; a
// sidecar failure -> ErrRecordBlocked.
func (r *recorder) decision(ctx context.Context, rec record.Record, strictForThisCall bool) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, err := r.appendLocked(ctx, rec)
	if err == nil {
		return res.Record.Seq, nil
	}
	if r.strict || strictForThisCall {
		// ErrRecordBlocked is the sole classification: the append cause (which
		// may be a context cancellation) is rendered as text only, so a blocked
		// call can never match context.Canceled and be treated as a clean stop.
		return 0, fmt.Errorf("%w: %v", ErrRecordBlocked, err) //nolint:errorlint // single-sentinel classification; cause deliberately not in the chain
	}
	if werr := r.noteLossLocked(err.Error(), rec.CallID); werr != nil {
		return 0, fmt.Errorf("%w: append failed (%v) and the loss sidecar could not be written (%v)", ErrRecordBlocked, err, werr) //nolint:errorlint // single-sentinel classification; causes deliberately not in the chain
	}
	return 0, nil
}

// completion appends the completion record; a failure is counted as loss
// (sidecar) but never blocks: the call already ran. A completion whose
// decision was lost has no parent row and is part of the same loss.
func (r *recorder) completion(ctx context.Context, rec record.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.DecisionSeq == nil || *rec.DecisionSeq == 0 {
		return
	}
	if _, err := r.appendLocked(ctx, rec); err != nil {
		_ = r.noteLossLocked("completion: "+err.Error(), rec.CallID)
	}
}

// writeSidecarLocked commits the in-memory loss state durably: write a
// 0600 temp file in the same directory, fsync it, rename over the sidecar,
// fsync the directory.
func (r *recorder) writeSidecarLocked() error {
	if r.sidecar == "" {
		return errors.New("no loss sidecar configured")
	}
	raw, err := json.Marshal(r.loss)
	if err != nil {
		return err
	}
	return writeAtomic(r.sidecar, raw, 0o600)
}

// dirOf returns the directory a sidecar path lives in (for the composition
// root: SidecarPath = filepath.Join(dirOf(dbPath), SidecarName)).
func dirOf(path string) string { return filepath.Dir(path) }

// SidecarPathFor returns the loss sidecar path beside an observer DB.
func SidecarPathFor(dbPath string) string { return filepath.Join(dirOf(dbPath), SidecarName) }
