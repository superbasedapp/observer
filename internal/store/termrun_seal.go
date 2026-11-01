package store

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// termrun_seal.go is the terminal_run seal seam (component isolation.seal,
// ledger SHR-6, lane GATES-SEC; migration 195): an injected sealer signs a
// run's evidence digest when the run row is inserted. With no sealer (the
// default, and whenever the component is off) InsertTerminalRun writes
// exactly the row it wrote before, the seal columns left ''. The sealer is
// the cmd layer's (the key lives in internal/keystore); the store only
// records what it answers.

// TerminalRunSeal is one run's seal: the key id, the public key and the
// signature, base64 (internal/execevidence.Seal).
type TerminalRunSeal struct {
	KeyID     string
	PublicKey string
	Sig       string
}

// TerminalRunSealer seals one evidence digest; ok false leaves the run
// unsealed (a key that cannot be read seals nothing, never fails the run).
type TerminalRunSealer func(ctx context.Context, digest string) (seal TerminalRunSeal, ok bool)

// terminalRunSealers holds each database's sealer, so every Store over the
// same handle seals (the Store struct is shared, so the seam keeps its own
// map).
var terminalRunSealers sync.Map // *sql.DB -> TerminalRunSealer

// SetTerminalRunSealer installs (or, with nil, removes) the sealer of the
// store's database handle.
func (s *Store) SetTerminalRunSealer(f TerminalRunSealer) {
	if f == nil {
		terminalRunSealers.Delete(s.db)
		return
	}
	terminalRunSealers.Store(s.db, f)
}

// sealRetryWaits are the waits before each retry of a seal write that
// failed after its run row was inserted (audit finding F6).
var sealRetryWaits = []time.Duration{25 * time.Millisecond, 100 * time.Millisecond, 400 * time.Millisecond}

// sealTerminalRun seals the run's digest just inserted, when a sealer is
// installed and the run has a digest. The row's other columns are not
// touched.
func (s *Store) sealTerminalRun(ctx context.Context, runID, digest string) error {
	v, ok := terminalRunSealers.Load(s.db)
	if !ok || digest == "" {
		return nil
	}
	f, _ := v.(TerminalRunSealer)
	seal, ok := f(ctx, digest)
	if !ok || seal.KeyID == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE terminal_run SET evidence_seal_key_id = ?, evidence_seal_public_key = ?, evidence_seal_sig = ?
		WHERE run_id = ? AND evidence_digest = ?`, seal.KeyID, seal.PublicKey, seal.Sig, runID, digest); err != nil {
		return fmt.Errorf("store.sealTerminalRun: %w", err)
	}
	return nil
}

// sealInsertedRun seals a run whose row InsertTerminalRun just committed.
// The row is already written, so a failed seal write never fails the
// insert (audit finding F6): it is retried a few times, then logged, and
// the run reads unsealed (the honest state of a row with no seal).
func (s *Store) sealInsertedRun(ctx context.Context, runID, digest string) {
	err := s.sealTerminalRun(ctx, runID, digest)
	for _, wait := range sealRetryWaits {
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			slog.Default().Warn("store: the terminal run seal was not written; the run reads unsealed", "err", ctx.Err())
			return
		case <-time.After(wait):
		}
		err = s.sealTerminalRun(ctx, runID, digest)
	}
	if err != nil {
		slog.Default().Warn("store: the terminal run seal was not written after retries; the run reads unsealed", "err", err)
	}
}

// TerminalRunSealOf reads a run's stored seal (zero when unsealed).
func (s *Store) TerminalRunSealOf(ctx context.Context, runID string) (TerminalRunSeal, error) {
	var seal TerminalRunSeal
	err := s.db.QueryRowContext(ctx, `SELECT evidence_seal_key_id, evidence_seal_public_key, evidence_seal_sig FROM terminal_run WHERE run_id = ?`, runID).
		Scan(&seal.KeyID, &seal.PublicKey, &seal.Sig)
	if err != nil {
		return TerminalRunSeal{}, fmt.Errorf("store.TerminalRunSealOf: %w", err)
	}
	return seal, nil
}

// resealTerminalRun re-seals a run whose digest changed (a lowered
// capture): with a sealer the new digest is sealed; with none a seal over
// the old digest is cleared, so the run reads unsealed rather than
// seal_invalid.
func (s *Store) resealTerminalRun(ctx context.Context, runID, digest string) error {
	if _, ok := terminalRunSealers.Load(s.db); ok {
		return s.sealTerminalRun(ctx, runID, digest)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE terminal_run SET evidence_seal_key_id = '', evidence_seal_public_key = '', evidence_seal_sig = ''
		WHERE run_id = ? AND evidence_seal_key_id != ''`, runID); err != nil {
		return fmt.Errorf("store.resealTerminalRun: %w", err)
	}
	return nil
}
