//go:build !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_local_fold.go is the daemon's session fold for an injected
// local run's model turns (tracker row F-003, finding F-N3-1, ledger row
// OSH-R-150): the proxy asks its injector (proxy.RunSessionFolder) whether
// a stamped request's turn may land on the session the request names
// instead of the run's namespace. The facts are the run's injection record
// (the host side wrote it), the run's helper liveness, the request's relay
// token and the relay daemon's claim table (claimed by this run, and fresh:
// the node did not record the session before the run claimed it); the rule
// is sandboxcred.DecideFold. A hosted run's record has no local lane, so its
// turns keep the run namespace its pulled transcripts land in.

func init() {
	onRelayRunEnd(credFoldRunEnded)
	relayFreshStoreFactory = func(observerDir string) sandboxrelayd.FreshSessions {
		return &credFreshStore{observerDir: observerDir}
	}
}

// credFreshCap bounds the fresh session ids kept per run (audit FU3-R1). A
// box can name at most this many of its own sessions as fresh across a
// re-adoption or a daemon restart; a session past the bound is simply not
// fresh after a drop (its turns stay in the run's namespace, fail safe).
const credFreshCap = 32

// credFreshStore is the relay daemon's sandboxrelayd.FreshSessions over
// credFreshDir.
type credFreshStore struct {
	observerDir string
	mu          sync.Mutex
}

// Fresh implements sandboxrelayd.FreshSessions (nil when unreadable).
func (s *credFreshStore) Fresh(runID string) []string {
	if !vocab.ValidRelayRunID(runID) || s.observerDir == "" {
		return nil
	}
	b, err := credReadOwned(credFreshPath(s.observerDir, runID))
	if err != nil {
		return nil
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil {
		return nil
	}
	return ids
}

// AddFresh implements sandboxrelayd.FreshSessions: kept only for a run
// whose injection record says lane local (no other run's turns are ever
// folded), up to credFreshCap ids.
func (s *credFreshStore) AddFresh(runID string, ids []string) {
	if len(ids) == 0 {
		return
	}
	rec, err := credReadRecord(s.observerDir, runID)
	if err != nil || rec.Lane != sandboxcred.LaneLocal {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.Fresh(runID)
	n := len(kept)
	for _, id := range ids {
		if len(kept) >= credFreshCap {
			break
		}
		if !slices.Contains(kept, id) {
			kept = append(kept, id)
		}
	}
	if len(kept) == n {
		return
	}
	_ = credWriteOwned(credFreshDir(s.observerDir), credFreshPath(s.observerDir, runID), kept)
}

// credWriteOwned writes v as JSON to path whole (0600, renamed into place,
// dir 0700).
func credWriteOwned(dir, path string, v any) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fresh.*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return werr
	}
	return os.Rename(tmp.Name(), path)
}

// credFoldClaimed reports whether the run's relayed hooks speak for the
// session and whether that claim was fresh (a test seam; the running relay
// daemon's claim table).
var credFoldClaimed = relaySessionClaim

// credFoldMismatchCap bounds the distinct sessions logged as a mismatch per
// run: the session string is the box's, so it must not grow the daemon's
// memory or log without bound (audit FU3-A3).
const credFoldMismatchCap = 32

// credFoldMismatch is one run's mismatch log state.
type credFoldMismatch struct {
	mu         sync.Mutex
	seen       map[string]struct{}
	suppressed bool
}

// credFoldMismatches holds the runs' mismatch log state (run id ->
// *credFoldMismatch). A run reaches the mismatch row only with a live local
// record and its own relay token, so the runs are real ones; an entry goes
// when its run ends.
var credFoldMismatches sync.Map

// credFoldRunEnded drops a run's mismatch log state (a relay run end hook,
// and the fold's own rows that find the run over).
func credFoldRunEnded(runID string) { credFoldMismatches.Delete(runID) }

// credFoldSessionRef is what a log line names for a session: a short hash,
// never the box-chosen string itself.
func credFoldSessionRef(session string) string {
	sum := sha256.Sum256([]byte(session))
	return hex.EncodeToString(sum[:6])
}

// credFoldLogMismatch logs one line per distinct session of a run, up to
// credFoldMismatchCap, then one suppression line, then nothing.
func credFoldLogMismatch(runID, session string, code sandboxcred.FoldCode) {
	v, _ := credFoldMismatches.LoadOrStore(runID, &credFoldMismatch{seen: map[string]struct{}{}})
	m := v.(*credFoldMismatch)
	ref := credFoldSessionRef(session)
	m.mu.Lock()
	_, dup := m.seen[ref]
	full := len(m.seen) >= credFoldMismatchCap
	first := !dup && !full
	if first {
		m.seen[ref] = struct{}{}
	}
	suppress := !dup && full && !m.suppressed
	if suppress {
		m.suppressed = true
	}
	m.mu.Unlock()
	switch {
	case first:
		slog.Default().Warn("terminal_sandbox: relay_session_mismatch: a sandboxed run's model request named a session its hooks do not speak for; the turn stays in the run's namespace",
			"run", runID, "session_hash", ref, "row", string(code))
	case suppress:
		slog.Default().Warn("terminal_sandbox: relay_session_mismatch: further mismatches of this run are suppressed",
			"run", runID, "logged", credFoldMismatchCap)
	}
}

// FoldRunSession implements proxy.RunSessionFolder.
func (i *credInjector) FoldRunSession(_ context.Context, in proxy.RunSessionRequest) (string, bool) {
	d := i.fold(in.RunID, in.Token, in.Session)
	switch {
	case d.Mismatch:
		credFoldLogMismatch(in.RunID, in.Session, d.Code)
	case d.Code == sandboxcred.FoldNoRecord || d.Code == sandboxcred.FoldNotLive || d.Code == sandboxcred.FoldHelperGone:
		credFoldRunEnded(in.RunID)
	}
	return d.Session, d.Session != ""
}

// fold reads the facts for one stamped request and walks the fold table.
func (i *credInjector) fold(runID, token, session string) sandboxcred.FoldDecision {
	rec, err := credReadRecord(i.observerDir, runID)
	f := sandboxcred.FoldFacts{Found: err == nil, Token: token, Session: session}
	if err == nil {
		_, rerr := sandboxrelayd.ReadRun(i.observerDir, runID)
		f.Lane, f.TokenHash = rec.Lane, rec.TokenHash
		f.Live = rerr == nil && credNow().Before(rec.Expires)
		if rec.Lane == sandboxcred.LaneLocal {
			f.HelperLive = credHelperLive(i.observerDir, runID)
			// Read last: only a request every host-side row admits
			// consults the relay daemon.
			if f.Live && f.HelperLive && session != "" {
				f.ClaimedByRun, f.FreshClaim = credFoldClaimed(runID, session)
			}
		}
	}
	return sandboxcred.DecideFold(f)
}
