package cursor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cursor's reasoning threading (B3 convergence, 2026-07-31 — see
// docs/plans/b3-reasoning-convergence-plan-2026-07-31.md §1).
//
// Every other adapter reads a transcript, so the thought and the action
// it precedes are two records of ONE parse call and the pending state is
// a struct field (grok's parseState.pendingReasoning). Cursor is a HOOK
// adapter: each event is delivered to a separate short-lived
// `observer hook cursor --<event>` PROCESS, so there is no in-memory
// state that can survive from the afterAgentThought event to the tool
// call it precedes. Pre-B3 that was papered over by minting a
// `cursor.thinking` action row and writing the thought onto that row's
// own PrecedingReasoning — a self-preview on a phantom action, which
// carried the text nowhere.
//
// This file is the missing carrier: a tiny per-conversation file under
// ~/.observer/cursor-reasoning/ holding exactly the 200-char scrubbed
// preview that would otherwise be dropped. Semantics match grok:
//
//   - CONSUMED-ONCE: the first recordable successor event of that
//     conversation takes the value AND removes it, so one thought is
//     threaded onto exactly one row.
//   - LAST-WINS: a second thought before any successor replaces the
//     first.
//   - TURN BOUNDARY: beforeSubmitPrompt (a new user turn) discards it,
//     exactly like grok's emitUserPrompt.
//
// # The file protocol is CROSS-PROCESS, so it uses atomic syscalls only
//
// Cursor fires several hooks per turn and they overlap: two successors
// can run concurrently, and a thought can be written while one is
// consuming. Those are separate PROCESSES, so no mutex, map, or lock
// file in this package can order them — only operations the kernel makes
// atomic can. A process-local mutex would order the goroutines of one
// process and silently do nothing for the case that actually happens.
// Every state transition below is therefore an os.Rename:
//
//   - WRITE (stash): write the body to a unique `<hash>.tmp.<nonce>` in
//     the SAME directory, then os.Rename it over `<hash>.txt`. Rename
//     replaces atomically, so a concurrent reader sees either the whole
//     old value or the whole new one — never a truncated file, which the
//     previous bare os.WriteFile (open-with-O_TRUNC, then write) could
//     hand out, losing the thought entirely because the reader deletes
//     what it read.
//   - CONSUME (take) / DISCARD (clear) / SWEEP: os.Rename the target to
//     a unique `<hash>.claim.<nonce>` FIRST. The rename IS the mutual
//     exclusion: exactly one caller can move a given name, every loser
//     gets ENOENT and correctly concludes there is nothing to consume.
//     Only then is the CLAIMED file read / age-checked / removed. The
//     previous read-then-remove let N concurrent successors all read
//     before any removed, threading one thought onto N actions
//     (measured: 190/200 iterations at N=16).
//
// Because the claim moves an INODE, a stale-file sweep can never destroy
// a thought written a microsecond later: the sweeper holds the old file,
// while the fresh one sits at the target name untouched. If a sweep
// discovers the file it claimed is NOT stale after all (a writer replaced
// it just before the claim), it puts it back via os.Link — which fails
// when the name is taken, so a newer thought is never overwritten by the
// older one it superseded (last-wins).
//
// Everything here is best-effort and FAIL-OPEN: any I/O error means the
// row simply carries no reasoning. A hook must never break the host tool
// (spec §17 P1), and a missing reasoning preview is not worth a failed
// capture. The failure direction is likewise deliberate — a lost thought
// is acceptable, a thought threaded onto the wrong (or onto several)
// actions is not.
//
// Content note: the file holds the SAME scrubbed 200-char preview that
// would land in the action's preceding_reasoning column — never the full
// thought body, never anything the DB wouldn't already hold.

// pendingReasoningTTL bounds how long a stashed thought may be claimed.
// Beyond it the value is treated as debris from an abandoned turn
// (Cursor was killed between the thought and its tool call) rather than
// as this turn's reasoning.
const pendingReasoningTTL = 30 * time.Minute

// File-name suffixes. The target is what a consumer claims; the other
// two are transient and are never claimed, only garbage-collected.
const (
	stashSuffix = ".txt"
	tmpMarker   = ".tmp."
	claimMarker = ".claim."
)

// pendingReasoningDir resolves the default stash directory. It is a var
// so tests can redirect it to a temp dir — no test may touch the
// operator's real ~/.observer.
var pendingReasoningDir = defaultPendingReasoningDir

func defaultPendingReasoningDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".observer", "cursor-reasoning")
}

// reasoningStash is one PARTICIPANT in the cross-process file protocol.
// Production runs exactly one per process (defaultStash); tests build
// several over a shared directory to stand in for several processes —
// which is the only honest way to exercise the protocol, since anything
// a single instance remembers is precisely what a real second process
// would not know.
type reasoningStash struct {
	// dir overrides the package default when non-empty (tests).
	dir string

	// mu/taken memoize a consumption within ONE process, keyed by the
	// consuming event's own SourceEventID.
	//
	// The guarded hook path calls BuildEvent TWICE for a single payload —
	// once through BuildCursorEvent to build the policy event, once in
	// processCursorEvent to build the row — and the first call would
	// otherwise swallow the stash before the row that needs it is built.
	// Keying on the event id (not the conversation) makes the memo
	// exactly "the same event asked again". It is a convenience for that
	// one re-ask; it is NOT the concurrency mechanism (see the protocol
	// note above).
	mu    sync.Mutex
	taken map[string]string
}

// defaultStash is the process-wide participant the hook path uses.
var defaultStash = &reasoningStash{}

// stashReasoning records a finalized thought preview for a conversation,
// replacing any unclaimed predecessor (last-wins).
func stashReasoning(conversationID, preview string) {
	defaultStash.stash(conversationID, preview)
}

// takeReasoning returns and consumes the pending thought for a
// conversation, or "" when there is none (or it aged past the TTL).
func takeReasoning(conversationID, eventID string) string {
	return defaultStash.take(conversationID, eventID)
}

// baseDir resolves this participant's directory.
func (s *reasoningStash) baseDir() string {
	if s.dir != "" {
		return s.dir
	}
	return pendingReasoningDir()
}

// path maps a conversation id onto its stash file. The id is hashed
// rather than used verbatim: it arrives from the host tool's payload and
// must never be able to steer a path.
func (s *reasoningStash) path(conversationID string) string {
	dir := s.baseDir()
	if dir == "" || conversationID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(conversationID))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+stashSuffix)
}

// nonce returns a value unique across processes, so two participants can
// never collide on a tmp or claim name.
func nonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a reason to break a hook; the pid +
		// clock is enough to keep two live participants apart.
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// stash writes preview for the conversation: body → unique temp file in
// the same directory → atomic rename over the target.
func (s *reasoningStash) stash(conversationID, preview string) {
	target := s.path(conversationID)
	if target == "" || preview == "" {
		return
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	s.sweepStale(dir)

	tmp := strings.TrimSuffix(target, stashSuffix) + tmpMarker + nonce()
	if err := os.WriteFile(tmp, []byte(preview), 0o600); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
	}
}

// take claims and consumes the pending thought. The claiming rename is
// the atomicity point: exactly one caller — in this process or any
// other — can move the target, so exactly one action can carry the
// thought.
func (s *reasoningStash) take(conversationID, eventID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if eventID != "" {
		if v, ok := s.taken[eventID]; ok {
			return v
		}
	}
	target := s.path(conversationID)
	if target == "" {
		return ""
	}
	claim := target + claimMarker + nonce()
	if err := os.Rename(target, claim); err != nil {
		// Nothing there, or another participant won the claim.
		return ""
	}
	defer func() { _ = os.Remove(claim) }()

	body, err := os.ReadFile(claim) //nolint:gosec // claim is a hash-derived name under our own state dir
	if err != nil {
		return ""
	}
	if info, statErr := os.Stat(claim); statErr == nil && time.Since(info.ModTime()) > pendingReasoningTTL {
		return ""
	}
	out := string(body)
	if eventID != "" {
		if s.taken == nil {
			s.taken = map[string]string{}
		}
		s.taken[eventID] = out
	}
	return out
}

// clear discards the pending thought via the same claim-then-remove
// pattern, so a thought written after the claim (a new turn's first
// thought racing the prompt event) survives at the target name instead
// of being deleted by name.
func (s *reasoningStash) clear(conversationID string) {
	target := s.path(conversationID)
	if target == "" {
		return
	}
	claim := target + claimMarker + nonce()
	if err := os.Rename(target, claim); err != nil {
		return
	}
	_ = os.Remove(claim)
}

// sweepStale garbage-collects debris: stash files whose turn was
// abandoned past the TTL, plus tmp/claim leftovers from a participant
// that died mid-operation. It removes nothing it has not first CLAIMED,
// and re-checks staleness on the claimed file, so a fresh thought
// written between the directory listing and the claim is never
// destroyed — the sweep is holding the superseded inode, and the fresh
// one is untouched at the target name.
func (s *reasoningStash) sweepStale(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) <= pendingReasoningTTL {
			continue
		}
		path := filepath.Join(dir, name)
		if !strings.HasSuffix(name, stashSuffix) {
			// A tmp/claim leftover: it is owned by nobody (its owner is
			// gone) and nothing can be restored from it.
			_ = os.Remove(path)
			continue
		}
		claim := path + claimMarker + nonce()
		if err := os.Rename(path, claim); err != nil {
			continue
		}
		claimed, statErr := os.Stat(claim)
		if statErr == nil && time.Since(claimed.ModTime()) <= pendingReasoningTTL {
			// A writer replaced the file between the listing and the
			// claim: what we hold is FRESH. Put it back — but only if
			// the name is still free. os.Link fails when the target
			// exists, which is exactly the last-wins outcome we want
			// (a newer thought must never be overwritten by an older).
			_ = os.Link(claim, path)
		}
		_ = os.Remove(claim)
	}
}
