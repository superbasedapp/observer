// codex_discover.go — daemon-spawned codex session discovery + OOB announce
// (session-attach design Phase 2 / P2-1).
//
// Codex CLI (0.144.x checked) has NO caller-choosable session id: there is no
// `--session-id` flag on a fresh or `exec` launch, and only `resume`/`fork`
// accept an EXISTING id. So a daemon-spawned attach/fresh `observer codex`
// launch cannot FORCE a known id up front the way `observer claude` does
// (claude.go::forceClaudeSessionID). Instead, this file DISCOVERS the session:
// after the child starts, it watches $CODEX_HOME/sessions for the NEW rollout
// codex writes for THIS run, reads only that file's leading session_meta line to
// extract the real session id (and cwd for corroboration), and announces the id
// on the trusted out-of-band launcher channel (announceOOBSession →
// termoob.TypeSession) so the daemon correlates the run to its dashboard
// session.
//
// Honesty via abstention (design intent — "honest about weaker evidence"):
// discovery is a weaker signal than claude's forced id (we infer the id from
// the filesystem rather than dictating it), so the matcher NEVER guesses. It
// announces only a SINGLE new rollout, corroborated by cwd when the meta line
// carries one, confirmed on two consecutive polls (to catch a racing concurrent
// session); ANY ambiguity (two or more new rollouts) makes it announce nothing.
// The announced id rides the same trusted OOB frame as claude's, so the daemon
// records it at oob confidence (the frame→source mapping is owned by the
// launcher-side drain and is intentionally not touched here); the strict
// abstention gate is what keeps that honest.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// codexDiscoverConfig tunes the discovery poll loop. Injectable so tests can use
// tiny durations.
type codexDiscoverConfig struct {
	// window bounds the total watch time after the child starts.
	window time.Duration
	// poll is the interval between rollout-directory scans.
	poll time.Duration
}

// defaultCodexDiscoverConfig is the production timing: watch for up to ~30s,
// scanning every ~750ms. Codex writes its session_meta line at session start, so
// the new rollout typically appears within the first second; the window mostly
// covers a slow first flush.
func defaultCodexDiscoverConfig() codexDiscoverConfig {
	return codexDiscoverConfig{window: 30 * time.Second, poll: 750 * time.Millisecond}
}

// codexRolloutModTimeSkew is how far before the child-start stamp a rollout's
// ModTime may fall and still be considered "new". It absorbs coarse filesystem
// timestamp granularity (some filesystems truncate ModTime to whole seconds);
// the name-based pre-start snapshot is the authoritative new-file signal, so
// this guard only needs to reject clearly-stale (name-recycled) files.
const codexRolloutModTimeSkew = 5 * time.Second

// codexRolloutCandidate is a discovered rollout file plus the identity fields
// read from its leading session_meta line.
type codexRolloutCandidate struct {
	path      string
	sessionID string
	cwd       string // from session_meta payload.cwd; "" when the meta omits it
}

// codexSessionsRoots returns every "<codex_home>/sessions" directory to watch,
// derived from the same codexHomeRoots() the capture check uses.
func codexSessionsRoots() []string {
	roots := codexHomeRoots()
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		out = append(out, filepath.Join(r, "sessions"))
	}
	return out
}

// snapshotCodexRollouts records the set of rollout-*.jsonl paths that already
// exist under the given roots. Taken BEFORE the child starts so the child's own
// (brand-new) rollout — which has a fresh unique name and is therefore absent
// from this set — is unambiguously detectable as "new" without relying on wall
// clocks. Best-effort: unreadable directories are skipped.
func snapshotCodexRollouts(roots []string) map[string]struct{} {
	existing := make(map[string]struct{})
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // skip unreadable entries, keep walking
			}
			if isCodexRolloutName(filepath.Base(path)) {
				existing[path] = struct{}{}
			}
			return nil
		})
	}
	return existing
}

// scanNewCodexRollouts returns the rollout files that appeared AFTER the
// pre-start snapshot: a path not in preexisting, touched at or after startedAt,
// whose leading session_meta line yields a session id. Only the meta line is
// read (never the whole transcript). Best-effort throughout.
func scanNewCodexRollouts(roots []string, preexisting map[string]struct{}, startedAt time.Time) []codexRolloutCandidate {
	var out []codexRolloutCandidate
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // skip unreadable entries, keep walking
			}
			if !isCodexRolloutName(filepath.Base(path)) {
				return nil
			}
			if _, seen := preexisting[path]; seen {
				return nil // pre-existing session (appended-to), not this run's
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			// Defensive secondary guard: a file whose last write clearly predates
			// the child start cannot be this run's (the snapshot already excludes
			// pre-existing names; this also rejects a name-recycled stale file).
			// A generous skew tolerates coarse filesystem ModTime granularity —
			// the name snapshot, not this clock, is the primary "new file" signal.
			if info.ModTime().Before(startedAt.Add(-codexRolloutModTimeSkew)) {
				return nil
			}
			id, cwd := readCodexRolloutMeta(path)
			if id == "" {
				return nil
			}
			out = append(out, codexRolloutCandidate{path: path, sessionID: id, cwd: cwd})
			return nil
		})
	}
	return out
}

// selectDiscoveredCodexSession applies the abstention policy to a scan result.
// It returns (sessionID, count) where count is the number of candidates that
// survived cwd corroboration:
//
//   - count == 1 → the single surviving candidate's id (the caller announces it
//     only at window close, never mid-window — R2-1).
//   - count == 0 → nothing yet (keep polling).
//   - count >= 2 → ambiguous; the caller NEVER guesses (announce nothing).
//
// When targetCwd is non-empty, a candidate whose meta cwd is KNOWN and does not
// match is dropped (a concurrent session in a different directory is
// disambiguated away). A candidate whose meta omits cwd is kept — it cannot be
// excluded, so it still counts toward ambiguity, preserving the never-guess
// guarantee.
func selectDiscoveredCodexSession(cands []codexRolloutCandidate, targetCwd string) (string, int) {
	kept := make([]codexRolloutCandidate, 0, len(cands))
	for _, c := range cands {
		if c.sessionID == "" {
			continue
		}
		if targetCwd != "" && c.cwd != "" && !sameCodexCwd(c.cwd, targetCwd) {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 1 {
		return kept[0].sessionID, 1
	}
	return "", len(kept)
}

// runCodexDiscovery watches for this run's new rollout across the FULL window
// and announces its session id via announce (wired to announceDiscoveredOOBSession
// in production) ONLY at window close, and ONLY when exactly one candidate
// survived cwd corroboration over the whole window.
//
// Why observe the whole window before announcing (R2-1): codex writes its
// session_meta at session start, but an UNRELATED concurrent codex process
// (a second fresh/resumed session in the same project) can race ahead and write
// its same-cwd rollout FIRST, before this run's file appears. A mid-window
// announce (the pre-fix behaviour, which fired after a candidate survived two
// polls) could lock onto that unrelated id at ~0.75s and return before this
// run's own — or a genuinely-second — candidate ever showed up, making a later
// abstention impossible. Deferring the decision to window close means a second
// candidate that appears at ANY point in the window still forces abstention
// (the never-guess rule). The honest price is latency: the correlation badge
// lights up ~30s after launch rather than sub-second.
//
// Candidates are accumulated across polls (keyed by session id, preferring a
// poll that read a non-empty cwd) rather than trusting a single final scan, so a
// candidate whose meta was briefly unreadable still counts toward ambiguity.
//
// It does NOT close the window early on any signal short of ctx cancellation:
// no signal here can guarantee a second candidate cannot appear later, so
// (per the never-invent-an-early-close rule) it just waits the window. On ctx
// cancellation (the caller cancels when the child exits) it returns WITHOUT
// announcing — a short-lived run legitimately forgoes discovery correlation
// rather than risk announcing a same-cwd id that only looked unique because the
// window was cut short. (The primary attach case is a long-lived interactive
// session, whose window elapses while it is still running, so it still
// announces at the deadline.)
func runCodexDiscovery(ctx context.Context, roots []string, preexisting map[string]struct{}, startedAt time.Time, targetCwd string, cfg codexDiscoverConfig, announce func(string)) {
	deadline := time.Now().Add(cfg.window)
	// seen accumulates every new rollout observed across the WHOLE window, keyed
	// by session id. Merge rule: keep the first read, but upgrade a candidate
	// whose cwd was empty when first seen to a later poll that resolved it — so
	// cwd corroboration at window close uses the best meta read for each id.
	seen := make(map[string]codexRolloutCandidate)
	for {
		if ctx.Err() != nil {
			return // child exited: forgo discovery rather than risk a cut-short guess
		}
		for _, c := range scanNewCodexRollouts(roots, preexisting, startedAt) {
			if c.sessionID == "" {
				continue
			}
			if prev, ok := seen[c.sessionID]; !ok || (prev.cwd == "" && c.cwd != "") {
				seen[c.sessionID] = c
			}
		}
		if time.Now().After(deadline) {
			break
		}
		timer := time.NewTimer(cfg.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	// F1: cancel wins over a completed final scan. The caller cancels this ctx
	// the instant the child exits (codex.go, right after child.Wait), which can
	// land between the loop's last filesystem scan and this announce. Re-check
	// immediately before announcing so a window cut short by child exit never
	// announces a candidate that only looked unique because we stopped early —
	// the same never-guess-on-a-short-window rule the in-loop check enforces.
	if ctx.Err() != nil {
		return
	}
	// Window closed cleanly: announce IFF exactly one candidate survived cwd
	// corroboration over the whole window. Two or more (at any point) → abstain.
	cands := make([]codexRolloutCandidate, 0, len(seen))
	for _, c := range seen {
		cands = append(cands, c)
	}
	if id, count := selectDiscoveredCodexSession(cands, targetCwd); count == 1 {
		announce(id)
	}
}

// isCodexRolloutName reports whether a base filename is a codex rollout JSONL.
func isCodexRolloutName(base string) bool {
	return strings.HasPrefix(base, "rollout-") && strings.HasSuffix(base, ".jsonl")
}

// readCodexRolloutMeta reads ONLY the leading session_meta record of a rollout
// and returns its session id and cwd. It scans at most a few leading lines (the
// session_meta always leads the file) and stops as soon as it resolves an id.
// Mirrors parseRolloutForCapture's envelope handling (session_meta plus the
// legacy session_configured / session_start / turn_context envelopes; "id" then
// "session_id"). Returns ("", "") on any read/parse failure.
func readCodexRolloutMeta(path string) (sessionID, cwd string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for i := 0; i < 4; i++ {
		raw, rerr := br.ReadString('\n')
		line := strings.TrimRight(raw, "\r\n")
		if line != "" {
			var env struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if json.Unmarshal([]byte(line), &env) == nil {
				switch env.Type {
				case "session_meta", "session_configured", "session_start", "turn_context":
					var p struct {
						ID        string `json:"id"`
						SessionID string `json:"session_id"`
						Cwd       string `json:"cwd"`
					}
					if json.Unmarshal(env.Payload, &p) == nil {
						id := p.ID
						if id == "" {
							id = p.SessionID
						}
						if id != "" {
							return id, p.Cwd
						}
					}
				}
			}
		}
		if rerr != nil {
			// EOF or any read error: the meta line is the first record, so if we
			// haven't resolved an id by now this rollout yields nothing.
			return "", ""
		}
	}
	return "", ""
}

// sameCodexCwd reports whether two cwd strings denote the same directory. It
// compares cleaned paths, then falls back to symlink-resolved comparison so a
// symlinked project root corroborates. Best-effort: resolution failures fall
// back to the cleaned comparison.
func sameCodexCwd(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ra, erra := filepath.EvalSymlinks(a)
	rb, errb := filepath.EvalSymlinks(b)
	if erra == nil && errb == nil {
		return filepath.Clean(ra) == filepath.Clean(rb)
	}
	return false
}
