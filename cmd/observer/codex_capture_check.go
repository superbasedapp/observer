// codex_capture_check.go — post-flight V5-1 detection.
//
// After `observer codex` exits, we cross-reference codex's on-disk
// rollout JSONL against the proxy's api_turns table. The watcher path
// always picks up the JSONL (token_count events are written to disk
// regardless of which app-server handled the HTTP), but the proxy
// only sees turns that actually rode through observer's port. When
// codex's global IPC pipe routed the call through a long-running
// `app-server` instead (V5-1), the JSONL has token_count events but
// api_turns has zero matching rows for the spawned session_id.
//
// The helper produces one stderr line — never multi-line — and
// returns it to the caller. The wrapper writes it after child.Run()
// completes (success OR failure exit code). Errors from the helper
// are swallowed by the caller because this is diagnostic-only: a
// stale DB or a transient FS hiccup must never fail the wrapper.

package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codexipc"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// validateCaptureRate compares per-session token_count counts in codex
// rollout JSONL files touched since cmdStart against the api_turns
// rows captured by the proxy for those session_ids. Returns the
// (single-line) warning string when a bypass is detected, or "" when
// every session was captured (or there's nothing to compare).
//
// preflight is the slice returned by codexipc.Detect at pre-flight
// time; non-empty preflight changes the warning copy to point back at
// the shared app-server(s) the operator was already warned about.
func validateCaptureRate(ctx context.Context, configPath string, cmdStart time.Time, preflight []codexipc.Process) (string, error) {
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return "", err
	}
	defer cleanup()

	// Stamp cmdStart in the same RFC3339Nano UTC format the store
	// writes timestamps in (internal/store/store.go::timestamp).
	startStamp := cmdStart.UTC().Format(time.RFC3339Nano)

	// Walk every plausible CODEX_HOME for rollout-*.jsonl files
	// touched at-or-after cmdStart. Sessions live under
	// <codex_home>/sessions/, with codex 0.130+ bucketing them under
	// YYYY/MM/ subdirs.
	type jsonlScan struct {
		path       string
		sessionID  string
		tokenCount int
	}
	var scans []jsonlScan
	for _, root := range codexHomeRoots() {
		sessionsDir := filepath.Join(root, "sessions")
		_ = filepath.WalkDir(sessionsDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // skip directories we can't read
			}
			if d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			if !strings.HasPrefix(base, "rollout-") || !strings.HasSuffix(base, ".jsonl") {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().Before(cmdStart) {
				return nil
			}
			sid, tk, perr := parseRolloutForCapture(path)
			if perr != nil || sid == "" {
				return nil
			}
			scans = append(scans, jsonlScan{path: path, sessionID: sid, tokenCount: tk})
			return nil
		})
	}

	if len(scans) == 0 {
		// No rollout files touched in the window — nothing to validate.
		return "", nil
	}

	var jsonlTotal, proxyTotal int
	for _, s := range scans {
		jsonlTotal += s.tokenCount
		n, qerr := countAPITurnsForSession(ctx, database, s.sessionID, startStamp)
		if qerr != nil {
			// Best-effort — surface the first error but keep going so
			// the caller still emits a useful warning when possible.
			return "", qerr
		}
		proxyTotal += n
	}

	if jsonlTotal == 0 {
		// Codex hit an auth error / aborted before any LLM call;
		// nothing to capture, nothing to warn about.
		return "", nil
	}

	switch {
	case proxyTotal == 0 && len(preflight) > 0:
		return fmt.Sprintf(
			"observer codex: 0 of %d codex turn(s) reached observer's proxy in this run - confirms the shared app-server(s) above bypassed the proxy. Re-run with `observer codex --exclusive`, or see https://superbased.app/docs/setup/codex.",
			jsonlTotal,
		), nil
	case proxyTotal == 0:
		return fmt.Sprintf(
			"observer codex: 0 of %d codex turn(s) reached observer's proxy in this run - capture failed but no shared app-server was detected at pre-flight; please report it at https://github.com/superbasedapp/observer/issues. See https://superbased.app/docs/setup/codex.",
			jsonlTotal,
		), nil
	case proxyTotal < jsonlTotal:
		return fmt.Sprintf(
			"observer codex: only %d of %d codex turn(s) captured by proxy; partial proxy bypass. See https://superbased.app/docs/setup/codex.",
			proxyTotal, jsonlTotal,
		), nil
	default:
		return "", nil
	}
}

// codexHomeRoots returns every directory that might be a CODEX_HOME on
// this host. Env-set CODEX_HOME wins; otherwise we union
// crossmount.AllHomes() with ".codex" so a wrapper running in WSL2
// picks up /mnt/c/Users/<u>/.codex and vice versa. Mirrors the codex
// adapter's WatchPaths logic at internal/adapter/codex/adapter.go:59.
func codexHomeRoots() []string {
	if env := os.Getenv("CODEX_HOME"); env != "" {
		return []string{env}
	}
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".codex"))
	}
	return roots
}

// effectiveCodexHome returns the SINGLE CODEX_HOME codex will actually load for a
// launch on THIS host (finding 3b): env CODEX_HOME when set, else ~/.codex. This
// is the ONLY home whose config may drive the fail-closed routing verdict — the
// cross-mount union codexHomeRoots() returns (foreign-OS Windows homes under
// /mnt/c/... when running in WSL, and vice-versa) will NOT be read by this
// launch, so a stale route there must never refuse it. Returns "" only when the
// home dir cannot be resolved and no override is set.
func effectiveCodexHome() string {
	if env := os.Getenv("CODEX_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex")
}

// effectiveCodexHomeRoots is effectiveCodexHome as the single-element list the
// route-detection helpers take. Empty when no home resolves (the caller then
// scans nothing — fail-open, never a false refusal).
func effectiveCodexHomeRoots() []string {
	if h := effectiveCodexHome(); h != "" {
		return []string{h}
	}
	return nil
}

// codexForeignHomeRoots returns the cross-mount CODEX_HOME roots that are NOT the
// effective one for this launch — the foreign-OS homes used ONLY for a
// non-blocking WARN (finding 3b), never as a fail-closed verdict input.
func codexForeignHomeRoots() []string {
	eff := effectiveCodexHome()
	var out []string
	for _, r := range codexHomeRoots() {
		if eff == "" || filepath.Clean(r) != filepath.Clean(eff) {
			out = append(out, r)
		}
	}
	return out
}

// parseRolloutForCapture is the minimal JSONL reader the post-flight
// check needs: pulls the session UUID from the rollout's metadata
// envelope and counts inner event_msg/token_count events.
//
// Envelope type matching (V6-1):
//   - Codex 0.130+ emits top-level "session_meta" with payload.id
//     (the session UUID).
//   - Older codex builds emit "session_configured" / "session_start"
//     / "turn_context" with payload.session_id (or payload.id; the
//     codex adapter declares both per internal/adapter/codex/
//     adapter.go::sessionContext at line 161).
//
// We match BOTH envelope types and try BOTH payload field names so
// the check is forward + backward compatible across codex schema
// flips. The v1.7.4 ship matched only "session_configured" + reads
// "session_id" — silently dropped every codex 0.130+ rollout and
// suppressed the V6-1 / V6-2 / V6-3 capture warnings the helper was
// designed to surface.
//
// Uses bufio.Reader.ReadString (NOT Scanner) per
// feedback_jsonl_parser_cursor — Scanner mis-handles CRLF + empty
// lines and would silently truncate the cursor on a live-written
// JSONL. Tolerates EOF mid-line: codex may still be flushing as we
// scan.
func parseRolloutForCapture(path string) (sessionID string, tokenCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for {
		raw, rerr := br.ReadString('\n')
		// Process whatever we got even if rerr is non-nil (EOF / partial).
		line := strings.TrimRight(raw, "\r\n")
		if line != "" {
			var env struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if jerr := json.Unmarshal([]byte(line), &env); jerr == nil {
				switch env.Type {
				// session_meta is the codex 0.130+ top-level envelope
				// for rollout metadata. session_configured /
				// session_start / turn_context are legacy / co-existing
				// envelopes that older codex builds use. Both are
				// handled the same way: extract whichever payload UUID
				// is present.
				case "session_meta", "session_configured", "session_start", "turn_context":
					if sessionID == "" {
						var p struct {
							ID        string `json:"id"`
							SessionID string `json:"session_id"`
						}
						if jerr := json.Unmarshal(env.Payload, &p); jerr == nil {
							// Prefer the modern "id" field. Fall back
							// to legacy "session_id". Mirrors
							// sessionContext at internal/adapter/codex/
							// adapter.go:161 which declares both.
							if p.ID != "" {
								sessionID = p.ID
							} else if p.SessionID != "" {
								sessionID = p.SessionID
							}
						}
					}
				case "event_msg":
					var p struct {
						Type string `json:"type"`
					}
					if jerr := json.Unmarshal(env.Payload, &p); jerr == nil && p.Type == "token_count" {
						tokenCount++
					}
				}
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return sessionID, tokenCount, nil
			}
			return sessionID, tokenCount, rerr
		}
	}
}

// countAPITurnsForSession returns the number of api_turns rows the
// proxy recorded for the given session_id with timestamp >= start.
// SessionID NULL rows aren't counted (only rows we can definitively
// attribute to this codex session).
func countAPITurnsForSession(ctx context.Context, database *sql.DB, sessionID, start string) (int, error) {
	if sessionID == "" {
		return 0, nil
	}
	var n int
	row := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_turns WHERE session_id = ? AND timestamp >= ?`,
		sessionID, start)
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("count api_turns for session %s: %w", sessionID, err)
	}
	return n, nil
}
