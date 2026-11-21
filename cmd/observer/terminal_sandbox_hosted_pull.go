//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// terminal_sandbox_hosted_pull.go is the checkpoint transcript pull of a
// hosted run (sandbox plan v2 section 5.7, lane SBX-P7, orchestrator
// default): at every checkpoint and before the box is deleted, the host
// helper lists the tool's state directories in the box, plans the pull
// (internal/sandboxremote.PlanPull: regular files of a transcript shape,
// size-capped, nothing outside the tool's state), copies each file into a
// per-run quarantine directory owner-only and no-follow, and ingests them
// through the tool's own adapter with session and event ids re-keyed
// under the run id, so a box can never collide with or upgrade another
// session's rows. The run itself carries capture_origin = remote_sandbox.
//
// The in-box database row export with a closed versioned schema is a later
// item (named in docs/sandboxed-terminals.md).

// hostedQuarantineDir is a run's quarantine directory.
func hostedQuarantineDir(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), "quarantine", runID)
}

// hostedListCap bounds the box's file listing.
const hostedListCap = 4 << 20

// hostedExecOutput runs argv in the box (no PTY, no stdin) and returns its
// output, capped.
func hostedExecOutput(ctx context.Context, c sandboxremote.Client, boxID string, argv []string, env map[string]string, limit int64) ([]byte, int, error) {
	return hostedExecOutputIn(ctx, c, boxID, sandboxremote.ExecSpec{Argv: argv, Env: env}, limit)
}

// hostedExecOutputIn is hostedExecOutput for a whole spec (a working
// directory included); the PTY and stdin are never asked for.
func hostedExecOutputIn(ctx context.Context, c sandboxremote.Client, boxID string, spec sandboxremote.ExecSpec, limit int64) ([]byte, int, error) {
	spec.PTY, spec.Stdin = false, false
	p, err := c.Exec(ctx, boxID, spec)
	if err != nil {
		return nil, 0, err
	}
	defer p.Close()
	out, err := io.ReadAll(io.LimitReader(p, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(out)) > limit {
		return nil, 0, fmt.Errorf("the box's output is over %d bytes", limit)
	}
	code, err := p.Wait(ctx)
	return out, code, err
}

// parseBoxListing reads `find -type f -printf '%p\t%s\n'` output: path, a
// tab, the size. A line that does not parse is skipped.
func parseBoxListing(out []byte) []sandboxremote.BoxFile {
	var files []sandboxremote.BoxFile
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		p, size, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			continue
		}
		files = append(files, sandboxremote.BoxFile{Path: p, Size: n, Regular: true})
	}
	return files
}

// hostedPullResult is one pull's outcome.
type hostedPullResult struct {
	Pulled  []string
	Skipped []sandboxremote.Exclusion
}

// hostedPullTranscripts copies the tool's transcripts out of the box into
// the run's quarantine directory.
func hostedPullTranscripts(ctx context.Context, c sandboxremote.Client, boxID string, plan hostedPlanFile, layout sandboxremote.BoxLayout) (hostedPullResult, error) {
	var res hostedPullResult
	roots := make([]string, 0, len(plan.ToolStateRel))
	for _, rel := range plan.ToolStateRel {
		roots = append(roots, path.Join(layout.Home, filepath.ToSlash(rel)))
	}
	if len(roots) == 0 {
		return res, nil
	}
	// find never follows a link (no -L), and -type f lists regular files
	// only; a missing root is not an error.
	argv := append([]string{"find"}, roots...)
	argv = append(argv, "-type", "f", "-printf", `%p\t%s\n`)
	out, _, err := hostedExecOutput(ctx, c, boxID, argv, map[string]string{"HOME": layout.Home}, hostedListCap)
	if err != nil {
		return res, fmt.Errorf("list the box's transcripts: %w", err)
	}
	items, skipped := sandboxremote.PlanPull(roots, parseBoxListing(out), sandboxremote.PullLimits{})
	res.Skipped = skipped
	dir := hostedQuarantineDir(plan.ObserverDir, plan.RunID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, err
	}
	for _, it := range items {
		b, err := c.ReadFile(ctx, boxID, it.BoxPath, sandboxremote.DefaultPullLimits.MaxFileBytes)
		if err != nil {
			res.Skipped = append(res.Skipped, sandboxremote.Exclusion{Path: it.BoxPath, Reason: "read_failed"})
			continue
		}
		local, err := hostedQuarantineWrite(dir, it.LocalRel, b)
		if err != nil {
			return res, err
		}
		res.Pulled = append(res.Pulled, local)
	}
	return res, nil
}

// hostedQuarantineWrite writes one pulled file under dir: the relative path
// is cleaned and confined, every directory is created owner-only, a link
// in the way is refused, and the file is replaced through a fresh 0600
// file and a rename (never written through a link).
func hostedQuarantineWrite(dir, rel string, b []byte) (string, error) {
	clean := path.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) || strings.ContainsRune(clean, 0) {
		return "", fmt.Errorf("quarantine path %q escapes the run's directory", rel)
	}
	dst := filepath.Join(dir, filepath.FromSlash(clean))
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	for p := parent; p != dir && strings.HasPrefix(p, dir); p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			return "", fmt.Errorf("quarantine path %s is not a plain directory", p)
		}
	}
	tmp, err := os.CreateTemp(parent, ".pull-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	_ = tmp.Chmod(0o600)
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return "", werr
	}
	if fi, err := os.Lstat(dst); err == nil && !fi.Mode().IsRegular() {
		_ = os.Remove(name)
		return "", fmt.Errorf("quarantine path %s is not a regular file", dst)
	}
	return dst, os.Rename(name, dst)
}

// hostedIngester ingests pulled transcripts (a seam: the host helper opens
// the node database; a test records the call).
type hostedIngester func(ctx context.Context, tool string, runs hostedCaptureRuns, files []string) (hostedIngestOut, error)

// hostedCaptureRuns names the run namespace a pulled transcript event is
// re-keyed under (lane FX6, F-P7-4). A resumed run's box keeps the held
// run's transcripts, and the agent continues the same session, so its pull
// carries the held run's events too. The model turns of the held run were
// filed under the held run's id when they were made (the relay stamps the
// run that was live), so those events are re-keyed under that id as well,
// not under the resumed run's: each run's api_turns, actions and session
// row land under one id, and a later pull of the same events lands on the
// same keys (no second copy under the resumed run).
type hostedCaptureRuns struct {
	// Run is this run's id.
	Run string
	// Earlier is the id of the held run this run resumed ("" for a fresh
	// run): a run id from this node's own plan, never one the box names.
	Earlier string
	// Since is when this run started; an event before it is the earlier
	// run's.
	Since time.Time
}

// runFor is the run an event at t was captured by: the earlier run for an
// event before this run started, else this run. An event with no time, or
// an earlier id that is not a run id, stays with this run.
func (c hostedCaptureRuns) runFor(t time.Time) string {
	if c.Earlier != "" && c.Earlier != c.Run && sandboxremote.ValidRelayRunID(c.Earlier) && !t.IsZero() && !c.Since.IsZero() && t.Before(c.Since) {
		return c.Earlier
	}
	return c.Run
}

// hostedIngestOut is what one ingest did: the actions inserted, and the
// agent's own session ids the pulled transcripts carry (before the re-key),
// oldest last event first, so the last one is the session a resume
// continues (FX4 fix round 1, F-P6B-2b).
type hostedIngestOut struct {
	Actions  int
	Sessions []string
}

// hostedIngestPulled parses each pulled file with the tool's adapter and
// ingests it with every id re-keyed under the run. Idempotent: a later pull
// of the same file lands on the same quarantine path and the same keys.
func hostedIngestPulled(st *store.Store) hostedIngester {
	return func(ctx context.Context, tool string, runs hostedCaptureRuns, files []string) (hostedIngestOut, error) {
		a, err := adapterForBackfill(tool, "the hosted transcript pull")
		if err != nil {
			return hostedIngestOut{}, err
		}
		n := 0
		var errs []error
		last := map[string]time.Time{}
		for _, f := range files {
			res, err := a.ParseSessionFile(ctx, f, 0)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), err))
				continue
			}
			for _, ev := range res.ToolEvents {
				if t, seen := last[ev.SessionID]; ev.SessionID != "" && (!seen || ev.Timestamp.After(t)) {
					last[ev.SessionID] = ev.Timestamp
				}
			}
			for i := range res.ToolEvents {
				ev := &res.ToolEvents[i]
				runID := runs.runFor(ev.Timestamp)
				ev.SessionID = sandboxremote.RekeyID(runID, ev.SessionID)
				ev.SourceEventID = sandboxremote.RekeyID(runID, ev.SourceEventID)
			}
			for i := range res.TokenEvents {
				tk := &res.TokenEvents[i]
				runID := runs.runFor(tk.Timestamp)
				tk.SessionID = sandboxremote.RekeyID(runID, tk.SessionID)
				tk.SourceEventID = sandboxremote.RekeyID(runID, tk.SourceEventID)
			}
			out, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{IsNativeTool: nativeToolOf(a)})
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), err))
				continue
			}
			n += out.ActionsInserted
		}
		return hostedIngestOut{Actions: n, Sessions: hostedSessionOrder(last)}, errors.Join(errs...)
	}
}

// hostedMaxSessions bounds the session ids written to the box's
// sessions.json (the newest kept).
const hostedMaxSessions = 32

// hostedSessionOrder orders the agent's session ids by their last event,
// oldest first (ties by id), keeping only ids that are one printable token
// of at most 128 bytes and the newest hostedMaxSessions.
func hostedSessionOrder(last map[string]time.Time) []string {
	ids := make([]string, 0, len(last))
	for id := range last {
		if hostedSessionIDOK(id) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if !last[ids[i]].Equal(last[ids[j]]) {
			return last[ids[i]].Before(last[ids[j]])
		}
		return ids[i] < ids[j]
	})
	if len(ids) > hostedMaxSessions {
		ids = ids[len(ids)-hostedMaxSessions:]
	}
	return ids
}

// hostedSessionIDOK reports whether a session id from a box transcript may
// be written to sessions.json and passed to a resume argv: one token of
// printable ASCII, no space, no `|`, at most 128 bytes.
func hostedSessionIDOK(id string) bool {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, "-") {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c < 0x21 || c > 0x7e || c == '|' {
			return false
		}
	}
	return true
}
