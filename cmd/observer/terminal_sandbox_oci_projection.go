//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxsignin"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// terminal_sandbox_oci_projection.go is G27 for the container driver (plan
// 5.4, lane SBX-P3C): a run whose tool state is projected starts from the
// tool's seed row (internal/integration projectionseed.go: non-secret
// files only, never a credential), and its transcript subtrees are watch
// roots of the host watcher for the run's life, read by the tool's own
// adapter. The roots go when the run's projection is removed (the helper
// after the run, Destroy, or the daemon-start sweep).

// ociSeedMaxBytes caps one seeded file.
const ociSeedMaxBytes = 1 << 20

// ociProjectionWatchPoll is how often a watched projection is checked for
// its end (its directory removed); a variable for tests.
var ociProjectionWatchPoll = 5 * time.Second

// ociSeedProjection seeds the projection from tool's seed row and creates
// its transcript subtrees; it returns those subtrees. A tool with no row
// starts empty and has none (G27 owed for it).
func ociSeedProjection(home string, proj []sandboxoci.ProjectedDir, tool string) ([]sandboxoci.TranscriptRoot, error) {
	seed, ok := integration.ProjectionSeedFor(tool)
	if !ok || len(proj) == 0 {
		return nil, nil
	}
	copies, roots, err := sandboxoci.PlanSeeds(proj, home, seed.Files, seed.Transcripts)
	if err != nil {
		return nil, err
	}
	for _, c := range copies {
		if err := ociCopySeed(c.From, c.To); err != nil {
			return nil, err
		}
	}
	for _, r := range roots {
		if err := os.MkdirAll(r.Host, 0o700); err != nil {
			return nil, fmt.Errorf("create a projected transcript directory: %w", err)
		}
	}
	return roots, nil
}

// ociSeedSignIn carries out the run's sign-in decision (lane BOXSIGNIN):
// for a consented run with a projection it copies exactly the decision's
// files into it (sandboxSeedSignIn: confined, regular, capped, owner-only,
// each source resolved through the vendor's relocation rule) and returns
// the posture line and the names copied. A run with no projection binds the
// tool's own state (oci-runc running this machine's tool, or an image still
// to be pulled that turned out to), so it shares the tool's sign-in with
// the box whatever the decision was, and says so plainly (operator ruling
// P-183). A tool with no sign-in row says nothing.
func ociSeedSignIn(home string, proj []sandboxoci.ProjectedDir, tool string, dec sandboxsignin.Decision) (string, []string, error) {
	row, ok := integration.SandboxSignInFor(tool)
	switch {
	case !ok:
		return "", nil, nil
	case len(proj) == 0:
		return sandboxsignin.SharedLine(tool, row.Files), nil, nil
	case dec.Verdict == "":
		return "", nil, nil
	case dec.Verdict != sandboxsignin.VerdictSeed:
		return sandboxsignin.PostureLine(tool, dec, nil), nil, nil
	}
	copies, _, err := sandboxoci.PlanSeeds(proj, home, dec.Files, nil)
	if err != nil {
		return "", nil, sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: %s's sign-in is not copied: its file has no place in this run's projected state: %v", tool, err)}
	}
	places := make([]sandboxSignInPlace, 0, len(copies))
	for _, c := range copies {
		places = append(places, sandboxSignInPlace{to: c.To})
	}
	plan, err := sandboxSignInPlan(home, places, tool, dec.Files, sandboxSignInGetenv())
	if err != nil {
		return "", nil, err
	}
	copied, err := sandboxSeedSignIn(plan)
	if err != nil {
		return "", nil, err
	}
	return sandboxsignin.PostureLine(tool, dec, copied), copied, nil
}

// seedRunSignIn carries out run's sign-in decision (ociSeedSignIn): the
// posture line goes first on the run's terminal, and a run that got a copy
// writes the daemon's one log line, the tool and the file names only.
func (d *ociDriver) seedRunSignIn(home string, proj []sandboxoci.ProjectedDir, run termsvc.SandboxRun, choice *ociRunChoice) error {
	line, copied, err := ociSeedSignIn(home, proj, run.Tool, choice.signIn)
	if err != nil {
		return err
	}
	if line != "" {
		choice.notices = append(choice.notices, line)
	}
	if len(copied) > 0 && d.r.logger != nil {
		d.r.logger.Info("terminal_sandbox: sign-in seeded", "run", run.ID, "tool", run.Tool, "files", copied)
	}
	return nil
}

// ociCopySeed copies one seed file: the source is opened no-follow and must
// be a regular file under the cap (a missing one is skipped: the tool has
// none), the copy is created fresh and owner-only.
func ociCopySeed(from, to string) error {
	lfi, err := os.Lstat(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("seed %s: %w", from, err)
	}
	if !lfi.Mode().IsRegular() || lfi.Size() > ociSeedMaxBytes {
		return fmt.Errorf("seed %s: not a regular file under %d bytes (a symlink is never followed), not seeded", from, ociSeedMaxBytes)
	}
	src, err := os.Open(from) //nolint:gosec // G304: a seed row's file under the real home, lstat-checked regular
	if err != nil {
		return fmt.Errorf("seed %s: %w", from, err)
	}
	defer func() { _ = src.Close() }()
	if fi, err := src.Stat(); err != nil || !os.SameFile(fi, lfi) {
		return fmt.Errorf("seed %s: the file changed while it was opened, not seeded", from)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the run's own fresh projected directory
	if err != nil {
		return fmt.Errorf("seed %s: %w", to, err)
	}
	_, werr := io.Copy(dst, io.LimitReader(src, ociSeedMaxBytes))
	if cerr := dst.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// watchProjection registers a run's transcript roots with the daemon's
// watcher (nothing outside the daemon) and keeps them until a root's
// directory is gone or unwatchProjection is called. It reports whether the
// watcher took every root (false outside the daemon, a CLI launch).
func (d *ociDriver) watchProjection(runID, tool, workspace string, roots []sandboxoci.TranscriptRoot) bool {
	fnp := sandboxProjectionWatcher.Load()
	if fnp == nil || len(roots) == 0 {
		return false
	}
	var removes []func()
	for _, r := range roots {
		// Bound to the run (audit finding 3): the transcripts' cwd and
		// session ids are the box's word.
		rm, err := (*fnp)(context.Background(), tool, r.Host, r.Box, watcher.ProjectionBinding{RunID: runID, Workspace: workspace})
		if err != nil {
			if d.r.logger != nil {
				d.r.logger.Warn("terminal_sandbox: the projected transcripts are not watched", "run", runID, "root", r.Host, "err", err)
			}
			continue
		}
		removes = append(removes, rm)
	}
	if len(removes) == 0 {
		return false
	}
	d.watches.Store(runID, removes)
	poll := ociProjectionWatchPoll
	go func() {
		t := time.NewTicker(poll)
		defer t.Stop()
		for range t.C {
			if _, ok := d.watches.Load(runID); !ok {
				return
			}
			for _, r := range roots {
				if _, err := os.Lstat(r.Host); err != nil {
					d.unwatchProjection(runID)
					return
				}
			}
		}
	}()
	return len(removes) == len(roots)
}

// unwatchProjection removes a run's projection roots from the watcher.
func (d *ociDriver) unwatchProjection(runID string) {
	v, ok := d.watches.LoadAndDelete(runID)
	if !ok {
		return
	}
	removes, _ := v.([]func())
	for _, rm := range removes {
		rm()
	}
}

// ociTranscriptHosts are the host sides of roots (the plan file's list).
func ociTranscriptHosts(roots []sandboxoci.TranscriptRoot) []string {
	var out []string
	for _, r := range roots {
		out = append(out, r.Host)
	}
	return out
}
