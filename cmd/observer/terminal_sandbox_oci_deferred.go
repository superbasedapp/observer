//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_oci_deferred.go is R-037: on a dashboard launch whose
// Observer default image is not on the engine yet, the pull happened in the
// daemon before the terminal existed, so its announcement (the source, the
// declared size and the bounds) reached the terminal only after the
// download. Now the daemon's Create leaves the pull pending
// (ociRunChoice.pending, only when termsvc sets DeferSlowPrep), Attach
// returns a helper argv that waits (ociDeferredFlag), and the pull, the
// checks that read the image and the plan run in the daemon after the
// terminal opened. The helper shows every line the daemon says as it is
// said, the announcement first, then runs the real host step with the argv
// the daemon wrote, in the same process (no exec: the trusted launcher
// channel the PTY child was given is kept). A refusal on the way is shown
// and ends the run; nothing of the agent ran. The CLI path is unchanged: it
// pulls inline.

// ociDeferredFlag selects the helper's waiting mode.
const ociDeferredFlag = "--deferred"

// The deferred run's files, in an owner-only dir under the oci state dir:
// the daemon's lines, the helper's count of the bytes it has shown, the real
// argv and a refusal.
const (
	ociDeferredProgress = "progress"
	ociDeferredShown    = "shown"
	ociDeferredArgv     = "argv.json"
	ociDeferredRefused  = "refused"
)

// ociDeferredAckWait bounds how long the daemon waits for the terminal to
// show the announcement before it starts the pull; past it nothing is
// pulled.
var ociDeferredAckWait = 60 * time.Second

// ociDeferredWait bounds the helper's wait for the daemon: the pull's own
// bound plus the checks that follow.
var ociDeferredWait = func() time.Duration { return ociDefaultPullTimeout + 5*time.Minute }

// ociPendingPrep is what Create left for Attach: the trusted image and the
// launch request the image-dependent checks need.
type ociPendingPrep struct {
	trust     ociImageTrust
	req       termsvc.PrepareRequest
	installID string
}

func init() {
	// The deferred argv still names the run's relay, so its capture health
	// binds to the terminal run as for any other launch.
	sandboxWrapRelays = append(sandboxWrapRelays, ociDeferredRelayOfWrap)
}

// ociDeferredDir is one run's deferred dir.
func ociDeferredDir(observerDir, runID string) string {
	return filepath.Join(ociStateDir(observerDir), "deferred", runID)
}

// attachDeferred makes the run's deferred dir, starts the daemon's half and
// returns the waiting helper's argv.
func (d *ociDriver) attachDeferred(created termsvc.CreateResult, res sandboxoci.ProbeResult, choice ociRunChoice) ([]string, error) {
	run := created.Run
	if !sandboxoci.ValidToken(run.ID) {
		return nil, fmt.Errorf("terminal_sandbox: the run id %q is not a token", run.ID)
	}
	dir := ociDeferredDir(d.r.observerDir, run.ID)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: the deferred launch dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := ociCreateExcl(filepath.Join(dir, ociDeferredProgress))
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: the deferred launch progress: %w", err)
	}
	_ = f.Close()
	go d.finishDeferred(created, res, choice, dir)
	return []string{d.r.observerBin, ociHostVerb, ociDeferredFlag, dir, "--relay-run", run.ID, "--observer-dir", d.r.observerDir}, nil
}

// ociDeferredRelayOfWrap reads the relay run back from a deferred argv.
func ociDeferredRelayOfWrap(argv []string) (runID, observerDir string, ok bool) {
	if len(argv) != 8 || argv[1] != ociHostVerb || argv[2] != ociDeferredFlag || argv[4] != "--relay-run" || argv[6] != "--observer-dir" {
		return "", "", false
	}
	return argv[5], argv[7], argv[5] != ""
}

// finishDeferred is the daemon's half: the pull (announced first), the
// read-back, the checks that read the image, then the plan; the helper
// gets the argv or the refusal.
func (d *ociDriver) finishDeferred(created termsvc.CreateResult, res sandboxoci.ProbeResult, choice ociRunChoice, dir string) {
	runID := created.Run.ID
	refuse := func(err error) {
		d.choices.Delete(runID)
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, runID)
		_ = ociDeferredWrite(dir, ociDeferredRefused, []byte(err.Error()))
		if d.r.logger != nil {
			d.r.logger.Warn("terminal_sandbox: deferred launch refused", "run", runID, "err", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), ociDeferredWait())
	defer cancel()
	c, err := ociEngineClient(res.Socket, res.Identity.APIVersion)
	if err != nil {
		refuse(fmt.Errorf("terminal_sandbox: %w", err))
		return
	}
	p := choice.pending
	size, err := ociDeferredPull(ctx, c, p.trust, d.r.observerDir, dir, func(l string) {
		if d.r.logger != nil {
			d.r.logger.Info("terminal_sandbox: default image", "progress", l)
		}
	})
	if err != nil {
		refuse(fmt.Errorf("terminal_sandbox: %w", err))
		return
	}
	id, err := c.ImageIdentity(ctx, choice.image)
	if err != nil {
		refuse(fmt.Errorf("terminal_sandbox: %s: the engine did not answer about the pulled image: %w", sandboxoci.VerdictArtifactUnverified, err))
		return
	}
	if r := ociCheckDefaultImage(p.trust, id); !r.OK {
		refuse(fmt.Errorf("terminal_sandbox: %s", r.Error()))
		return
	}
	choice.notices = append(choice.notices, fmt.Sprintf("Observer's default image %s (%s) was pulled from %s for this launch", choice.image, sandboxoci.HumanBytes(size), p.trust.desc.Repository))
	note := ""
	if err := d.checkPulledChoice(ctx, c, res, p.req, p.installID, &choice, &note); err != nil {
		refuse(err)
		return
	}
	choice.pending = nil
	d.choices.Store(runID, choice)
	wrap, err := d.compose(created, res)
	if err != nil {
		refuse(err)
		return
	}
	b, err := json.Marshal(wrap)
	if err != nil {
		refuse(err)
		return
	}
	if err := ociDeferredWrite(dir, ociDeferredArgv, b); err != nil {
		refuse(fmt.Errorf("terminal_sandbox: hand the plan to the terminal: %w", err))
	}
}

// ociDeferredPull is the deferred pull: every line goes to the run's
// progress file, and the first (the announcement: source, declared size and
// bounds) is held until the terminal has shown it, so the download starts
// only after the user could read it (R-037). log also gets each line.
func ociDeferredPull(ctx context.Context, c *sandboxengine.Client, trust ociImageTrust, observerDir, dir string, log func(string)) (int64, error) {
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	first := true
	var ackErr error
	_, size, err := ociPullDefault(pctx, c, trust, observerDir, func(l string) {
		log(l)
		end := ociDeferredSay(dir, l)
		if first {
			first = false
			if ackErr = ociDeferredAwaitShown(pctx, dir, end, ociDeferredAckWait); ackErr != nil {
				// The download must not start: the pull's context ends
				// before its request is sent.
				cancel()
			}
		}
	})
	if ackErr != nil {
		return 0, ackErr
	}
	return size, err
}

// errOCIDeferredNotShown: the terminal never showed the announcement.
var errOCIDeferredNotShown = errors.New("the run's terminal did not show the pull's announcement in time, so nothing was pulled")

// ociDeferredAwaitShown waits until the helper has shown at least end bytes
// of the progress file, or until wait passes or ctx ends.
func ociDeferredAwaitShown(ctx context.Context, dir string, end int64, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if b, err := readOwnedNoFollow(filepath.Join(dir, ociDeferredShown), 64); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n >= end {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errOCIDeferredNotShown
}

// ociDeferredSay appends one line to the run's progress file and returns
// the file's size after it.
func ociDeferredSay(dir, line string) int64 {
	f, err := os.OpenFile(filepath.Join(dir, ociDeferredProgress), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the run's own owner-only deferred dir
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(strings.ReplaceAll(line, "\n", " ") + "\n")
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

// ociDeferredWrite writes name in dir whole: an owner-only temp file renamed
// over it, so the helper never reads half a file.
func ociDeferredWrite(dir, name string, b []byte) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	_ = os.Remove(tmp) //nolint:gosec // G703: the run's own owner-only deferred dir under the observer dir
	f, err := ociCreateExcl(tmp)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp) //nolint:gosec // G703: the run's own owner-only deferred dir under the observer dir
		return werr
	}
	return os.Rename(tmp, filepath.Join(dir, name)) //nolint:gosec // G703: the run's own owner-only deferred dir under the observer dir
}
