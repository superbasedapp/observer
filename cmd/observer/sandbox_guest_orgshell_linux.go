//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
)

// sandbox_guest_orgshell_linux.go holds the org-hosted OpenShell row's
// in-box verbs (g1-design.md sections 3.2, 4.2, 4.3 and 4.6, lane G4). They
// run inside the org's box as `observer sandbox-guest <verb>`; none of them
// calls the network, and none of them clones (the clone is a plain git exec,
// G1-D46):
//
//   - --hold: the box's keeper, the command the org compiled for the box; it
//     keeps the box running while the run's execs come and go, and ends on
//     SIGTERM;
//   - --paced-stdin -- <argv>: runs argv with its stdin handed through, and
//     reports the bytes consumed as credit lines on stderr, so the node's
//     wire client never outruns the gateway's bounded stdin buffer;
//   - --receive-part <n> --to <path>: writes one upload part from a one-shot
//     stdin, owner-only, never following a link, capped;
//   - --baseline: records the workspace HEAD as the run's return baseline;
//   - --diff: the staged diff of the workspace against the baseline;
//   - --bundle: the box's commits since the baseline as a git bundle on
//     stdout, with git's config and hooks neutralized.

// The verbs.
const (
	guestHoldFlag        = "--hold"
	guestReceivePartFlag = "--receive-part"
	guestBaselineFlag    = guestBaselineFlagCore
	guestDiffFlag        = "--diff"
	guestBundleFlag      = "--bundle"
)

func init() {
	guestExtraVerbs[guestHoldFlag] = runGuestHold
	guestExtraVerbs[guestPacedStdinFlag] = runGuestPacedStdin
	guestExtraVerbs[guestReceivePartFlag] = runGuestReceivePart
	guestExtraVerbs[guestBaselineFlag] = runGuestBaseline
	guestExtraVerbs[guestDiffFlag] = runGuestDiff
	guestExtraVerbs[guestBundleFlag] = runGuestBundle
}

// runGuestHold is the keeper: it waits for SIGTERM or SIGINT and exits 0.
func runGuestHold(args []string) int {
	if len(args) != 0 {
		return helperFail("observer sandbox-guest %s: takes no arguments", guestHoldFlag)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	<-ch
	return 0
}

// pacedStderr serializes the wrapper's stderr: the child's stderr bytes and
// the credit lines, so a credit line always starts a line.
type pacedStderr struct {
	mu          sync.Mutex
	w           io.Writer
	atLineStart bool
}

func (p *pacedStderr) child(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(b) == 0 {
		return
	}
	_, _ = p.w.Write(b)
	p.atLineStart = b[len(b)-1] == '\n'
}

func (p *pacedStderr) ack(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := osorg.AckLine(n)
	if !p.atLineStart {
		line = append([]byte{'\n'}, line...)
	}
	_, _ = p.w.Write(line)
	p.atLineStart = true
}

// runGuestPacedStdin runs argv with its stdin copied from the wrapper's own,
// acknowledging every chunk handed to the child. A child that stops reading
// blocks the copy, so no credit is reported and the node stops at its window.
func runGuestPacedStdin(args []string) int {
	if len(args) < 2 || args[0] != "--" {
		return helperFail("observer sandbox-guest %s: usage: %s -- <argv>", guestPacedStdinFlag, guestPacedStdinFlag)
	}
	return pacedStdinRun(args[1:], os.Stdin, os.Stdout, os.Stderr)
}

// pacedStdinRun is runGuestPacedStdin over explicit streams (a test seam).
func pacedStdinRun(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	//nolint:gosec // G204: the hosted core's own fixed guest argv
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = stdout
	in, err := cmd.StdinPipe()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestPacedStdinFlag, err)
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestPacedStdinFlag, err)
	}
	se := &pacedStderr{w: stderr, atLineStart: true}
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestPacedStdinFlag, err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := errPipe.Read(buf)
			se.child(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { _ = in.Close() }()
		buf := make([]byte, osorg.FrameBytes)
		var consumed int64
		for {
			n, rerr := stdin.Read(buf)
			if n > 0 {
				if _, werr := in.Write(buf[:n]); werr != nil {
					return
				}
				consumed += int64(n)
				se.ack(consumed)
			}
			if rerr != nil {
				return
			}
		}
	}()
	wg.Wait()
	err = cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return helperFail("observer sandbox-guest %s: %v", guestPacedStdinFlag, err)
}

// guestPartMax caps one received part (the wire client's one-shot bound plus
// slack).
const guestPartMax = osorg.MaxOneShotStdin + 4096

// guestPartRE is the shape of a part's file name.
var guestPartRE = regexp.MustCompile(`^\.upload\.[0-9a-f]{16}\.part\.[0-9]{1,6}$`)

// runGuestReceivePart writes one upload part from stdin: --receive-part <n>
// --to <path>. The path must be a part name in an existing owner-only
// directory; the file is created exclusively, owner-only, never through a
// link, and refused over guestPartMax.
func runGuestReceivePart(args []string) int {
	if len(args) != 3 || args[1] != "--to" {
		return helperFail("observer sandbox-guest %s: usage: %s <n> --to <path>", guestReceivePartFlag, guestReceivePartFlag)
	}
	if err := receivePart(args[0], args[2], os.Stdin); err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestReceivePartFlag, err)
	}
	return 0
}

func receivePart(n, to string, in io.Reader) error {
	if _, err := strconv.Atoi(n); err != nil {
		return fmt.Errorf("part number %q", n)
	}
	if !filepath.IsAbs(to) || filepath.Clean(to) != to || !guestPartRE.MatchString(filepath.Base(to)) || !strings.HasSuffix(to, ".part."+n) {
		return fmt.Errorf("part path %q is not an upload part name", to)
	}
	dir := filepath.Dir(to)
	fi, err := os.Lstat(dir) //nolint:gosec // G703: an upload part's directory, its name checked above against the part grammar
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not an owner-only directory", dir)
	}
	f, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600) //nolint:gosec // G304: an upload part path checked above
	if err != nil {
		return err
	}
	n64, err := io.Copy(f, io.LimitReader(in, guestPartMax+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n64 > guestPartMax {
		err = fmt.Errorf("the part is over %d bytes", guestPartMax)
	}
	if err != nil {
		_ = os.Remove(to) //nolint:gosec // G703: the part file this call just created exclusively
	}
	return err
}

// guestBaselineFile is the run's recorded baseline: the org core's
// BoxBaselineFile under the box's fixed run dir (OB-084), the file the org's
// collect reads.
var guestBaselineFile = osorg.BoxBaselineFile

// guestGitEnv is the fixed git environment of the return verbs: no system
// or global config, no prompt, no pager, no external diff.
func guestGitEnv() []string {
	return append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EXTERNAL_DIFF=")
}

// guestGitSafe are the per-command overrides that neutralize the
// repository's own exec-capable settings.
var guestGitSafe = []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}

func guestBaselinePath() (string, error) { return guestBaselineFile, nil }

// runGuestBaseline records HEAD of the working directory's repository as the
// run's baseline and prints it.
func runGuestBaseline(args []string) int {
	if len(args) != 0 {
		return helperFail("observer sandbox-guest %s: takes no arguments", guestBaselineFlag)
	}
	//nolint:gosec // G204: a fixed git argv
	out, err := exec.Command("git", append(append([]string(nil), guestGitSafe...), "rev-parse", "--verify", "HEAD")...).Output()
	if err != nil {
		return helperFail("observer sandbox-guest %s: no HEAD in the workspace: %v", guestBaselineFlag, err)
	}
	head := strings.TrimSpace(string(out))
	if !regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`).MatchString(head) {
		return helperFail("observer sandbox-guest %s: HEAD %q is not an object id", guestBaselineFlag, head)
	}
	p, err := guestBaselinePath()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestBaselineFlag, err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestBaselineFlag, err)
	}
	if err := os.WriteFile(p, []byte(head+"\n"), 0o600); err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestBaselineFlag, err)
	}
	fmt.Println(head)
	return 0
}

// guestBaseline reads the recorded baseline ("" when none).
func guestBaseline() string {
	p, err := guestBaselinePath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the run's own baseline file under the box run dir
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// guestReturnMax caps a diff or bundle written to stdout (the node checks
// it again with workspace.CheckReturnSize).
const guestReturnMax = 64 << 20

// runGuestDiff prints the workspace's changes against the baseline (or, with
// no baseline, against HEAD), staged first, with external diff and textconv
// drivers off.
func runGuestDiff(args []string) int {
	if len(args) != 0 {
		return helperFail("observer sandbox-guest %s: takes no arguments", guestDiffFlag)
	}
	env := guestGitEnv()
	add := exec.Command("git", append(append([]string(nil), guestGitSafe...), "add", "-A")...) //nolint:gosec // G204: a fixed git argv
	add.Env, add.Stderr = env, os.Stderr
	if err := add.Run(); err != nil {
		return helperFail("observer sandbox-guest %s: git add: %v", guestDiffFlag, err)
	}
	base := guestBaseline()
	if base == "" {
		base = "HEAD"
	}
	argv := append(append([]string(nil), guestGitSafe...), "diff", "--no-ext-diff", "--no-textconv", "--binary", "--cached", base)
	return guestCapped(guestDiffFlag, exec.Command("git", argv...), env) //nolint:gosec // G204: a fixed git argv
}

// runGuestBundle writes the commits since the baseline as a git bundle on
// stdout; exit 2 when there are none.
func runGuestBundle(args []string) int {
	if len(args) != 0 {
		return helperFail("observer sandbox-guest %s: takes no arguments", guestBundleFlag)
	}
	base := guestBaseline()
	if base == "" {
		return helperFail("observer sandbox-guest %s: no baseline recorded", guestBundleFlag)
	}
	env := guestGitEnv()
	//nolint:gosec // G204: a fixed git argv
	count, err := exec.Command("git", append(append([]string(nil), guestGitSafe...), "rev-list", "--count", base+"..HEAD")...).Output()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", guestBundleFlag, err)
	}
	if strings.TrimSpace(string(count)) == "0" {
		return 2
	}
	argv := append(append([]string(nil), guestGitSafe...), "bundle", "create", "-", base+"..HEAD")
	return guestCapped(guestBundleFlag, exec.Command("git", argv...), env) //nolint:gosec // G204: a fixed git argv
}

// guestCapped runs cmd with its stdout capped at guestReturnMax; over the
// cap it exits 3 (cut), as the staged diff one-shot does.
func guestCapped(verb string, cmd *exec.Cmd, env []string) int {
	cmd.Env, cmd.Stderr = env, os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", verb, err)
	}
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox-guest %s: %v", verb, err)
	}
	n, _ := io.Copy(os.Stdout, io.LimitReader(out, guestReturnMax))
	extra, _ := io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return helperFail("observer sandbox-guest %s: %v", verb, err)
	}
	if n == guestReturnMax && extra > 0 {
		return 3
	}
	return 0
}
