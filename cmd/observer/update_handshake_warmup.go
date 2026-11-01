//go:build !sbo_omit_org_update

package main

import (
	"context"
	"os/exec"
	"time"
)

// update_handshake_warmup.go is the Windows warm-up after `observer update`
// swaps the binary (lane shr-hookseam2, roadmap F0-3 revision 2.1). On
// Windows the FIRST run of a new executable costs about 2 s (p99 3.9 s on
// the JSP-2 laptop) while Microsoft Defender scans it; whichever process
// runs the file first pays it. Hooks exec the same file the update swapped
// in (the hook command is the installed path, or a launcher resolving to
// it: installshape.Decide), so the warm-up's job is to make sure the first
// run is not a hook.
//
// The daemon-driven apply already does that: its handshake starts the new
// binary as the successor daemon (superviseNewBinary) at
// Installed.ExecPath, the swapped-in file itself, before any hook can run
// it, so that child IS the warm-up and nothing is added. The CLI apply with
// no daemon running only probed the STAGED copy (a different path) and has
// no handshake child, so on Windows it runs the swapped-in file once,
// bounded, before returning. Off Windows there is no first-run scan and
// nothing runs.

// warmUpTimeout bounds the warm-up run: past the JSP-2 p99 with room, and
// short enough that a hung binary cannot hold `observer update apply`.
const warmUpTimeout = 30 * time.Second

// warmUpNoticeLine is the one line the CLI apply prints while the warm-up
// runs (applyDeps.WarmUpNotice).
const warmUpNoticeLine = "warming the new binary (the Windows first-run scan, at most 30 s)"

// warmUpRules is the warm-up decision, walked top to bottom; the first row
// that matches decides.
var warmUpRules = []struct {
	when func(goos string, hs handshakeResult) bool
	run  bool
	why  string
}{
	{func(goos string, _ handshakeResult) bool { return goos != "windows" }, false, "no first-run scan off Windows"},
	{func(_ string, hs handshakeResult) bool { return hs.Started }, false, "the handshake child already ran the swapped-in binary"},
	{func(string, handshakeResult) bool { return true }, true, "nothing has run the swapped-in binary yet"},
}

// warmUpNeeded reports whether the apply should run the swapped-in binary
// once before the first hook does, and why.
func warmUpNeeded(goos string, hs handshakeResult) (bool, string) {
	for _, r := range warmUpRules {
		if r.when(goos, hs) {
			return r.run, r.why
		}
	}
	return false, ""
}

// warmUpNewBinary runs exePath once with --version (the flag every probe of
// this binary uses; there is no `version` subcommand) and waits for it,
// bounded by warmUpTimeout. Its output and result are ignored: a binary
// that does not run was already refused by the staged probe, and the
// warm-up only exists to take the first-run scan off the hook path.
func warmUpNewBinary(ctx context.Context, exePath string) {
	wctx, cancel := context.WithTimeout(ctx, warmUpTimeout)
	defer cancel()
	cmd := exec.CommandContext(wctx, exePath, "--version") //nolint:gosec // the binary this apply just verified and swapped in
	_ = cmd.Run()
}
