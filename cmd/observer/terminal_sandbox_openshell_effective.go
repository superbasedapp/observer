//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_effective.go runs the gateway policy reads of
// lane FU8 (ledger OSH-40; the pure tables are
// internal/sandboxopenshell/effectivepolicy.go):
//
//   - probe row PS: the gateway's proposal settings and global policy, read
//     through the pinned gateway after the probe's other rows. External
//     mode refuses a gateway that widens or cannot be read; managed mode
//     refuses only a positive deviation, and keeps the reading for the
//     drift posture (the settings Observer's private gateway keeps in its
//     database, beside the gateway.toml drift).
//   - the box watch: the host helper reads the box's effective policy once
//     the box exists and then on its own tick, compares it with the rules
//     the plan compiled, and stops the box with a closed reason on any
//     widening or when the policy stays unreadable. It runs where the plan
//     asks for it (EffectiveCheck, set for an external gateway).

// openShellGatewayPolicyStep gathers row PS's facts.
func openShellGatewayPolicyStep(ctx context.Context, g *openShellGathering) {
	t := g.out.pin.Target
	var f sandboxopenshell.GatewayPolicyFacts
	if argv, err := sandboxopenshell.SettingsArgv(t); err == nil {
		res := g.runAt(ctx, t, openShellCLISpec, argv[1:])
		if res.Outcome == extrun.OutcomeOK {
			if s, err := sandboxopenshell.ParseGatewaySettings(res.Stdout); err == nil {
				f.SettingsRead, f.Settings = true, s
			}
		}
	}
	if argv, err := sandboxopenshell.GlobalPolicyArgv(t); err == nil {
		res := g.runAt(ctx, t, openShellCLISpec, argv[1:])
		switch res.Outcome {
		case extrun.OutcomeOK:
			f.Global = sandboxopenshell.ClassifyGlobalPolicy(true, res.Stdout)
		case extrun.OutcomeExitNonZero:
			f.Global = sandboxopenshell.ClassifyGlobalPolicy(false, append(append([]byte{}, res.Stdout...), res.Stderr...))
		}
	}
	g.out.facts.GatewayPolicy = f
	// The reading is the private gateway's only: an external probe resets
	// it, so a managed reading never outlives a switch of mode (FU8-A7).
	if g.out.facts.GatewayMode == sandboxopenshell.GatewayManaged {
		openShellRecordManagedDB(sandboxopenshell.ClassifyGatewayDB(f))
	} else {
		openShellRecordManagedDB(sandboxopenshell.GatewayDBNotRead)
	}
}

// openShellManagedDB is the last managed probe's database settings value
// (the drift posture folds it in; GatewayDBNotRead until a probe ran).
var openShellManagedDB atomic.Int32

// openShellRecordManagedDB records a managed probe's reading.
func openShellRecordManagedDB(d sandboxopenshell.GatewayDBDrift) {
	openShellManagedDB.Store(int32(d)) //nolint:gosec // G115: a small closed enum
}

// openShellManagedDBDrift returns the last reading.
func openShellManagedDBDrift() sandboxopenshell.GatewayDBDrift {
	return sandboxopenshell.GatewayDBDrift(openShellManagedDB.Load())
}

// The box watch's timing.
const (
	// openShellEffectiveFirstPoll is the interval while the box is not
	// readable yet (it is being created).
	openShellEffectiveFirstPoll = 2 * time.Second
	// openShellEffectiveWait bounds how long the first read may take; a box
	// whose policy is not read by then is stopped (never assumed narrow).
	openShellEffectiveWait = 2 * time.Minute
	// openShellEffectiveTick is the re-read interval once read (the
	// reaper's sweep interval: a proposal approved later is caught).
	openShellEffectiveTick = openShellPeriodicSweep
	// openShellEffectiveMissLimit is how many consecutive failed re-reads
	// stop the box.
	openShellEffectiveMissLimit = 4
)

// openShellEffectiveTiming is the watch's timing (tests shorten it).
type openShellEffectiveTiming struct {
	firstPoll, wait, tick time.Duration
	missLimit             int
}

// openShellEffectiveDefaults are the production timings.
var openShellEffectiveDefaults = openShellEffectiveTiming{
	firstPoll: openShellEffectiveFirstPoll, wait: openShellEffectiveWait,
	tick: openShellEffectiveTick, missLimit: openShellEffectiveMissLimit,
}

// openShellEffectiveRead is one read: ok false when the command did not
// answer (the box is not there yet, or the gateway did not answer).
type openShellEffectiveRead func(ctx context.Context) (answer []byte, ok bool)

// openShellEffectiveLoop is the watch: it returns the verdict and detail
// that stopped the box, or EffectiveMatch when ctx ended first.
func openShellEffectiveLoop(ctx context.Context, compiled []sandboxopenshell.NetRule, read openShellEffectiveRead, tm openShellEffectiveTiming) (sandboxopenshell.EffectiveVerdict, string) {
	deadline := time.NewTimer(tm.wait)
	defer deadline.Stop()
	// firstRead fires once, while nothing was read yet; it is dropped after
	// the first read (it bounds only the first read).
	firstRead := deadline.C
	misses := 0
	interval := tm.firstPoll
	for {
		if answer, ok := read(ctx); ok {
			v, d := sandboxopenshell.EffectiveVerdictOf(compiled, answer)
			if v != sandboxopenshell.EffectiveMatch {
				return v, d
			}
			firstRead, misses, interval = nil, 0, tm.tick
		} else if firstRead == nil {
			misses++
			if misses >= tm.missLimit {
				return sandboxopenshell.EffectiveUnreadable, fmt.Sprintf("%d reads in a row did not answer", misses)
			}
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return sandboxopenshell.EffectiveMatch, ""
		case <-firstRead:
			t.Stop()
			return sandboxopenshell.EffectiveUnreadable, "the box's effective policy was not read within " + tm.wait.String()
		case <-t.C:
		}
	}
}

// openShellEnforceStop enforces a stop the watch decided (fix rounds 1
// and 2, FU8-A6, FU8-R3): it deletes the box through the pinned gateway
// and says each outcome on the run's terminal; on any outcome but gone it
// terminates the supervised child (kill reports false while there is no
// child to kill yet, and is then retried on the next tick) and retries the
// delete every tick until the box is shown gone or ctx ends (the host
// helper then deletes again, and the daemon's reaper keeps trying).
func openShellEnforceStop(ctx context.Context, del func(context.Context) sandboxopenshell.Outcome, kill func() bool, say func(string), tick time.Duration) sandboxopenshell.Outcome {
	killed, told := false, false
	for {
		dctx, dcancel := context.WithTimeout(context.Background(), 2*openShellCmdTimeout)
		out := del(dctx)
		dcancel()
		if out == sandboxopenshell.OutcomeGone {
			say("the box was deleted (gone)")
			return out
		}
		if !told {
			say(fmt.Sprintf("the box delete answered %s; ending the run's session and retrying the delete every %s", out, tick))
			told = true
		} else {
			say(fmt.Sprintf("the box delete answered %s again; retrying", out))
		}
		if !killed && kill != nil {
			killed = kill()
		}
		t := time.NewTimer(tick)
		select {
		case <-ctx.Done():
			t.Stop()
			return out
		case <-t.C:
		}
	}
}

// openShellWatchEffectivePolicy starts the box watch for a run whose plan
// asks for it and returns its stop. On a widening it says so on the run's
// terminal and enforces the stop (openShellEnforceStop): kill terminates
// the supervised child when the box is not shown gone.
func openShellWatchEffectivePolicy(pf openShellPlanFile, kill func() bool) func() {
	if !pf.EffectiveCheck {
		return func() {}
	}
	runner := openShellRunner()
	pin := openShellPin{Target: pf.Target, Server: pf.Server}
	read := func(ctx context.Context) ([]byte, bool) {
		argv, err := sandboxopenshell.EffectivePolicyArgv(pf.Target, pf.Name)
		if err != nil || !openShellServerMatches(ctx, runner, pin) {
			return nil, false
		}
		res := openShellRunAt(ctx, runner, pf.Target, openShellCLISpec, argv[1:])
		return res.Stdout, res.Outcome == extrun.OutcomeOK
	}
	say := func(msg string) { fmt.Fprintf(os.Stderr, "\r\n[observer: %s]\r\n", msg) }
	del := func(ctx context.Context) sandboxopenshell.Outcome { return openShellDeleteBox(ctx, runner, pf) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		v, detail := openShellEffectiveLoop(ctx, pf.Network, read, openShellEffectiveDefaults)
		if v == sandboxopenshell.EffectiveMatch || ctx.Err() != nil {
			return
		}
		say(fmt.Sprintf("the box is stopped (%s): the OpenShell gateway's effective policy for it is wider than the rules Observer compiled, or could not be read (%s); ledger OSH-40", v, detail))
		openShellEnforceStop(ctx, del, kill, say, openShellEffectiveDefaults.tick)
	}()
	return func() {
		cancel()
		<-done
	}
}
