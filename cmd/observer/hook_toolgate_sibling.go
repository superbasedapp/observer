package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Sibling tool-gate firings (FU-127). A tool whose registry row serves tool
// gates in TWO dialects can see one action through both: Devin Desktop runs
// the Devin CLI hooks file (~/.config/devin/config.json, a Claude-style
// PreToolUse in the claude-json dialect) and the Cascade hooks file
// (~/.codeium/windsurf/hooks.json, pre_run_command and its siblings in the
// cascade dialect), so one shell call is two hook processes (Mac round 3).
// Each firing is judged and answered as before: the verdicts are the same
// rules over the same action, and the host blocks when either blocks. Only
// the record is collapsed: the firing that persists second skips the
// guard_events row and the alert when the sibling dialect's firing recorded
// the same verdict on the same action within siblingGateWindow.
//
// The pair is matched on the judged action (event kind, target, rule,
// decision), never on the session: the two payloads key the session
// differently (session_id vs trajectory_id). A firing consumes the
// sibling's marker when it skips, so the next identical call on a
// dual-firing host is recorded again, and a host that fires one channel
// (Devin CLI, Windsurf) never sees a sibling marker and records every call.
// Two firings that persist at the same instant can both record (the bound is
// best effort, like guardposture.AllowOnce); no marker directory (no spool
// path) records every firing.

// siblingGateWindow is how long a recorded verdict waits for its sibling
// firing: one call's two hook processes run back to back.
const siblingGateWindow = 10 * time.Second

// siblingGateEvents returns the native events of tool's other served tool
// gates whose dialect differs from b's: the channels a second firing of the
// same action can arrive on. nil for a tool with one tool-gate dialect.
func siblingGateEvents(tool string, b integration.HookBinding) []string {
	c, ok := integration.For(tool)
	if !ok {
		return nil
	}
	var out []string
	for _, s := range c.Hook.Bindings {
		if toolGateServed(s) && s.Dialect != b.Dialect && s.NativeEvent != b.NativeEvent {
			out = append(out, s.NativeEvent)
		}
	}
	return out
}

// siblingGateMarker is the marker file of one recorded verdict on one
// channel, named by a hash (never the target itself).
func siblingGateMarker(dir, tool, event string, v guard.ActionVerdict) string {
	sum := sha256.Sum256([]byte(tool + "\x00" + event + "\x00" + string(v.Kind) + "\x00" + v.Input.Target + "\x00" + v.Verdict.RuleID + "\x00" + v.Verdict.Decision.String()))
	return filepath.Join(dir, "sibling-"+hex.EncodeToString(sum[:8]))
}

// recordSiblingGateOnce wraps a tool gate's persist so a verdict its
// sibling dialect already recorded for the same action is not recorded
// again (see the file comment). persist is returned unchanged for a tool
// with no sibling dialect or with no marker directory.
func recordSiblingGateOnce(tool string, b integration.HookBinding, spoolPath string, persist func(guard.ActionVerdict)) func(guard.ActionVerdict) {
	siblings := siblingGateEvents(tool, b)
	dir := guardposture.RateLimitDir(spoolPath)
	if len(siblings) == 0 || dir == "" {
		return persist
	}
	return func(v guard.ActionVerdict) {
		now := siblingGateNow()
		for _, ev := range siblings {
			m := siblingGateMarker(dir, tool, ev, v)
			fi, err := os.Stat(m)
			if err != nil {
				continue
			}
			if age := now.Sub(fi.ModTime()); age < -siblingGateWindow || age >= siblingGateWindow {
				_ = os.Remove(m)
				continue
			}
			// Consuming the marker claims the pair: of two processes that
			// both see it, only the one whose remove succeeds skips.
			if os.Remove(m) == nil {
				return
			}
		}
		persist(v)
		// The marker is dated when the record has landed, not when this
		// firing started: the window is how long the marker waits for the
		// sibling, and a slow persist (a first database open that runs the
		// migration chain) must not spend it. Dated before the persist, a
		// persist longer than the window left a marker the sibling already
		// saw as stale, and both firings recorded.
		markSiblingGateRecorded(siblingGateMarker(dir, tool, b.NativeEvent, v), siblingGateNow())
	}
}

// siblingGateNow is the sibling marker clock (a seam for the persist-duration
// regression test).
var siblingGateNow = time.Now

// markSiblingGateRecorded stamps a recorded verdict's marker (best effort:
// without it the sibling firing records too, as before).
func markSiblingGateRecorded(marker string, now time.Time) {
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	if f.Close() == nil {
		_ = os.Chtimes(marker, now, now)
	}
}
