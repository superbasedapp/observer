package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
)

// spoolActivityLines counts the activity records in the live spool beside
// configPath (0 when there is no spool yet).
func spoolActivityLines(t *testing.T, configPath string) int {
	t.Helper()
	raw, err := os.ReadFile(hookspool.Path(configPath))
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, `"kind":"`+hookspool.KindActivity+`"`) {
			n++
		}
	}
	return n
}

// TestHookActivitySurvivesProcessExit (R-188 F4): a block or fail-closed
// answer ends the hook process through os.Exit, which runs no deferred call,
// so the activity record must already be written when the exit seam is
// reached, and the deferred flush that a real process never reaches must not
// write a second one. Each row arms one emission, takes one exit path with an
// exit recorder that counts the records at the moment of exit, then runs the
// deferred flush.
func TestHookActivitySurvivesProcessExit(t *testing.T) {
	enforced := func(t *testing.T) string {
		t.Helper()
		cp := filepath.Join(t.TempDir(), "config.toml")
		writeFileT(t, cp, "this is = = not toml [")
		writePosture(t, cp, enforcedPosture)
		return cp
	}
	cases := []struct {
		name     string
		tool     string
		event    string
		failPlan bool
		exit     func()
		wantCode int
	}{
		{name: "guard block (hookExit)", tool: "qoder", event: "UserPromptSubmit", exit: func() { hookExit(2) }, wantCode: 2},
		{
			name: "fail-closed receiver (hookFailClosed)", tool: "qoder", event: "UserPromptSubmit", failPlan: true,
			exit: func() { hookFailClosed(guardposture.KindConfig, []byte(`{"session_id":"q1"}`)) }, wantCode: 2,
		},
		{
			name: "pending block code (hookReplyBarrier)", tool: "qoder", event: "UserPromptSubmit", failPlan: true,
			exit: func() {
				hookReplyMu.Lock()
				hookFailureOwned, hookPendingExitCode = true, 2
				hookReplyMu.Unlock()
				hookReplyBarrier()
			},
			wantCode: 2,
		},
		{
			name: "fail-closed watchdog (exitFn)", tool: "qoder", event: "UserPromptSubmit", failPlan: true,
			exit: func() { hookWatchdogFire(time.Millisecond, activityFlushingExit(hookOSExit), io.Discard) }, wantCode: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := enforced(t)
			plan := hookFailurePlan{}
			if tc.failPlan {
				plan = resolveHookFailurePlan(tc.tool, tc.event, cp)
				if !plan.FailClosed {
					t.Fatalf("plan %+v does not fail closed", plan)
				}
			}
			h := newFailureHarness(t, plan)
			resetHookActivity()
			t.Cleanup(resetHookActivity)
			atExit := -1
			hookOSExit = func(code int) {
				atExit = spoolActivityLines(t, cp)
				h.exit(code)
			}
			armHookActivity(func() {
				emitHookActivity(tc.tool, tc.event, cp, io.Discard, hookActivityDepsFor(func(string) string { return "" }))
			})
			tc.exit()
			// The deferred flush a real process never reaches.
			flushHookActivity()
			if fmt.Sprint(h.exitCodes()) != fmt.Sprint([]int{tc.wantCode}) {
				t.Fatalf("exits %v, want [%d]", h.exitCodes(), tc.wantCode)
			}
			if atExit != 1 {
				t.Errorf("activity records at exit = %d, want 1 (written before the process ends)", atExit)
			}
			if got := spoolActivityLines(t, cp); got != 1 {
				t.Errorf("activity records after the deferred flush = %d, want exactly 1", got)
			}
		})
	}
}

// TestHookInvocationBlockCountsActivity runs the two exits through a whole
// invocation (runHookInvocation): a Claude Code prompt the guard blocks (exit
// 2 through hookExit) and a Qoder prompt gate whose config cannot load under
// enforcement (a fail-closed exit 2). Each leaves exactly one activity
// record, already on disk when the process exit is reached, whichever exit
// seam answers (the receiver's hookOSExit, or exitFn when the fail-closed
// watchdog answers first on a slow run).
func TestHookInvocationBlockCountsActivity(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		config  func(dir string) string
		seedDB  bool
		posture bool
		payload string
	}{
		{
			name: "guard block", args: []string{"claude-code", "user-prompt-submit"},
			config: func(dir string) string {
				return "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "observer.db"))) + "\n\n" +
					"[observer.hooks]\nauto_register = false\n\n" +
					"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
					"[guard.prompt]\nenabled = true\nmode = \"ask-once\"\nhook_lane = true\nreconsider_min_delay = \"0s\"\n"
			},
			seedDB:  true,
			payload: `{"session_id":"blk-1","cwd":"/r","hook_event_name":"UserPromptSubmit","user_prompt":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`,
		},
		{
			name: "fail-closed", args: []string{"qoder", "UserPromptSubmit"},
			config:  func(string) string { return "this is = = not toml [" },
			posture: true,
			payload: `{"prompt":"hi","session_id":"q1"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cp := filepath.Join(dir, "config.toml")
			writeFileT(t, cp, tc.config(dir))
			if tc.seedDB {
				// A migrated database, so the capture the block still runs
				// does not spend the gate budget migrating one.
				database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(dir, "observer.db")})
				if err != nil {
					t.Fatal(err)
				}
				_ = database.Close()
			}
			if tc.posture {
				writePosture(t, cp, enforcedPosture)
			}
			h := newFailureHarness(t, hookFailurePlan{})
			var mu sync.Mutex
			var atExit []int
			counting := func(code int) {
				mu.Lock()
				atExit = append(atExit, spoolActivityLines(t, cp))
				mu.Unlock()
				h.exit(code)
			}
			hookOSExit = counting
			withStdinT(t, tc.payload, func() {
				runHookInvocation(context.Background(), tc.args, cp, 20*time.Second, counting)
			})
			if fmt.Sprint(h.exitCodes()) != "[2]" {
				t.Fatalf("exits %v, want [2] (stderr %q)", h.exitCodes(), h.stderr.String())
			}
			mu.Lock()
			got := fmt.Sprint(atExit)
			mu.Unlock()
			if got != "[1]" {
				t.Errorf("activity records at exit = %s, want [1]", got)
			}
			if n := spoolActivityLines(t, cp); n != 1 {
				t.Errorf("activity records after the invocation = %d, want exactly 1", n)
			}
		})
	}
}
