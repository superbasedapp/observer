package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookbridge"
	"github.com/marmutapp/superbased-observer/internal/hookbridgesvc"
)

// TestRunHookBridge pins the bridge's answers (AW-37), one row per outcome
// for each dialect the bridge is written for: the hook's own bytes pass
// through untouched when it ran; anything that cannot prove it ran writes
// the dialect's fail-closed block, never the stray output.
func TestRunHookBridge(t *testing.T) {
	claude := hookbridge.Entry{Distro: "Ubuntu", Bin: "/opt/o", Tool: "claude-code", Event: "pre-tool"}
	codex := hookbridge.Entry{Distro: "Ubuntu", Bin: "/opt/o", Tool: "codex", Event: "PreToolUse"}
	hookOut := []byte("{\"hookSpecificOutput\":{\"x\":\"\u00e9\"}}\r\n")
	cases := []struct {
		name     string
		entry    hookbridge.Entry
		run      hookbridgesvc.Result
		wantExit int
		wantOut  []byte // nil: the dialect's fail-closed reply
		wantErr  string
	}{
		{"allow passes through", claude, hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: 0}, Stdout: hookOut, Stderr: []byte("diag\n")}, 0, hookOut, "diag\n"},
		{"the hook's own block passes through", codex, hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: 2}, Stderr: []byte("blocked by rule\n")}, 2, []byte{}, "blocked by rule\n"},
		{"the hook's non-blocking answer stays non-blocking", claude, hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: hookbridge.SentinelExit}, Stderr: []byte("warn\n")}, 1, []byte{}, "warn\n"},
		{"claude: wsl.exe could not start", claude, hookbridgesvc.Result{}, -1, nil, ""},
		{"claude: WSL returned its own failure", claude, hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: -1}, Stdout: []byte("The Windows Subsystem for Linux is not running")}, -1, nil, ""},
		{"codex: wsl.exe could not start", codex, hookbridgesvc.Result{}, -1, nil, ""},
		{"codex: WSL returned 1", codex, hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: 1}}, -1, nil, ""},
	}
	prev := hookBridgeRun
	t.Cleanup(func() { hookBridgeRun = prev })
	for _, c := range cases {
		c := c
		var gotArgv []string
		var gotStdin []byte
		hookBridgeRun = func(_ context.Context, exe string, argv []string, stdin io.Reader) hookbridgesvc.Result {
			if exe != `C:\Windows\System32\wsl.exe` {
				t.Errorf("%s: started %q, want the System32 wsl.exe", c.name, exe)
			}
			gotArgv = argv
			gotStdin, _ = io.ReadAll(stdin)
			return c.run
		}
		var stdout, stderr bytes.Buffer
		code := runHookBridge(context.Background(), c.entry, "", strings.NewReader("PAYLOAD\x00\r\n"), &stdout, &stderr)
		if string(gotStdin) != "PAYLOAD\x00\r\n" {
			t.Errorf("%s: stdin reached the hook as %q", c.name, gotStdin)
		}
		if gotArgv[len(gotArgv)-1] != hookbridge.SentinelFlag {
			t.Errorf("%s: argv %q lacks the sentinel flag", c.name, gotArgv)
		}
		if c.wantOut != nil {
			if code != c.wantExit || !bytes.Equal(stdout.Bytes(), c.wantOut) || stderr.String() != c.wantErr {
				t.Errorf("%s: exit %d stdout %q stderr %q; want %d %q %q", c.name, code, stdout.Bytes(), stderr.String(), c.wantExit, c.wantOut, c.wantErr)
			}
			continue
		}
		b, _ := resolveHookInvocationBinding(c.entry.Tool, canonicalHookEvent(c.entry.Tool, c.entry.Event))
		reply, ok := hook.BuildFailClosedReply(b.Dialect, hook.FailClosedErrorReason)
		if !ok {
			t.Fatalf("%s: dialect %q has no fail-closed reply", c.name, b.Dialect)
		}
		if code != reply.ExitCode || !bytes.Equal(stdout.Bytes(), reply.Stdout) {
			t.Errorf("%s: exit %d stdout %q; want the fail-closed reply exit %d %q", c.name, code, stdout.Bytes(), reply.ExitCode, reply.Stdout)
		}
		if bytes.Contains(stdout.Bytes(), []byte("Subsystem")) {
			t.Errorf("%s: wsl.exe's own output leaked into the reply", c.name)
		}
		if reply.StderrReason && !strings.Contains(stderr.String(), hook.FailClosedErrorReason) {
			t.Errorf("%s: stderr %q lacks the fail-closed reason", c.name, stderr.String())
		}
		if !reply.StderrReason && !strings.Contains(string(reply.Stdout), "deny") && code != 2 {
			t.Errorf("%s: the fail-closed reply neither denies nor exits 2", c.name)
		}
	}
}

// TestRunHookBridgeRefusesAnUnsafeEntry: an entry outside the closed
// spellings never starts wsl.exe and blocks.
func TestRunHookBridgeRefusesAnUnsafeEntry(t *testing.T) {
	prev := hookBridgeRun
	t.Cleanup(func() { hookBridgeRun = prev })
	started := false
	hookBridgeRun = func(context.Context, string, []string, io.Reader) hookbridgesvc.Result {
		started = true
		return hookbridgesvc.Result{}
	}
	var stdout, stderr bytes.Buffer
	code := runHookBridge(context.Background(), hookbridge.Entry{Distro: "U;rm", Bin: "/o", Tool: "claude-code", Event: "pre-tool"}, "", strings.NewReader(""), &stdout, &stderr)
	if started {
		t.Fatal("an unsafe entry started wsl.exe")
	}
	if code == 0 && !strings.Contains(stdout.String(), "deny") {
		t.Fatalf("an unsafe entry must block: exit %d stdout %q", code, stdout.String())
	}
}

// TestSentinelExit pins the hook side: under --bridge-sentinel every exit
// other than 0 and 2 reaches the bridge as the sentinel.
func TestSentinelExit(t *testing.T) {
	for in, want := range map[int]int{0: 0, 2: 2, 1: hookbridge.SentinelExit, 3: hookbridge.SentinelExit} {
		got := -100
		sentinelExit(func(c int) { got = c })(in)
		if got != want {
			t.Errorf("exit %d reached the bridge as %d, want %d", in, got, want)
		}
	}
	if "--"+hookbridgeSentinelFlagName != hookbridge.SentinelFlag {
		t.Fatal("the hook flag and the bridge's argv flag must be one spelling")
	}
	if f := newHookCmd().Flags().Lookup(hookbridgeSentinelFlagName); f == nil || !f.Hidden {
		t.Fatal("observer hook must take the hidden sentinel flag")
	}
}

// TestLockReadsManaged: one row per org-lock state the bridge's managed
// reading sees (second audit item 1): a tampered lock that still expects an
// organization reads managed, so tampering cannot downgrade the bridge.
func TestLockReadsManaged(t *testing.T) {
	cases := []struct {
		name string
		lock config.GuardOrgLock
		want bool
	}{
		{"verified managed lock", config.GuardOrgLock{TenancyKnown: true, Managed: true}, true},
		{"verified individual lock", config.GuardOrgLock{TenancyKnown: true}, false},
		{"tampered lock, organization expected", config.GuardOrgLock{State: "tampered", OrgExpected: true}, true},
		{"tampered lock on an individual node", config.GuardOrgLock{State: "tampered", TenancyKnown: true}, false},
		{"no lock", config.GuardOrgLock{}, false},
	}
	for _, c := range cases {
		if got := lockReadsManaged(c.lock); got != c.want {
			t.Errorf("%s: lockReadsManaged = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRunHookBridgeTimesOutAHangingRun pins second-audit item 2: a wsl.exe
// that never answers is cut off at the bridge's own deadline, which is
// derived from the binding's host timeout, and the call is BLOCKED with the
// timeout reason before the host could give up and let it through.
func TestRunHookBridgeTimesOutAHangingRun(t *testing.T) {
	prevRun, prevDeadline := hookBridgeRun, hookBridgeDeadline
	t.Cleanup(func() { hookBridgeRun, hookBridgeDeadline = prevRun, prevDeadline })
	var askedHost time.Duration
	hookBridgeDeadline = func(host time.Duration) time.Duration {
		askedHost = host
		return 50 * time.Millisecond
	}
	hookBridgeRun = func(ctx context.Context, _ string, _ []string, _ io.Reader) hookbridgesvc.Result {
		<-ctx.Done() // a hung wsl.exe
		return hookbridgesvc.Result{Run: hookbridge.Run{Started: true, TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded), ExitCode: -1}}
	}
	e := hookbridge.Entry{Distro: "Ubuntu", Bin: "/opt/o", Tool: "claude-code", Event: "pre-tool"}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := runHookBridge(context.Background(), e, "", strings.NewReader("{}"), &stdout, &stderr)
	if time.Since(start) > 10*time.Second {
		t.Fatal("the bridge did not stop at its deadline")
	}
	b, _ := resolveHookInvocationBinding("claude-code", canonicalHookEvent("claude-code", "pre-tool"))
	if askedHost != b.HostTimeout || askedHost <= 0 {
		t.Fatalf("deadline asked for host timeout %v, want the binding's %v", askedHost, b.HostTimeout)
	}
	reply, _ := hook.BuildFailClosedReply(b.Dialect, hook.FailClosedTimeoutReason)
	if code != reply.ExitCode || !bytes.Equal(stdout.Bytes(), reply.Stdout) {
		t.Fatalf("exit %d stdout %q; want the timeout fail-closed reply %d %q", code, stdout.Bytes(), reply.ExitCode, reply.Stdout)
	}
	if hookbridge.Deadline(b.HostTimeout) >= b.HostTimeout {
		t.Fatal("the production deadline must sit below the host's hook timeout")
	}
}

// TestRunHookBridgeKeepsWSLNoticesOutOfABlockReason pins second-audit item
// 6: wsl.exe's own "wsl: " notices never join a hook's exit-2 block reason,
// and on other answers they are kept but named as wsl.exe's.
func TestRunHookBridgeKeepsWSLNoticesOutOfABlockReason(t *testing.T) {
	prev := hookBridgeRun
	t.Cleanup(func() { hookBridgeRun = prev })
	e := hookbridge.Entry{Distro: "Ubuntu", Bin: "/opt/o", Tool: "codex", Event: "PreToolUse"}
	stderrIn := []byte("wsl: A localhost proxy configuration was detected\nblocked by rule R-101\n")
	for code, want := range map[int]string{
		2: "blocked by rule R-101\n",
		0: "blocked by rule R-101\nobserver hook-bridge: wsl.exe said: wsl: A localhost proxy configuration was detected\n",
	} {
		code := code
		hookBridgeRun = func(context.Context, string, []string, io.Reader) hookbridgesvc.Result {
			return hookbridgesvc.Result{Run: hookbridge.Run{Started: true, ExitCode: code}, Stderr: stderrIn}
		}
		var stdout, stderr bytes.Buffer
		if got := runHookBridge(context.Background(), e, "", strings.NewReader(""), &stdout, &stderr); got != code {
			t.Fatalf("exit %d, want %d", got, code)
		}
		if stderr.String() != want {
			t.Errorf("exit %d: stderr %q, want %q", code, stderr.String(), want)
		}
	}
}
