package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
)

// TestDecideAttach walks every row of the default-on attach decision table
// (attach_default.go) plus the laziness contract: the injected reachability
// probe is invoked ONLY on the default-on row (enabled+default_on+grounded past
// the TTY/incompatible filter), never on an opted-out, scripted, or
// attach-disabled launch.
func TestDecideAttach(t *testing.T) {
	cases := []struct {
		name string
		in   attachDecisionInputs
		// reach is the value the injected probe returns when called.
		reach bool
		// nilProbe injects a nil reachable closure (defensive: treated as
		// unreachable).
		nilProbe bool

		wantVerdict attachVerdict
		wantAttach  bool
		wantNotice  bool
		// wantNoticeText, when non-empty, pins the EXACT notice string for the row
		// (checked only when wantNotice is true). Different surprise rows print
		// different notices, so a single canonical constant no longer suffices.
		wantNoticeText string
		wantProbeRun   bool
	}{
		{
			// The daemon's OWN healthy inner launcher (live OOB) is the normal
			// attach path: bare (anti-recursion) and SILENT — its stderr is the
			// user's attached PTY, so an "attach skipped" line would print on every
			// session and mislead.
			name: "daemon-spawned inner launcher never re-attaches (anti-recursion), even with --attach — SILENT",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonSpawned: true, flagAttach: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			// daemonSpawned is checked FIRST, so even when the env marker is also
			// set (as it always is for a real inner launcher) the normal path stays
			// silent — the daemon-child NOTICE below is reserved for the no-live-OOB
			// case.
			name: "daemon-spawned wins over daemon-child marker → SILENT (normal inner launcher)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonSpawned: true, daemonChild: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			// H1: the INFALLIBLE env marker forces bare even when the best-effort
			// OOB channel is dead (daemonSpawned=false) and --attach is set — the
			// case a dead-OOB daemon child would otherwise recurse. With no live OOB
			// this is the "manually running inside a daemon PTY" surprise, so it now
			// prints ONE explanatory notice (still bare — anti-recursion intact).
			name: "daemon-child env marker forces bare even with a dead OOB channel and --attach → NOTICE",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonChild: true, daemonSpawned: false, flagAttach: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false,
			wantNotice: true, wantNoticeText: attachDaemonChildNotice, wantProbeRun: false,
		},
		{
			// Finding 5: a daemon-child that ALSO carries an incompatible mode
			// (headless --print → incompatible=true) is a scripted path — bare AND
			// SILENT, no notice, so `observer claude -- --print` inside a
			// daemon-owned terminal doesn't leak a stray stderr line.
			name: "daemon-child + incompatible (--print) → bare, SILENT (finding 5)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonChild: true, incompatible: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			// Finding 5: a daemon-child that ALSO passed --no-attach opted out
			// explicitly — bare AND SILENT, no notice.
			name: "daemon-child + --no-attach → bare, SILENT (finding 5)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonChild: true, flagNoAttach: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			// Finding 5: a daemon-child, non-TTY (CI pipe) → bare, SILENT.
			name: "daemon-child + non-TTY (CI pipe) → bare, SILENT (finding 5)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonChild: true,
				stdinTTY:    false, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			// Finding 5 baseline: a daemon-child on a plain interactive launch (no
			// opt-out, compatible, both-TTY) IS the genuine surprise → NOTICE.
			name: "daemon-child interactive plain → bare + NOTICE (finding 5 baseline)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				daemonChild: true,
				stdinTTY:    true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false,
			wantNotice: true, wantNoticeText: attachDaemonChildNotice, wantProbeRun: false,
		},
		{
			name: "no-attach wins over everything",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				flagNoAttach: true, flagAttach: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictForcedBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "no-attach composes with an incompatible mode (e.g. --continue-from)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				flagNoAttach: true, incompatible: true,
				stdinTTY: true, stdoutTTY: true,
			},
			wantVerdict: verdictForcedBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "explicit --attach forces attach when grounded",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				flagAttach: true, stdinTTY: true, stdoutTTY: true,
			},
			reach:       false, // must NOT be consulted on the forced path
			wantVerdict: verdictForcedAttach, wantAttach: true, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "explicit --attach forces attach even when ungrounded (downstream errors honestly)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: false,
				flagAttach: true, stdinTTY: true, stdoutTTY: true,
			},
			wantVerdict: verdictForcedAttach, wantAttach: true, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "explicit --attach forces attach even in an incompatible mode (reject happens downstream)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				flagAttach: true, incompatible: true,
				stdinTTY: true, stdoutTTY: true,
			},
			wantVerdict: verdictForcedAttach, wantAttach: true, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "incompatible mode → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				incompatible: true, stdinTTY: true, stdoutTTY: true,
			},
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "non-TTY stdin → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				stdinTTY: false, stdoutTTY: true,
			},
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "non-TTY stdout → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				stdinTTY: true, stdoutTTY: false,
			},
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "default-on all conditions met + reachable → attach",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictAttach, wantAttach: true, wantNotice: false, wantProbeRun: true,
		},
		{
			name: "default-on all conditions met + unreachable → bare + notice",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       false,
			wantVerdict: verdictBare, wantAttach: false,
			wantNotice: true, wantNoticeText: attachDaemonUnreachableNotice, wantProbeRun: true,
		},
		{
			name: "default-on wanted but nil probe → bare + notice (defensive)",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: true,
				stdinTTY: true, stdoutTTY: true,
			},
			nilProbe:    true,
			wantVerdict: verdictBare, wantAttach: false,
			wantNotice: true, wantNoticeText: attachDaemonUnreachableNotice, wantProbeRun: false,
		},
		{
			// Config contradiction: default_on=true but the master enabled switch
			// is off, on an otherwise attach-eligible interactive launch. Now prints
			// ONE notice naming [terminal.attach].enabled (previously silent). The
			// reachability probe is NOT dialed on this row.
			name: "attach disabled (enabled=false) but default_on=true → bare + config-contradiction notice, no probe",
			in: attachDecisionInputs{
				enabled: false, defaultOn: true, grounded: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false,
			wantNotice: true, wantNoticeText: attachConfigDisabledNotice, wantProbeRun: false,
		},
		{
			// The config-contradiction notice requires groundedness: an ungrounded
			// tool cannot attach at all, so naming [terminal.attach].enabled would
			// mislead — stays silent.
			name: "enabled=false + default_on=true but UNGROUNDED → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: false, defaultOn: true, grounded: false,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "default_on=false → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: true, defaultOn: false, grounded: true,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
		{
			name: "ungrounded (no attach capability) → bare, silent, no probe",
			in: attachDecisionInputs{
				enabled: true, defaultOn: true, grounded: false,
				stdinTTY: true, stdoutTTY: true,
			},
			reach:       true,
			wantVerdict: verdictBare, wantAttach: false, wantNotice: false, wantProbeRun: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probeRun := false
			in := tc.in
			if tc.nilProbe {
				in.reachable = nil
			} else {
				in.reachable = func() bool {
					probeRun = true
					return tc.reach
				}
			}
			got := decideAttach(in)
			if got.verdict != tc.wantVerdict {
				t.Errorf("verdict = %d, want %d", got.verdict, tc.wantVerdict)
			}
			if got.attach() != tc.wantAttach {
				t.Errorf("attach() = %v, want %v", got.attach(), tc.wantAttach)
			}
			if (got.notice != "") != tc.wantNotice {
				t.Errorf("notice = %q, wantNotice=%v", got.notice, tc.wantNotice)
			}
			if tc.wantNotice && tc.wantNoticeText != "" && got.notice != tc.wantNoticeText {
				t.Errorf("notice = %q, want %q", got.notice, tc.wantNoticeText)
			}
			if probeRun != tc.wantProbeRun {
				t.Errorf("reachable probe run = %v, want %v (laziness contract)", probeRun, tc.wantProbeRun)
			}
		})
	}
}

// TestAttachNoticesAreOneLine pins that every attach-decision notice is a single
// non-empty line (the operator decision: exactly one stderr notice per surprise
// row — a multi-line notice would be spam).
func TestAttachNoticesAreOneLine(t *testing.T) {
	for name, notice := range map[string]string{
		"daemon-unreachable": attachDaemonUnreachableNotice,
		"daemon-child":       attachDaemonChildNotice,
		"config-disabled":    attachConfigDisabledNotice,
	} {
		if notice == "" {
			t.Errorf("%s notice must be non-empty", name)
		}
		for _, r := range notice {
			if r == '\n' {
				t.Errorf("%s notice must be a single line, got %q", name, notice)
			}
		}
	}
}

// TestArgsContainClaudePrint pins the claude headless-print detection used to
// mark `observer claude -- --print "hi"` (and its `-p` alias) as an incompatible
// mode that must take the bare path.
func TestArgsContainClaudePrint(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, false},
		{"interactive prompt", []string{"hello world"}, false},
		{"long print", []string{"--print", "hi"}, true},
		{"short print", []string{"-p", "hi"}, true},
		{"print with equals", []string{"--print=hi"}, true},
		{"short print with equals", []string{"-p=hi"}, true},
		{"print among other flags", []string{"--model", "sonnet", "--print", "hi"}, true},
		{"prompt text merely containing the word print", []string{"tell me about print statements"}, false},
		// M6: a `--print` AFTER a bare `--` is a positional prompt token, not the
		// print flag — claude parses it as literal text, so the launch is
		// interactive and may attach (must classify NOT-headless).
		{"print after a bare -- is positional (interactive)", []string{"foo", "--", "--print"}, false},
		{"print before a bare -- is still the flag", []string{"--print", "hi", "--", "x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := argsContainClaudePrint(tc.args); got != tc.want {
				t.Errorf("argsContainClaudePrint(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestArgsAreCodexHeadless pins the codex headless detection: the non-interactive
// `exec` subcommand (claude's `--print` analogue) leading the tool args, even
// behind a leading `-c`/`--config` override.
func TestArgsAreCodexHeadless(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, false},
		{"interactive prompt", []string{"do a thing"}, false},
		{"exec leads", []string{"exec", "hello"}, true},
		{"exec behind -c pair", []string{"-c", "model=gpt", "exec", "hi"}, true},
		{"exec behind -c=combined", []string{"-c=model=gpt", "exec", "hi"}, true},
		{"exec behind --config pair", []string{"--config", "model=gpt", "exec", "hi"}, true},
		{"resume subcommand is not headless", []string{"resume", "abc"}, false},
		{"prompt containing exec is not headless", []string{"run exec for me"}, false},
		// M6: a value-taking global flag's value is skipped, so exec behind
		// `--model gpt` IS now correctly classified headless (previously this
		// pinned NOT-headless — the reviewer's bug).
		{"exec behind --model value pair", []string{"--model", "gpt", "exec"}, true},
		{"exec behind -m value pair", []string{"-m", "gpt-5", "exec", "hi"}, true},
		{"exec behind -C cd value pair", []string{"-C", "/work", "exec"}, true},
		{"e alias is headless", []string{"e", "hello"}, true},
		{"review subcommand is headless", []string{"review"}, true},
		{"exec behind --model=combined", []string{"--model=gpt", "exec"}, true},
		{"boolean flag then interactive prompt is not headless", []string{"--search", "do a thing"}, false},
		{"tool remainder boundary before any subcommand is not headless", []string{"--", "exec"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := argsAreCodexHeadless(tc.args); got != tc.want {
				t.Errorf("argsAreCodexHeadless(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestClaudeAttachIncompatible pins which claude launcher modes are incompatible
// with default-on attach — the guard that keeps scripted paths (verify, the
// handoff-fork family, headless --print) on the bare launch, while leaving
// --resume compatible (attach forwards it) so `--resume`/`--no-attach` compose.
func TestClaudeAttachIncompatible(t *testing.T) {
	cases := []struct {
		name string
		opts claudeLauncherOptions
		want bool
	}{
		{"bare interactive", claudeLauncherOptions{}, false},
		{"resume is compatible", claudeLauncherOptions{resume: "sid"}, false},
		{"no-proxy-route is compatible (escape hatch)", claudeLauncherOptions{noProxyRoute: true}, false},
		{"verify", claudeLauncherOptions{verify: true}, true},
		{"continue-from", claudeLauncherOptions{continueFrom: "sid"}, true},
		{"carry", claudeLauncherOptions{carry: "full"}, true},
		{"from-message", claudeLauncherOptions{fromMessage: 3}, true},
		{"from-time", claudeLauncherOptions{fromTime: "2026-01-01T00:00:00Z"}, true},
		{"headless --print in tool args", claudeLauncherOptions{claudeArgs: []string{"--print", "hi"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeAttachIncompatible(tc.opts); got != tc.want {
				t.Errorf("claudeAttachIncompatible = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCodexAttachIncompatible pins the codex incompatible-mode set (verify,
// detect-only, write-config, exclusive, the handoff-fork family, headless exec),
// with --resume left compatible so `--resume`/`--no-attach` compose.
func TestCodexAttachIncompatible(t *testing.T) {
	cases := []struct {
		name string
		opts codexLauncherOptions
		want bool
	}{
		{"bare interactive", codexLauncherOptions{}, false},
		{"resume is compatible", codexLauncherOptions{resume: "sid"}, false},
		{"verify", codexLauncherOptions{verify: true}, true},
		{"detect-only", codexLauncherOptions{detectOnly: true}, true},
		{"write-config", codexLauncherOptions{writeConfig: true}, true},
		{"exclusive", codexLauncherOptions{exclusive: true}, true},
		{"continue-from", codexLauncherOptions{continueFrom: "sid"}, true},
		{"carry", codexLauncherOptions{carry: "full"}, true},
		{"from-message", codexLauncherOptions{fromMessage: 3}, true},
		{"from-time", codexLauncherOptions{fromTime: "2026-01-01T00:00:00Z"}, true},
		{"headless exec in tool args", codexLauncherOptions{codexArgs: []string{"exec", "hi"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := codexAttachIncompatible(tc.opts); got != tc.want {
				t.Errorf("codexAttachIncompatible = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClaudePrintTakesBarePath is the load-bearing regression guard: the
// `observer claude -- --print "hi"` wrapper contract. Given default-on attach
// fully enabled + interactive TTYs, the print launch must still resolve to a
// SILENT bare verdict — no attach, no notice — and the reachability probe must
// never even be dialed.
func TestClaudePrintTakesBarePath(t *testing.T) {
	opts := claudeLauncherOptions{claudeArgs: []string{"--print", "hi"}}
	probed := false
	got := decideAttach(attachDecisionInputs{
		enabled: true, defaultOn: true, grounded: true,
		stdinTTY: true, stdoutTTY: true,
		incompatible: claudeAttachIncompatible(opts),
		reachable:    func() bool { probed = true; return true },
	})
	if got.attach() {
		t.Fatal("`claude -- --print` must NOT attach")
	}
	if got.notice != "" {
		t.Fatalf("`claude -- --print` must be a SILENT bare path, got notice %q", got.notice)
	}
	if probed {
		t.Fatal("`claude -- --print` must not dial the daemon socket")
	}
}

// TestNoAttachComposesWithResumeAndContinue pins that --no-attach yields a bare
// verdict regardless of --resume (compatible) or --continue-from (incompatible)
// — the opt-out never fights the reattach/handoff flags, and never dials.
func TestNoAttachComposesWithResumeAndContinue(t *testing.T) {
	for _, opts := range []claudeLauncherOptions{
		{noAttach: true, resume: "sid"},
		{noAttach: true, continueFrom: "sid"},
	} {
		probed := false
		got := decideAttach(attachDecisionInputs{
			enabled: true, defaultOn: true, grounded: true,
			flagNoAttach: opts.noAttach,
			stdinTTY:     true, stdoutTTY: true,
			incompatible: claudeAttachIncompatible(opts),
			reachable:    func() bool { probed = true; return true },
		})
		if got.verdict != verdictForcedBare || got.attach() {
			t.Errorf("opts=%+v: want forced-bare, got verdict=%d attach=%v", opts, got.verdict, got.attach())
		}
		if got.notice != "" {
			t.Errorf("opts=%+v: --no-attach must be silent, got notice %q", opts, got.notice)
		}
		if probed {
			t.Errorf("opts=%+v: --no-attach must not dial the daemon", opts)
		}
	}
}

// TestAttachSocketReachable exercises the real dial probe: a nonexistent socket
// path reports unreachable, and a live listener at the derived attach-socket path
// reports reachable (reusing the same attachsock.Dial the interactive client
// uses).
//
// The live-listener half is AF_UNIX-specific and is skipped on a host whose
// attach transport is not the unix socket. attachSocketReachable probes
// attachSocketPath — the ON-DISK path, which is the transport endpoint only on
// unix — so on a named-pipe host it reports unreachable unconditionally. That
// is currently the CORRECT answer there (the interactive `--attach` client is
// still the honest non-unix stub, so default-on attach must resolve to a bare
// launch), but it is a KNOWN residual to revisit together with a native console
// client: at that point the probe must consult attachEndpoint, not
// attachSocketPath.
func TestAttachSocketReachable(t *testing.T) {
	// Nonexistent daemon.
	missing := filepath.Join(t.TempDir(), "observer.db")
	if attachSocketReachable(missing) {
		t.Errorf("attachSocketReachable(%q) = true, want false (no daemon)", missing)
	}

	if got := attachsock.DefaultTransport().Describe(); got != attachsock.TransportUnixSocket {
		t.Skipf("attach transport is %q, not %q — the live-listener probe below pins AF_UNIX behaviour", got, attachsock.TransportUnixSocket)
	}

	// Live listener at the derived socket path.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	sockPath := attachSocketPath(dbPath)
	if mkErr := os.MkdirAll(filepath.Dir(sockPath), 0o700); mkErr != nil {
		t.Fatalf("prepare socket dir: %v", mkErr)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		// Unix-socket path-length limits (~104 bytes) can bite on long temp
		// dirs; skip rather than fail on that environmental constraint.
		t.Skipf("cannot listen on %q: %v", sockPath, err)
	}
	defer ln.Close()
	if !attachSocketReachable(dbPath) {
		t.Errorf("attachSocketReachable(%q) = false, want true (listener up)", dbPath)
	}
}
