package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// commandCodeInject mirrors the promptInjection descriptor newCommandCodeCmd
// hands to the shared continueFromArgs seam. NO tool binary is spawned.
var commandCodeInject = promptInjection{
	Kind:          injectTrailingPositional,
	ConflictFlags: []string{"-p", "--print"},
	Subcommands:   commandCodeSubcommands,
}

// TestCommandCodeInjectShape pins the grounded seed contract from
// `commandcode --help` (v1.4.5): `commandcode "message"   Start with initial
// message` — a bare trailing positional on the default TUI command.
func TestCommandCodeInjectShape(t *testing.T) {
	const prompt = "SEEDED HANDOVER"

	t.Run("bare seed is the sole positional", func(t *testing.T) {
		got, err := injectPrompt(nil, commandCodeInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{prompt}) {
			t.Fatalf("got %v, want %v", got, []string{prompt})
		}
	})

	t.Run("forwarded flags are preserved before the seed", func(t *testing.T) {
		got, err := injectPrompt([]string{"--model=kimi"}, commandCodeInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{"--model=kimi", prompt}) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("headless -p with a query collides via its positional", func(t *testing.T) {
		// The shared two-prompt check inspects POSITIONALS for the positional
		// injection kinds (ConflictFlags are consulted only by the flag-value
		// kind), so `-p hi` trips it through "hi". The BARE flag forms are
		// caught by the launcher's own argsContainHeadlessFlag guard —
		// TestCommandCodeHeadlessFlagIsASeedConflict below.
		if _, err := injectPrompt([]string{"-p", "hi"}, commandCodeInject, prompt); err == nil {
			t.Fatal("forwarded -p <query> must collide with the seed")
		}
	})

	t.Run("a forwarded bare message collides", func(t *testing.T) {
		if _, err := injectPrompt([]string{"do the thing"}, commandCodeInject, prompt); err == nil {
			t.Fatal("a forwarded positional message must collide with the seed")
		}
	})
}

// TestCommandCodeSubcommandsNotMisreadAsPrompt pins that a forwarded
// management verb is not mistaken for a competing positional message.
func TestCommandCodeSubcommandsNotMisreadAsPrompt(t *testing.T) {
	for _, sub := range []string{"info", "status", "whoami", "update", "taste", "mcp", "skills", "mods", "login", "logout"} {
		if forwardedPromptConflict([]string{sub}, commandCodeSubcommands) {
			t.Errorf("subcommand %q was misread as a forwarded prompt", sub)
		}
	}
	if !forwardedPromptConflict([]string{"mcp", "do it"}, commandCodeSubcommands) {
		t.Error("subcommand + bare prompt must still collide")
	}
}

// TestCommandCodeNoSessionIsASeedConflict pins the capture guard: a forwarded
// --no-session keeps the session in memory only, so observer's command-code
// adapter (an on-disk JSONL watcher) would capture nothing of the continued
// work. The launcher detects it with the shared flag check.
func TestCommandCodeNoSessionIsASeedConflict(t *testing.T) {
	if !forwardedFlagConflict([]string{"--no-session"}, "--no-session") {
		t.Fatal("--no-session must be detected as a seed conflict")
	}
	if forwardedFlagConflict([]string{"--model=x"}, "--no-session") {
		t.Fatal("unrelated flags must not trip the --no-session guard")
	}
}

// TestCommandCodeHeadlessFlagIsASeedConflict pins the launcher-owned guard
// for the headless one-shot: `-p`/`--print` (bare or `=value`) answers and
// exits, so --continue-from must reject it rather than seed a run that never
// becomes interactive. The generic positional check cannot see a flag, which
// is exactly why this guard exists.
func TestCommandCodeHeadlessFlagIsASeedConflict(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-p"}, true},
		{[]string{"--print"}, true},
		{[]string{"--print=hi"}, true},
		{[]string{"--model", "x"}, false},
		{[]string{"--", "-p"}, false}, // after a bare --, it is literal text
	}
	for _, tc := range cases {
		if got := argsContainHeadlessFlag(tc.args, "-p", "--print"); got != tc.want {
			t.Errorf("argsContainHeadlessFlag(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestCommandCodeManagementVerbsAreRejectedForSeeding is the FINDING-1
// regression. `commandcode status` (and every other management verb) PRINTS
// AND EXITS, and none of them takes a message positional — v1.4.5 accepts the
// extra argument and ignores it — so seeding a handover behind one produced a
// tool that exited instead of opening the seeded session. The launcher must
// reject the verb by NAME before the (expensive) handoff render, the way
// `observer droid` rejects `exec`.
//
// This drives the real cobra command so the WIRING is pinned, not just the
// predicate: --commandcode-path short-circuits binary resolution (never
// spawned — the guard returns first) and --config points at a throwaway file.
func TestCommandCodeManagementVerbsAreRejectedForSeeding(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, verb := range []string{"status", "info", "mcp", "login", "learn-taste"} {
		t.Run(verb, func(t *testing.T) {
			cmd := newCommandCodeCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{
				"--config", cfgPath,
				"--commandcode-path", filepath.Join(dir, "stub-never-spawned"),
				"--continue-from", "no-such-session",
				"--", verb,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("`command-code --continue-from … -- %s` must be rejected, got nil error (stderr=%q)", verb, out.String())
			}
			msg := err.Error()
			if !strings.Contains(msg, verb) {
				t.Errorf("error must NAME the offending verb %q, got %q", verb, msg)
			}
			if !strings.Contains(msg, "management subcommand") {
				t.Errorf("error must explain the management-subcommand collision, got %q", msg)
			}
			if !strings.Contains(out.String(), "observer command-code:") {
				t.Errorf("the rejection must also be printed (SilenceErrors hides the return), got %q", out.String())
			}
		})
	}
}

// TestCommandCodeSeededInteractiveLaunchIsNotRejected is the other half of
// the FINDING-1 fix: an ordinary seeded launch must still get past the guard.
// A non-verb argv reaches the handoff render, which then fails on the unknown
// session — a DIFFERENT error, and the one that proves the guard let it by.
func TestCommandCodeSeededInteractiveLaunchIsNotRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := newCommandCodeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--commandcode-path", filepath.Join(dir, "stub-never-spawned"),
		"--continue-from", "no-such-session",
		"--", "--model=kimi",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the unknown source session to fail the handoff render")
	}
	if strings.Contains(err.Error(), "management subcommand") {
		t.Fatalf("an ordinary flag argv must NOT trip the management-verb guard: %v", err)
	}
}

// TestCommandCodeHeadlessScanClosesSplitValueBypass is the FINDING-2
// regression for this launcher: with Command Code's flag grammar grounded off
// `commandcode --help` (v1.4.5), a SPLIT flag value no longer parks itself in
// the operand slot and hides a following management verb.
func TestCommandCodeHeadlessScanClosesSplitValueBypass(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"status"}, true},
		{[]string{"--model=kimi", "mcp"}, true},
		{[]string{"--model", "kimi"}, false},
		{[]string{"--", "status"}, false},
		// FINDING-2: split values used to hide the verb behind them.
		{[]string{"--model", "kimi", "status"}, true},
		{[]string{"--config", "theme=dark", "info"}, true},
		{[]string{"--add-dir", "/repo", "login"}, true},
		{[]string{"--session", "abc123", "mcp"}, true},
		// The value itself is not the verb.
		{[]string{"--name", "status"}, false},
		// A grounded switch keeps the scan aligned, so a multi-word bare
		// message whose Nth word equals a verb is NOT rejected.
		{[]string{"--plan", "check", "the", "status", "page"}, false},
		// `-r/--resume [name]` and `-w/--worktree [name]` are OPTIONAL-value
		// options → ungrounded on purpose → conservative reject.
		{[]string{"-r", "status"}, true},
	}
	for _, tc := range cases {
		if got := commandCodeHeadlessScan.leads(tc.args); got != tc.want {
			t.Errorf("commandCodeHeadlessScan.leads(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestCommandCodeFlagGrammarIsDisjoint pins that no flag is claimed as both
// value-taking and a switch, and that the optional-value options stay
// ungrounded so the conservative branch owns them.
func TestCommandCodeFlagGrammarIsDisjoint(t *testing.T) {
	for f := range commandCodeValueFlags {
		if commandCodeBoolFlags[f] {
			t.Errorf("flag %q is in BOTH commandCodeValueFlags and commandCodeBoolFlags", f)
		}
	}
	for _, f := range []string{"-r", "--resume", "-p", "--print", "-w", "--worktree"} {
		if commandCodeValueFlags[f] || commandCodeBoolFlags[f] {
			t.Errorf("optional-value flag %q must stay ungrounded so the scan goes conservative", f)
		}
	}
}

// TestCommandCodeAttachPassthrough pins the wrapper-flag forwarding.
func TestCommandCodeAttachPassthrough(t *testing.T) {
	if got := commandCodeAttachPassthrough("/opt/commandcode"); !equalArgs(got, []string{"--commandcode-path", "/opt/commandcode"}) {
		t.Fatalf("commandCodeAttachPassthrough = %v", got)
	}
	if got := commandCodeAttachPassthrough(""); len(got) != 0 {
		t.Fatalf("expected empty passthrough, got %v", got)
	}
}
