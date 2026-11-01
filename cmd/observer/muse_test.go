package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// museInject mirrors the promptInjection descriptor newMuseCmd hands to the
// shared continueFromArgs seam, so the argv-shape assertions below exercise
// the exact contract the launcher declares. NO tool binary is spawned.
var museInject = promptInjection{
	Kind:        injectTrailingPositional,
	Subcommands: museSubcommands,
}

// TestMuseInjectShape pins the grounded seed contract from `muse --help`:
// `Usage: muse [OPTIONS] [PROMPT]` — a bare trailing positional prompt, with
// no headless prompt FLAG (unlike droid/commandcode/prime-agent) because the
// non-interactive lane is the `exec` SUBCOMMAND instead.
func TestMuseInjectShape(t *testing.T) {
	const prompt = "SEEDED HANDOVER"

	t.Run("bare seed is the sole positional", func(t *testing.T) {
		got, err := injectPrompt(nil, museInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{prompt}) {
			t.Fatalf("got %v, want %v", got, []string{prompt})
		}
	})

	t.Run("forwarded flags are preserved before the seed", func(t *testing.T) {
		got, err := injectPrompt([]string{"--yolo"}, museInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{"--yolo", prompt}) {
			t.Fatalf("got %v, want [--yolo <prompt>]", got)
		}
	})

	t.Run("a forwarded bare prompt collides", func(t *testing.T) {
		if _, err := injectPrompt([]string{"do the thing"}, museInject, prompt); err == nil {
			t.Fatal("a forwarded positional prompt must collide with the seed")
		}
	})

	t.Run("separated value-flag reads as a competing positional", func(t *testing.T) {
		if _, err := injectPrompt([]string{"--model", "muse-large"}, museInject, prompt); err == nil {
			t.Fatal("separated --model value must trip the conservative collision check")
		}
	})
}

// TestMuseSubcommandsNotMisreadAsPrompt pins that a forwarded muse verb
// (including `resume`, which can reopen an interactive TUI) is not mistaken
// for a competing positional prompt.
func TestMuseSubcommandsNotMisreadAsPrompt(t *testing.T) {
	for sub := range museSubcommands {
		if forwardedPromptConflict([]string{sub}, museSubcommands) {
			t.Errorf("subcommand %q was misread as a forwarded prompt", sub)
		}
	}
	// A subcommand FOLLOWED by a bare prompt is still a collision.
	if !forwardedPromptConflict([]string{"exec", "do it"}, museSubcommands) {
		t.Error("subcommand + bare prompt must still collide")
	}
}

// TestMuseHeadlessScan pins the grounded leading-verb guard: the subcommand
// set plus the flag grammar, so a SPLIT flag value does not park itself in
// the operand slot and hide a following management verb (the
// droid/command-code FINDING-2 regression class).
func TestMuseHeadlessScan(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"exec", "analyze"}, true},
		{[]string{"--model=muse-large", "exec"}, true},
		{[]string{"resume"}, true},
		{[]string{"--model", "muse-large"}, false},
		{[]string{"--", "exec"}, false},
		// A split-value flag before a subcommand must still detect it — the
		// exact class a wrong/incomplete flag table breaks.
		{[]string{"--model", "muse-large", "exec"}, true},
		{[]string{"--provider", "meta", "resume"}, true},
		{[]string{"--workspace", "/repo", "sandbox"}, true},
		{[]string{"--image", "shot.png", "trace"}, true},
		// …and the value itself must not be mistaken for the verb.
		{[]string{"--model", "exec"}, false},
		{[]string{"--provider", "resume"}, false},
		// A positional PROMPT does not trip the scan.
		{[]string{"please run exec for me"}, false},
		{[]string{"tell", "me", "about", "resume", "state"}, false},
		// Bool switches keep the scan aligned.
		{[]string{"--yolo", "exec"}, true},
		// An OPTIONAL-value option (`-w, --worktree [<MODE>]`) is in neither
		// grounded set, so the scan goes conservative: a headless verb behind
		// it is refused rather than silently launched.
		{[]string{"-w", "exec"}, true},
	}
	for _, tc := range cases {
		if got := museHeadlessScan.leads(tc.args); got != tc.want {
			t.Errorf("museHeadlessScan.leads(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestMuseFlagGrammarIsDisjoint pins that no muse flag is claimed as BOTH a
// value-taking flag and a switch, that both spellings of every -x/--xyz pair
// land in the SAME table, and that the OPTIONAL-value `-w/--worktree` stays
// in NEITHER table (leadingVerbScan's conservative branch owns it).
func TestMuseFlagGrammarIsDisjoint(t *testing.T) {
	for f := range museValueFlags {
		if museBoolFlags[f] {
			t.Errorf("muse flag %q is in BOTH museValueFlags and museBoolFlags", f)
		}
	}
	pairs := [][2]string{
		{"-h", "--help"},
		{"-V", "--version"},
	}
	for _, p := range pairs {
		short, long := p[0], p[1]
		shortIsValue, longIsValue := museValueFlags[short], museValueFlags[long]
		shortIsBool, longIsBool := museBoolFlags[short], museBoolFlags[long]
		if shortIsValue != longIsValue {
			t.Errorf("flag pair %s/%s split across museValueFlags (short=%v long=%v)", short, long, shortIsValue, longIsValue)
		}
		if shortIsBool != longIsBool {
			t.Errorf("flag pair %s/%s split across museBoolFlags (short=%v long=%v)", short, long, shortIsBool, longIsBool)
		}
		if !shortIsBool {
			t.Errorf("flag pair %s/%s expected to be a grounded switch pair", short, long)
		}
	}
	for _, f := range []string{"-w", "--worktree"} {
		if museValueFlags[f] || museBoolFlags[f] {
			t.Errorf("optional-value flag %q must stay ungrounded so the scan goes conservative", f)
		}
	}
}

// TestMuseAttachPassthrough pins the wrapper-flag forwarding to the
// daemon-spawned inner launcher.
func TestMuseAttachPassthrough(t *testing.T) {
	if got := museAttachPassthrough("/opt/muse"); !equalArgs(got, []string{"--muse-path", "/opt/muse"}) {
		t.Fatalf("museAttachPassthrough = %v", got)
	}
	if got := museAttachPassthrough(""); len(got) != 0 {
		t.Fatalf("expected empty passthrough, got %v", got)
	}
}

// TestMuseSubcommandForwardedToSeedIsRejected drives the real cobra command
// (--muse-path short-circuits binary resolution — never spawned, since the
// headless-scan guard returns first) to pin the FINDING-1-class regression:
// a forwarded muse subcommand (`resume`, `exec`, …) must be rejected by NAME
// before the (comparatively expensive) handoff render, the same way
// `observer droid` rejects `exec`.
func TestMuseSubcommandForwardedToSeedIsRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, sub := range []string{"exec", "resume", "export", "sandbox"} {
		t.Run(sub, func(t *testing.T) {
			cmd := newMuseCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{
				"--config", cfgPath,
				"--muse-path", filepath.Join(dir, "stub-never-spawned"),
				"--continue-from", "no-such-session",
				"--", sub,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("`observer muse --continue-from … -- %s` must be rejected, got nil error (stderr=%q)", sub, out.String())
			}
			if !strings.Contains(out.String(), "observer muse:") {
				t.Errorf("the rejection must also be printed (SilenceErrors hides the return), got %q", out.String())
			}
		})
	}
}

// TestMuseSeededInteractiveLaunchIsNotRejected is the other half of the
// FINDING-1-class fix: an ordinary seeded launch (no leading subcommand)
// must still get past the guard and reach the handoff render, which then
// fails on the unknown source session — a DIFFERENT failure than the
// subcommand-collision one, proving the guard let it through.
func TestMuseSeededInteractiveLaunchIsNotRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := newMuseCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--muse-path", filepath.Join(dir, "stub-never-spawned"),
		"--continue-from", "no-such-session",
		"--", "--yolo",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the unknown source session to fail the handoff render")
	}
	if strings.Contains(err.Error(), "muse subcommand") {
		t.Fatalf("an ordinary flag argv must NOT trip the subcommand guard: %v", err)
	}
}

// TestMuseResumeTranslation pins the native-resume argv translation:
// `--resume <id>` -> `muse resume <id>`, the SUBCOMMAND+positional shape
// (grounded off `muse resume --help`: `Usage: muse resume` / `muse resume
// <session-uuid>`). This exercises the same resumeTranslations row
// TestResumeTranslationsMatchGroundedRegistry cross-checks against the
// registry, at the injectNativeResume argv level. The subcommand LEADS the
// composed argv, ahead of any forwarded user args (injectNativeResume's own
// contract — see resume_launcher.go).
func TestMuseResumeTranslation(t *testing.T) {
	got := injectNativeResume("muse", "abc-123-uuid", nil)
	if !equalArgs(got, []string{"resume", "abc-123-uuid"}) {
		t.Fatalf("injectNativeResume(muse) = %v, want [resume abc-123-uuid]", got)
	}
	// Forwarded flags are preserved AFTER the subcommand+positional pair.
	got = injectNativeResume("muse", "abc-123-uuid", []string{"--yolo"})
	if !equalArgs(got, []string{"resume", "abc-123-uuid", "--yolo"}) {
		t.Fatalf("injectNativeResume(muse, --yolo) = %v, want [resume abc-123-uuid --yolo]", got)
	}
	// A user-forwarded duplicate of the leading subcommand is stripped, not
	// doubled.
	got = injectNativeResume("muse", "abc-123-uuid", []string{"resume", "--yolo"})
	if !equalArgs(got, []string{"resume", "abc-123-uuid", "--yolo"}) {
		t.Fatalf("injectNativeResume(muse) with duplicate leading subcommand = %v, want [resume abc-123-uuid --yolo]", got)
	}
}
