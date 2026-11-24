// docassisted.go — the shared --continue-from step for DOC-ASSISTED launchers.

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// docAssistedFlags is the handoff-fork flag family a DOC-ASSISTED launcher
// registers (--continue-from and its --carry/--from-message/--from-time
// modifiers), gathered so the shared step below takes one value.
type docAssistedFlags struct {
	continueFrom string
	carry        string
	fromMessage  int
	fromTime     string
}

// engaged reports whether any flag of the family was set (the attach gate's
// incompatible-mode predicate, continueFamilyEngaged).
func (f docAssistedFlags) engaged() bool {
	return continueFamilyEngaged(f.continueFrom, f.carry, f.fromMessage, f.fromTime)
}

// docAssistedContinue is the --continue-from step for a launcher whose
// registry row declares LaunchDocAssisted: the tool's interactive TUI has no
// verified initial-prompt seed, so the handover is written to disk (the file
// lane, resolveContinueFromDoc) and the operator is told where it is. It
// returns the directory the TUI should open in (the source session's project
// root, translated for this OS; "" = inherit the caller's cwd). A launch with
// no --continue-from is a no-op returning "".
//
// The kimi / freebuff launchers inline the same steps; this helper exists so
// the 2026-10-03 launchers (aider, crush, junie, pool) share one copy instead
// of four.
func docAssistedContinue(ctx context.Context, stderr io.Writer, configPath, tool, label string, f docAssistedFlags) (string, error) {
	if f.continueFrom == "" {
		return "", nil
	}
	fork, err := forkFromFlags(f.fromMessage, f.fromTime)
	if err != nil {
		return "", err
	}
	out, err := resolveContinueFromDoc(ctx, configPath, f.continueFrom, tool, f.carry, fork)
	if err != nil {
		fmt.Fprintf(stderr, "observer %s: continue-from failed: %v\n", label, err)
		return "", err
	}
	fmt.Fprintf(stderr, "observer %s: %s has no verified initial-prompt seed, so the handover was written to %s\n", label, label, out.DocPath)
	fmt.Fprintf(stderr, "observer %s: paste it (or point the agent at that file) as your first message\n", label)
	if out.Note != "" {
		fmt.Fprintf(stderr, "observer %s: %s\n", label, out.Note)
	}
	dir := launchDir(out.ProjectRoot)
	if dir != "" {
		fmt.Fprintf(stderr, "observer %s: continuing in %s\n", label, dir)
	}
	return dir, nil
}

// registerDocAssistedFlags registers the handoff-fork flag family on a
// DOC-ASSISTED launcher, wording each flag for the doc-assisted lane.
func registerDocAssistedFlags(cmd *cobra.Command, label string, f *docAssistedFlags) {
	cmdFlags := cmd.Flags()
	cmdFlags.StringVar(&f.continueFrom, "continue-from", "", "Session id to continue from: distill a handover, write it to disk, and open the "+label+" TUI (doc-assisted: no verified initial-prompt seed). See observer handoff --help.")
	cmdFlags.StringVar(&f.carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmdFlags.IntVar(&f.fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmdFlags.StringVar(&f.fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
}

// argsHaveUndeclaredPositional reports whether argv carries a bare positional
// operand once the values of the declared value-taking flags are skipped.
// Several CLIs (junie) treat a positional as a HEADLESS task that runs and
// exits, which must take the bare path rather than attach. An undeclared flag
// is treated as boolean, so its value reads as a positional: the safe
// direction (attach declined, the launch still runs). Tokens after a bare
// `--` are positional by definition.
func argsHaveUndeclaredPositional(args []string, valueFlags map[string]bool) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return i+1 < len(args)
		}
		if len(a) > 1 && a[0] == '-' {
			if valueFlags[a] {
				i++ // skip the flag's separate value token
			}
			continue
		}
		return true
	}
	return false
}
