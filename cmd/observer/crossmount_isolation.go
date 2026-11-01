package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// noCrossmountFlag is the root flag that switches foreign-OS (WSL/Windows)
// profile detection and writes off for one command (R-013).
const noCrossmountFlag = "no-crossmount"

// noCrossmountHelp is the flag's help line; `observer init --help` lists it
// under Global Flags and init's long help repeats the rule.
const noCrossmountHelp = "never detect or write a foreign-OS profile (the Windows side of WSL, or WSL from Windows); " +
	"also implied when HOME is not the real user home, when --config is outside the real user home, or when " + crossmount.EnvDisableForeignHomes + "=1 is set"

// crossmountIsolationHelp is the paragraph `observer init --help` carries.
const crossmountIsolationHelp = "Isolation: when HOME (USERPROFILE on Windows) is not exactly the real user home (a scratch dir beneath it counts), " +
	"when --config points outside the real user home, " +
	"or --no-crossmount or " + crossmount.EnvDisableForeignHomes + "=1 is given, no foreign-OS profile is detected or written: " +
	"no Windows-side hooks, MCP entries, proxy routes or browser-host files from WSL, and no WSL-side ones from Windows. " +
	"`observer doctor` names the reason on its crossmount row."

// addCrossmountIsolationFlag registers --no-crossmount on root and the
// pre-run step that records the isolation reason before any command body
// resolves a home. cobra runs only the nearest persistent pre-run, so a
// subcommand that defines its own (`sandbox hosted`,
// terminal_sandbox_hosted_leftovers.go) calls applyCrossmountIsolation
// first itself (LEFT2 audit S5); TestEveryPersistentPreRunAppliesIsolation
// walks the tree for any other.
func addCrossmountIsolationFlag(root *cobra.Command) {
	root.PersistentFlags().Bool(noCrossmountFlag, false, noCrossmountHelp)
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		applyCrossmountIsolation(cmd)
		return nil
	}
}

// applyCrossmountIsolation records why this command must not reach a foreign
// profile: the --no-crossmount flag, or a --config outside the real user
// home. An isolated HOME needs no step here; crossmount reads it itself.
func applyCrossmountIsolation(cmd *cobra.Command) {
	if f := cmd.Flags().Lookup(noCrossmountFlag); f != nil && f.Changed && f.Value.String() == "true" {
		crossmount.DisableForProcess("--no-crossmount was given")
		return
	}
	if f := cmd.Flags().Lookup("config"); f != nil && f.Changed {
		crossmount.DisableForProcess(crossmount.ConfigOutsideRealHome(f.Value.String()))
	}
}
