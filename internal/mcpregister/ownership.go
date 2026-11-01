package mcpregister

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ownership.go decides what a registration does with an EXISTING "observer"
// MCP entry (U2, lane FIX-UPGRADE, D-590). Before, any command other than
// this binary's was a conflict that only --force overrode, so an entry an
// older init wrote into an npm package tree (which npm deletes on upgrade)
// could not be repaired without --force, and doctor's "re-run observer init"
// advice looped. The table below is walked top-down; the first row that
// matches decides.

// mcpWriteAction is what a registration does with the entry it found.
type mcpWriteAction int

const (
	// mcpActionAlreadySet: the entry is exactly the desired one.
	mcpActionAlreadySet mcpWriteAction = iota
	// mcpActionRefresh: the entry is Observer's own and is rewritten.
	mcpActionRefresh
	// mcpActionConflict: the entry is not provably Observer's; --force
	// is needed.
	mcpActionConflict
)

// mcpEntryFacts is an existing entry reduced to what the rules read.
type mcpEntryFacts struct {
	// command is the program the entry runs.
	command string
	// args are the entry's arguments after the program.
	args []string
}

// mcpOwnershipEnv is what the rules consult beyond the two entries.
type mcpOwnershipEnv struct {
	// force is --force.
	force bool
	// commandExists reports whether a command still names a file.
	commandExists func(string) bool
	// sameInstall reports whether a command runs this same Observer
	// install (it resolves to the running binary).
	sameInstall func(string) bool
}

// mcpOwnershipRule is one row of the table.
type mcpOwnershipRule struct {
	name   string
	action mcpWriteAction
	match  func(have, want mcpEntryFacts, env mcpOwnershipEnv) bool
}

// mcpOwnershipRules is THE existing-entry decision table.
var mcpOwnershipRules = []mcpOwnershipRule{
	{
		name: "identical", action: mcpActionAlreadySet,
		match: func(have, want mcpEntryFacts, _ mcpOwnershipEnv) bool {
			return have.command == want.command && stringSlicesEqual(have.args, want.args)
		},
	},
	{
		name: "same-command", action: mcpActionRefresh,
		match: func(have, want mcpEntryFacts, _ mcpOwnershipEnv) bool {
			return have.command == want.command
		},
	},
	{
		name: "force", action: mcpActionRefresh,
		match: func(_, _ mcpEntryFacts, env mcpOwnershipEnv) bool { return env.force },
	},
	{
		// An Observer-shaped entry (`<cmd> serve [--config <path>]`) whose
		// command no longer exists: a package manager deleted it. Nothing
		// can be running it, so rewriting it loses nothing.
		name: "stale-observer", action: mcpActionRefresh,
		match: func(have, _ mcpEntryFacts, env mcpOwnershipEnv) bool {
			return observerServeShape(have.args) && env.commandExists != nil && !env.commandExists(have.command)
		},
	},
	{
		// An Observer-shaped entry that runs THIS install by another path
		// (the real binary where the launcher is now registered, or the
		// reverse).
		name: "same-install", action: mcpActionRefresh,
		match: func(have, _ mcpEntryFacts, env mcpOwnershipEnv) bool {
			return observerServeShape(have.args) && env.sameInstall != nil && env.sameInstall(have.command)
		},
	},
	{
		name: "foreign", action: mcpActionConflict,
		match: func(mcpEntryFacts, mcpEntryFacts, mcpOwnershipEnv) bool { return true },
	},
}

// decideMCPEntry walks mcpOwnershipRules and returns the action and the rule
// that decided it.
func decideMCPEntry(have, want mcpEntryFacts, env mcpOwnershipEnv) (mcpWriteAction, string) {
	for _, r := range mcpOwnershipRules {
		if r.match(have, want, env) {
			return r.action, r.name
		}
	}
	return mcpActionConflict, "foreign"
}

// observerServeShape reports whether args are the ones an Observer MCP
// entry carries: ["serve"] or ["serve", "--config", <path>].
func observerServeShape(args []string) bool {
	switch len(args) {
	case 1:
		return args[0] == "serve"
	case 3:
		return args[0] == "serve" && args[1] == "--config"
	}
	return false
}

// IsObserverServeArgs reports whether args are an Observer MCP entry's
// arguments (observerServeShape): the shape the ownership rules read as
// Observer's own.
func IsObserverServeArgs(args []string) bool { return observerServeShape(args) }

// ownershipEnv is the registrar's mcpOwnershipEnv.
func (r *Registrar) ownershipEnv() mcpOwnershipEnv {
	exists := r.opts.commandExists
	if exists == nil {
		exists = commandFileExists
	}
	self := r.opts.SelfBinary
	return mcpOwnershipEnv{
		force:         r.opts.Force,
		commandExists: exists,
		sameInstall: func(cmd string) bool {
			if self == "" || cmd == "" {
				return false
			}
			path, ok := resolveCommandPath(cmd)
			if !ok {
				return false
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return false
			}
			want, err := filepath.EvalSymlinks(self)
			if err != nil {
				want = self
			}
			return filepath.Clean(resolved) == filepath.Clean(want)
		},
	}
}

// commandFileExists reports whether a command names an existing file: an
// absolute path is checked as it is, and a bare program name (no path
// separator, the stable form a managed node registers, FU-24) is resolved
// through PATH, the way the client resolves it. A relative path with a
// separator depends on the client's working directory, which is unknown
// here, so it counts as existing (never proven gone).
func commandFileExists(cmd string) bool {
	if cmd == "" {
		return false
	}
	path, ok := resolveCommandPath(cmd)
	if !ok {
		return false
	}
	if !filepath.IsAbs(path) {
		return true
	}
	_, err := os.Stat(path)
	return err == nil
}

// lookPath is exec.LookPath; a package variable so a test can stand in for
// the PATH search.
var lookPath = exec.LookPath

// resolveCommandPath returns the file a command names: an absolute path as
// it is, a bare name through PATH (ok=false when PATH has none), and a
// relative path with a separator unchanged. A bare name is never resolved
// against the working directory: filepath.EvalSymlinks("observer") would
// read a file named observer in the cwd, not the program the client runs.
func resolveCommandPath(cmd string) (string, bool) {
	if filepath.IsAbs(cmd) || strings.ContainsAny(cmd, `/\`) {
		return cmd, true
	}
	p, err := lookPath(cmd)
	if err != nil {
		return "", false
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return p, true
}

// gateWrite applies RepairOnly: a repair run writes only for the
// stale-observer rule and reports everything else as untouched.
func (r *Registrar) gateWrite(action mcpWriteAction, rule string) (write bool, conflict bool) {
	if r.opts.RepairOnly {
		return action == mcpActionRefresh && rule == "stale-observer", false
	}
	switch action {
	case mcpActionAlreadySet:
		return false, false
	case mcpActionConflict:
		return false, true
	}
	return true, false
}

// tomlStringArgs converts a decoded TOML array to strings; a non-string
// element (not an Observer shape) yields nil.
func tomlStringArgs(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// InitRefreshes reports whether `observer init` WITHOUT --force rewrites an
// existing observer entry (haveCommand, haveArgs) to wantCommand, under the
// same table the writers use. selfBinary is the running binary's real path.
// Doctor uses it to name the exact command that will work (U2).
func InitRefreshes(haveCommand string, haveArgs []string, wantCommand, selfBinary string) bool {
	r := &Registrar{opts: RegisterOptions{SelfBinary: selfBinary}}
	action, _ := decideMCPEntry(
		mcpEntryFacts{command: haveCommand, args: haveArgs},
		mcpEntryFacts{command: wantCommand, args: haveArgs},
		r.ownershipEnv())
	return action != mcpActionConflict
}

// SameInstallCommand reports whether cmd (an absolute path or a bare name
// resolved through PATH) runs the install at selfBinary, the same-install
// rule a registration applies.
func SameInstallCommand(cmd, selfBinary string) bool {
	r := &Registrar{opts: RegisterOptions{SelfBinary: selfBinary}}
	return r.ownershipEnv().sameInstall(cmd)
}

// TOMLStringArgs is tomlStringArgs for callers outside the package that
// read a decoded codex config.toml entry.
func TOMLStringArgs(v any) []string { return tomlStringArgs(v) }
