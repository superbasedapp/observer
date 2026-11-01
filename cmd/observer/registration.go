package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/installshape"
)

// registration.go is the ONE renderer of what a hook or MCP entry invokes
// (lane FIX-UPGRADE U1 + U5). `observer init`, the interactive init, the
// enrolment's --wire-clients step and `observer start`'s auto-registration
// all build their hook / MCP options through it, so the two writers stop
// rewriting each other's entries:
//
//   - the command is installshape.Decide over the running binary: the
//     package manager's launcher when the binary lives in an npm or pip
//     tree (which an upgrade deletes), the real path otherwise (U1);
//   - the --config argument is written only when it names a config other
//     than the default ~/.observer/config.toml, which a hook or MCP server
//     reads anyway (U5). init used to omit it and auto-register used to
//     always spell it out, so each rewrote the other.

// registrationCommand is the command hook and MCP entries invoke for the
// observer binary at binary (an absolute, symlink-resolved path).
func registrationCommand(binary string) string {
	return registrationDecision(binary).Command
}

// registrationWSLTwinBinary is the Windows observer.exe a "-wsl" hook twin
// runs through WSL interop (hook.Options.WSLTwinBinaryPath): the running
// binary itself, binary (absolute, symlink-resolved). On an npm or pip
// install registrationCommand names the package manager's launcher, a
// cmd.exe script interop cannot run; binary is the observer.exe that
// launcher started (FU-214, operator ruling option 1). Every caller that
// registers passes it on every run, so after an upgrade moves the
// observer.exe the next `observer start` re-points the twin.
func registrationWSLTwinBinary(binary string) string { return binary }

// mcpRegistrationCommand is registrationCommand for an MCP server entry.
// With stable set (registrationStableMCPCommand) it is the bare `observer`
// when PATH resolves that name to this same install (installshape.PathName,
// surface-gap FU-24), so the managed allowlist entry `observer org
// emit-managed-settings` writes (serverCommand ["observer", "serve"])
// matches every node, whatever path each one was installed at. Otherwise it
// is today's command.
func mcpRegistrationCommand(binary string, stable bool) string {
	d := registrationDecision(binary)
	if !stable {
		return d.Command
	}
	d, _ = installshape.PathName(registrationInput(binary), d)
	return d.Command
}

// registrationStableMCPCommand reports whether the node at configPath
// registers the stable bare MCP command: only when the operator opted in
// ([observer.mcp] stable_command = true, off by default while the live
// check is owed) AND the node holds a managed (org) enrolment. It reads the
// database only when both the opt-in and the org client are on, so an
// individual node (and a test home) never opens it.
func registrationStableMCPCommand(configPath string) bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !cfg.Observer.MCP.StableCommand || !cfg.OrgClient.Enabled {
		return false
	}
	return launcherManagedNode(context.Background(), configPath)
}

// registrationInput is the installshape input for binary on this host.
func registrationInput(binary string) installshape.Input {
	return installshape.Input{
		GOOS:           runtime.GOOS,
		Binary:         binary,
		PathCandidates: pathObserverCandidates(os.Getenv("PATH")),
		Resolve:        resolveRegularFile,
	}
}

// registrationDecision is installshape.Decide with the file system and PATH
// as its inputs.
func registrationDecision(binary string) installshape.Decision {
	return installshape.Decide(registrationInput(binary))
}

// pathObserverCandidates lists every `observer` launcher on PATH, in order.
func pathObserverCandidates(pathEnv string) []string {
	names := []string{"observer"}
	if runtime.GOOS == "windows" {
		names = []string{"observer.exe"}
	}
	var out []string
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		for _, n := range names {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// resolveRegularFile follows symlinks and reports whether p ends at a
// regular file.
func resolveRegularFile(p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	abs, err := filepath.Abs(r)
	if err != nil {
		return "", false
	}
	fi, err := os.Stat(abs) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return abs, true
}

// registrationConfigArg is the --config value a hook or MCP entry carries:
// "" when configPath is empty or names the default config file for homeDir
// ("" = the real home), configPath otherwise.
func registrationConfigArg(configPath, homeDir string) string {
	if configPath == "" {
		return ""
	}
	def := ""
	if homeDir != "" {
		def = filepath.Join(homeDir, ".observer", "config.toml")
	} else if p, err := config.ResolveGlobalPath(""); err == nil {
		def = p
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		abs = configPath
	}
	if def != "" && filepath.Clean(abs) == filepath.Clean(def) {
		return ""
	}
	return configPath
}

// dashboardBinaryInstall is dashapi.Options.BinaryInstall (U12): the
// install channel of the running binary and whether hooks and MCP entries
// name the package manager's launcher. No path: the route is remote-readable.
func dashboardBinaryInstall() dashapi.BinaryInstall {
	out := dashapi.BinaryInstall{Channel: string(installshape.ChannelOther), Version: version, Registers: "binary"}
	binary, err := absoluteBinaryPath()
	if err != nil {
		return out
	}
	d := registrationDecision(binary)
	out.Channel = string(d.Channel)
	if d.Command != binary {
		out.Registers = "launcher"
	}
	return out
}

// binaryInstallLine is `observer components status`'s binary line (U12): the
// running binary's path, its install channel and what hooks and MCP entries
// invoke.
func binaryInstallLine() string {
	binary, err := absoluteBinaryPath()
	if err != nil {
		return "Binary: unknown (" + err.Error() + ")"
	}
	d := registrationDecision(binary)
	line := "Binary: " + binary + " (v" + version + ", " + installChannelLabel(d.Channel) + ")"
	if d.Command != binary {
		line += "; hooks and MCP entries run " + d.Command + ", which survives a package-manager upgrade"
	}
	return line
}

// installChannelLabel words an install channel for a status line.
func installChannelLabel(c installshape.Channel) string {
	switch c {
	case installshape.ChannelNPM:
		return "installed with npm"
	case installshape.ChannelPip:
		return "installed with pip"
	}
	return "an install.sh, archive or local build install"
}
