package hook

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// # IDE-hosted targets of surface-gap Wave 7 (IDE-6, IDE-10)
//
// devin-windows: a WSL daemon wiring the Windows Devin Desktop, by the one
// hook system each of its surfaces runs (DEC-11): the Cascade editor's
// %USERPROFILE%\.codeium\windsurf\hooks.json when the editor's data
// directory is there, and Devin Local's (the Devin CLI's)
// %APPDATA%\devin\config.json when that directory is there, every command
// the portable wsl.exe bridge. It mirrors the native registerDevinAll file
// for file. LC29 showed Devin Local ALSO fires the Cascade file for its own
// calls; dropping that second invocation at the receiver is FU-87, not
// this writer.
//
// devin-jetbrains: the Windsurf / Devin plugin for JetBrains IDEs reads
// ~/.codeium/hooks.json (docs.devin.ai/desktop/cascade/hooks), the same
// Cascade shape one directory up from the desktop editor's file.
//
// antigravity-cli-windows (IDE-10's "agy-windows"; spelled after the tool id
// so every "-windows" consumer resolves its capability): the Antigravity
// CLI, App and IDE on Windows all run %USERPROFILE%\.gemini\config\hooks.json
// (LC15, LCX-5), so a WSL daemon writes Observer's hook name there behind
// the portable bridge. Kiro IDE stays ungated: LC15 found it runs none of
// Observer's ~/.kiro hooks on Windows or macOS, so there is nothing to
// write.
//
// All three wait on a live check and land switched off (livegate.go);
// devin-windows also waits on FU-87 (see ideTargetGateRows).

// ideTargetGateRows feeds this file's targets into the live-check gate.
// IDE-6-JB names the check the pending tracker does not have a row for yet:
// a JetBrains IDE with the Devin plugin runs ~/.codeium/hooks.json.
func ideTargetGateRows() []liveGateRow {
	return []liveGateRow{
		// DEC-11: devin-windows writes both the Cascade editor's file and
		// Devin Local's CLI config, and Devin Local fires both for one call
		// (LC29), so the receiver-side drop of that second invocation
		// (FU-87) is a prerequisite beside the live check: the row stays
		// off until BOTH have passed.
		{target: "devin-windows", liveChecks: []string{"WSL-4", "FU-87"}},
		{target: "devin-jetbrains", liveChecks: []string{"IDE-6-JB"}},
		{target: "antigravity-cli-windows", liveChecks: []string{"WSL-4"}},
	}
}

// artifactSubdir is the directory of catalogued artifact id relative to a
// user home on goos, in this host's separators, with no relocation variable
// applied (agentconfig.HomeRelativeDir): the cross-OS targets cannot see the
// other side's environment, so they write the vendor default the catalogue
// names. "" when the artifact has no user path there.
func artifactSubdir(id, goos string) string {
	rel, ok := agentconfig.HomeRelativeDir(id, goos)
	if !ok {
		return ""
	}
	return filepath.FromSlash(rel)
}

// devinWindowsCascadeSubdir / devinWindowsCLISubdir are the Windows-side
// directories of Devin Desktop's two surfaces under the user home, from the
// catalogue (devin/cascade-user-hooks, devin/user-config).
var (
	devinWindowsCascadeSubdir = artifactSubdir("devin/cascade-user-hooks", "windows")
	devinWindowsCLISubdir     = artifactSubdir("devin/user-config", "windows")
)

// detectWindowsDevinHome resolves the Windows user home carrying either
// Devin Desktop surface (Options.WindowsUserHome, else the one owned
// Windows home crossmount sees with that directory).
func (r *Registry) detectWindowsDevinHome() string {
	for _, sub := range []string{devinWindowsCascadeSubdir, devinWindowsCLISubdir} {
		if sub == "" {
			continue
		}
		if d := r.detectWindowsHome(r.opts.WindowsUserHome, sub); d != "" {
			return strings.TrimSuffix(d, string(filepath.Separator)+sub)
		}
	}
	return ""
}

// portableCommand is the bridge command builder of a "-windows" target for
// tool.
func (r *Registry) portableCommand(distro, tool string) func(event string) string {
	return func(event string) string {
		return portableBridgeCommand(distro, r.opts.BinaryPath, tool, event, r.opts.ConfigPath)
	}
}

// registerDevinWindows writes devin-windows.
func (r *Registry) registerDevinWindows() RegistrationResult {
	res := RegistrationResult{Tool: "devin-windows", DryRun: r.opts.DryRun}
	home := r.detectWindowsDevinHome()
	if home == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsUserHome) {
			r.sandboxSkipResult(&res, filepath.ToSlash(devinWindowsCascadeSubdir), "WindowsUserHome", r.opts.WindowsUserHome)
			return res
		}
		res.Error = errors.New("hook.registerDevinWindows: no Windows-side Devin Desktop detected (set WindowsUserHome, or run where crossmount sees the Cascade editor's or the Devin CLI's directory under an owned Windows home)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerDevinWindows")
	if err != nil {
		res.Error = err
		return res
	}
	if err := portableBridgePathError("hook.registerDevinWindows", r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	cascadeDir := filepath.Join(home, devinWindowsCascadeSubdir)
	cliDir := filepath.Join(home, devinWindowsCLISubdir)
	cli := r.dirExists(cliDir)
	if r.dirExists(cascadeDir) || !cli {
		res = r.registerCascadeAt(cascadeTarget{
			label: "devin-windows", dir: cascadeDir,
			command:    r.portableCommand(distro, "devin"),
			powershell: true,
			errPrefix:  "hook.registerDevinWindows",
		})
	}
	if res.Error != nil || !cli {
		return res
	}
	t := r.devinCLIHooksTarget()
	t.dir, t.label, t.portableDistro, t.errPrefix = cliDir, "devin-windows", distro, "hook.registerDevinWindows"
	c := r.registerJSONHooks(t)
	return mergeDevinResults(res, c)
}

// mergeDevinResults folds the Devin CLI half into the Cascade half, the way
// registerDevinAll reports both files as one target.
func mergeDevinResults(res, c RegistrationResult) RegistrationResult {
	if res.ConfigPath == "" {
		res.ConfigPath = c.ConfigPath
	}
	res.Warnings = append(res.Warnings, c.Warnings...)
	res.HooksAdded = append(res.HooksAdded, c.HooksAdded...)
	res.AlreadySet = append(res.AlreadySet, c.AlreadySet...)
	if c.Error != nil {
		res.Error = c.Error
	}
	return res
}

// unregisterDevinWindows removes both devin-windows files' entries.
func (r *Registry) unregisterDevinWindows() UnregistrationResult {
	home := r.detectWindowsDevinHome()
	if home == "" {
		return UnregistrationResult{Tool: "devin-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	res := r.unregisterCascadeAt("devin-windows", filepath.Join(home, devinWindowsCascadeSubdir))
	distro, _ := r.resolveWSLDistro("hook.unregisterDevinWindows")
	t := r.devinCLIHooksTarget()
	t.dir, t.label, t.portableDistro = filepath.Join(home, devinWindowsCLISubdir), "devin-windows", distro
	cli := r.unregisterJSONHooks(t)
	res.HooksRemoved = append(res.HooksRemoved, cli.HooksRemoved...)
	if res.Error == nil {
		res.Error = cli.Error
	}
	return res
}

// devinJetBrainsDir is the JetBrains plugin's hooks.json directory (the
// devin/cascade-jetbrains-hooks artifact; "" when it does not resolve). Its
// presence is the install signal, which the desktop editor's
// ~/.codeium/windsurf also satisfies: grounding a plugin-only signal is
// part of switching the target on (IDE-6-JB).
func (r *Registry) devinJetBrainsDir() string {
	d, err := r.artifactDir("devin/cascade-jetbrains-hooks")
	if err != nil {
		return ""
	}
	return d
}

// registerDevinJetBrains writes devin-jetbrains on the daemon's own OS.
func (r *Registry) registerDevinJetBrains() RegistrationResult {
	if r.devinJetBrainsDir() == "" {
		_, err := r.artifactDir("devin/cascade-jetbrains-hooks")
		return RegistrationResult{Tool: "devin-jetbrains", DryRun: r.opts.DryRun, Error: err}
	}
	return r.registerCascadeAt(cascadeTarget{
		label: "devin-jetbrains", dir: r.devinJetBrainsDir(),
		command:   r.nativeCascadeCommand,
		errPrefix: "hook.registerDevinJetBrains",
	})
}

// unregisterDevinJetBrains removes devin-jetbrains' entries.
func (r *Registry) unregisterDevinJetBrains() UnregistrationResult {
	dir := r.devinJetBrainsDir()
	if dir == "" {
		return UnregistrationResult{Tool: "devin-jetbrains", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterCascadeAt("devin-jetbrains", dir)
}

// detectWindowsAgyHome resolves the Windows user home carrying any
// Antigravity product's data directory under .gemini (the install signal of
// every product that runs .gemini/config/hooks.json).
func (r *Registry) detectWindowsAgyHome() string {
	gemini := agyGeminiSubdir("windows")
	if gemini == "" {
		return ""
	}
	for _, d := range agyHookFileReaderDirs {
		sub := filepath.Join(gemini, d)
		if dir := r.detectWindowsHome(r.opts.WindowsGeminiHome, sub); dir != "" {
			return strings.TrimSuffix(dir, string(filepath.Separator)+sub)
		}
	}
	return ""
}

// registerAntigravityCLIWindows writes antigravity-cli-windows.
func (r *Registry) registerAntigravityCLIWindows() RegistrationResult {
	res := RegistrationResult{Tool: "antigravity-cli-windows", DryRun: r.opts.DryRun}
	home := r.detectWindowsAgyHome()
	if home == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsGeminiHome) {
			r.sandboxSkipResult(&res, filepath.ToSlash(agyGeminiSubdir("windows")), "WindowsGeminiHome", r.opts.WindowsGeminiHome)
			return res
		}
		res.Error = errors.New("hook.registerAntigravityCLIWindows: no Windows-side Antigravity data directory detected (set WindowsGeminiHome, or run where crossmount sees an Antigravity product's data directory under an owned Windows home)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerAntigravityCLIWindows")
	if err != nil {
		res.Error = err
		return res
	}
	if err := portableBridgePathError("hook.registerAntigravityCLIWindows", r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return r.registerAgyAt(agyTarget{
		label: "antigravity-cli-windows", home: home, goos: "windows",
		command: r.portableCommand(distro, "antigravity-cli"),
	})
}

// unregisterAntigravityCLIWindows removes antigravity-cli-windows' entry.
func (r *Registry) unregisterAntigravityCLIWindows() UnregistrationResult {
	home := r.detectWindowsAgyHome()
	if home == "" {
		return UnregistrationResult{Tool: "antigravity-cli-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterAgyAt("antigravity-cli-windows", home, "windows")
}

// installedIDETargets lists this file's detected targets; a gated one only
// when includeGated is set (InstalledLiveGated), so Installed spends no
// detection on a target it would drop.
func (r *Registry) installedIDETargets(includeGated bool) []string {
	var out []string
	for _, t := range []struct {
		target   string
		detected func() bool
	}{
		{"devin-windows", func() bool { return r.detectWindowsDevinHome() != "" }},
		{"devin-jetbrains", func() bool { d := r.devinJetBrainsDir(); return d != "" && r.dirExists(d) }},
		{"antigravity-cli-windows", func() bool { return r.detectWindowsAgyHome() != "" }},
	} {
		if _, gated := LiveCheckGate(t.target); gated && !includeGated {
			continue
		}
		if t.detected() {
			out = append(out, t.target)
		}
	}
	return out
}
