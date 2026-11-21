// setup_extras_dash.go - dashboard CLI parity, lane L2: the three Settings
// controls that used to exist only as CLI verbs. Each is an adapter over the
// code the CLI runs, handed to the dashboard through dashapi.SetupExtras:
//
//   - the Claude Code status line (`observer init --statusline`), through the
//     same hook.Registry writers, byte-exact removal included;
//   - start at login (`observer service install` / `uninstall` on Linux and
//     macOS, `observer setup autostart` on Windows), WITHOUT --now: it never
//     starts, stops or restarts the daemon, and it never overwrites an
//     existing entry;
//   - the browser-capture native-messaging host (`observer init --browser`),
//     through runBrowserOnlyInit.
//
// The dashboard package never sees these types: it calls the dashapi
// interfaces and gets plain results (CLAUDE.md module rule 2).

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/setup"
)

// dashboardSetupExtras builds the three setup controls over configPath. It is
// the single call the two dashboard wiring sites (`observer start` and
// `observer dashboard`) make.
func dashboardSetupExtras(configPath string) *dashapi.SetupExtras {
	return &dashapi.SetupExtras{
		Statusline: &statuslineDash{configPath: configPath},
		LoginStart: &loginStartDash{configPath: configPath, sys: defaultSetupOS()},
		Browser:    &browserDash{configPath: configPath},
	}
}

// splitOutputLines turns a writer's text into non-empty trimmed lines.
func splitOutputLines(s string) []string {
	out := []string{}
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, " \t\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// componentGate reports whether component id is active, through gate when a
// test injected one, else the node's resolved component state.
func componentGate(gate func(id string) bool, configPath, id string) bool {
	if gate != nil {
		return gate(id)
	}
	return componentSnapshotFor(configPath).Active(id)
}

// ------------------------------------------------------------- status line

// statuslineDash adapts the Claude Code status line writer.
type statuslineDash struct {
	configPath string
	// binary overrides the observer binary the entry runs (tests); "" = this
	// process's own binary, which is what `observer init` writes.
	binary string
	// homeDir pins the home (tests); "" = the real home.
	homeDir string
	// gate overrides the component-active check (tests).
	gate func(id string) bool
}

// registry builds the writer registry for one call.
func (d *statuslineDash) registry(dry, force bool) (*hook.Registry, string, error) {
	bin := d.binary
	if bin == "" {
		b, err := absoluteBinaryPath()
		if err != nil {
			return nil, "", err
		}
		bin = b
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: bin, ConfigPath: d.configPath, HomeDir: d.homeDir, DryRun: dry, Force: force})
	return reg, bin, err
}

// statuslineSupport reports whether this daemon can write Claude Code's
// settings: the status line runs on every render, so (like the CLI) it is
// native-OS only and no cross-OS bridge is written.
func statuslineSupport(installed []string) (bool, string) {
	switch {
	case contains(installed, "claude-code"):
		return true, ""
	case contains(installed, "claude-code-windows"):
		return false, "Claude Code was found only on the Windows side of this WSL setup. The status line runs on every render, so set it up from the OS where Claude Code itself runs."
	}
	return false, "Claude Code was not found on this machine."
}

// active reports whether the status line component is active; the reason is
// the dashboard's own wording.
func (d *statuslineDash) active() (bool, string) {
	if componentGate(d.gate, d.configPath, "integration.statusline") {
		return true, ""
	}
	return false, "The Claude Code status line component is not active on this node. Turn it on in Settings > Components, then try again."
}

// classify reads where the entry stands through the writers' own dry runs
// (nothing is written and no lock is taken): the removal dry run says whether
// an Observer-written entry exists (a foreign one is reported as kept), and
// the install dry run says whether it already matches byte for byte.
func (d *statuslineDash) classify(reg *hook.Registry) (dashapi.StatuslineState, string, error) {
	un := reg.UnregisterClaudeCodeStatusline()
	if un.Error != nil {
		return dashapi.StatuslineAbsent, un.ConfigPath, un.Error
	}
	switch {
	case !un.Skipped:
		in := reg.RegisterClaudeCodeStatusline()
		if in.Error != nil {
			return dashapi.StatuslineStale, un.ConfigPath, nil
		}
		if len(in.AlreadySet) > 0 {
			return dashapi.StatuslineInstalled, un.ConfigPath, nil
		}
		return dashapi.StatuslineStale, un.ConfigPath, nil
	case len(un.HooksKept) > 0:
		return dashapi.StatuslineForeign, un.ConfigPath, nil
	}
	return dashapi.StatuslineAbsent, un.ConfigPath, nil
}

// Status implements dashapi.StatuslineSetup.
func (d *statuslineDash) Status(_ context.Context) (dashapi.StatuslineStatus, error) {
	reg, bin, err := d.registry(true, false)
	if err != nil {
		return dashapi.StatuslineStatus{}, fmt.Errorf("statusline status: %w", err)
	}
	st := dashapi.StatuslineStatus{State: dashapi.StatuslineAbsent, Command: bin + " statusline"}
	if ok, why := statuslineSupport(reg.Installed()); !ok {
		st.Reason = why
		return st, nil
	}
	st.Supported = true
	state, path, err := d.classify(reg)
	if err != nil {
		return st, fmt.Errorf("statusline status: %w", err)
	}
	st.State, st.ConfigPath = state, path
	return st, nil
}

// Apply implements dashapi.StatuslineSetup.
func (d *statuslineDash) Apply(_ context.Context, action dashapi.SetupAction, dryRun, force bool) (dashapi.SetupOutcome, error) {
	out := dashapi.SetupOutcome{Action: action, DryRun: dryRun, Lines: []string{}}
	reg, bin, err := d.registry(dryRun, force)
	if err != nil {
		return out, fmt.Errorf("statusline: %w", err)
	}
	if ok, why := statuslineSupport(reg.Installed()); !ok {
		out.Refused, out.Reason = true, why
		return out, nil
	}
	switch action {
	case dashapi.SetupRemove:
		res := reg.UnregisterClaudeCodeStatusline()
		out.Path = res.ConfigPath
		if res.Error != nil {
			return out, fmt.Errorf("statusline remove: %w", res.Error)
		}
		switch {
		case !res.Skipped:
			out.Changed = true
			out.Lines = append(out.Lines, fmt.Sprintf("Remove the \"statusLine\" entry from %s (the rest of the file is kept as it is).", res.ConfigPath))
		case len(res.HooksKept) > 0:
			out.Refused = true
			out.Reason = "The status line in " + res.ConfigPath + " is not Observer's, so it is left untouched."
		default:
			out.Lines = append(out.Lines, "Nothing to remove: there is no status line entry in "+res.ConfigPath+".")
		}
		return out, nil
	case dashapi.SetupInstall:
		if ok, why := d.active(); !ok {
			out.Refused, out.Reason = true, why
			return out, nil
		}
		// Classify with a dry-run registry so a foreign entry is reported in
		// the dashboard's words instead of a CLI flag hint.
		probe, _, perr := d.registry(true, false)
		if perr != nil {
			return out, fmt.Errorf("statusline: %w", perr)
		}
		state, path, cerr := d.classify(probe)
		out.Path = path
		if cerr != nil {
			return out, fmt.Errorf("statusline install: %w", cerr)
		}
		if state == dashapi.StatuslineForeign && !force {
			out.Refused = true
			out.Reason = "Claude Code already has a status line command in " + path + " that Observer did not write. Choose \"Replace it\" to overwrite it."
			return out, nil
		}
		res := reg.RegisterClaudeCodeStatusline()
		out.Path = res.ConfigPath
		if res.Error != nil {
			return out, fmt.Errorf("statusline install: %w", res.Error)
		}
		if len(res.AlreadySet) > 0 {
			out.Lines = append(out.Lines, "Already set in "+res.ConfigPath+"; nothing to change.")
			return out, nil
		}
		out.Changed = true
		out.Lines = append(out.Lines,
			fmt.Sprintf("Set the \"statusLine\" entry in %s to run: %s statusline", res.ConfigPath, bin),
			"The dollar figures it prints are an estimated list price, not invoiced.")
		return out, nil
	}
	return out, fmt.Errorf("statusline: unknown action %q", action)
}

// -------------------------------------------------------------- start at login

// Managers a start-at-login entry can use, by capability of the host.
const (
	loginManagerSystemd = "systemd-user"
	loginManagerLaunchd = "launchd"
	loginManagerWinRun  = "windows-run"
)

// loginStartDash adapts the user-level start-at-login install. It never starts
// or stops the daemon, so it is safe to use while the daemon is running under
// the very unit it installs or removes.
type loginStartDash struct {
	configPath string
	sys        setupOS
	// deps are the install's injected I/O (zero value = production); tests
	// stand in for systemd here.
	deps serviceInstallDeps
	// query runs a read-only host command and returns its output (nil =
	// exec). It backs the enabled / running reads.
	query func(ctx context.Context, c service.Command) (string, error)
	// exeDir overrides the directory holding observer and observerw.exe for
	// the Windows entry (tests); "" = the running binary's, else the setup dir.
	exeDir string
}

// manager picks the start-at-login mechanism by capability of this host
// (launchd, then systemd, then the Windows sign-in entry), never by OS name.
func (d *loginStartDash) manager() (id, label string) {
	switch {
	case launchdAvailable():
		return loginManagerLaunchd, "a launchd LaunchAgent"
	case systemdAvailable():
		return loginManagerSystemd, "a systemd user unit"
	case d.sys.supportsRun():
		return loginManagerWinRun, "the Windows sign-in entry"
	}
	return "", ""
}

// run executes a read-only command, bounded.
func (d *loginStartDash) run(ctx context.Context, c service.Command) (string, error) {
	if d.query != nil {
		return d.query(ctx, c)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, c.Name, c.Args...).CombinedOutput() //nolint:gosec // fixed program names, args from the pure builder
	return strings.TrimSpace(string(b)), err
}

// windowsAutostartDir is the directory the sign-in entry's launcher lives in:
// the running binary's when observerw.exe sits beside it, else the setup
// program's directory (the CLI default).
func (d *loginStartDash) windowsAutostartDir() string {
	if d.exeDir != "" {
		return d.exeDir
	}
	if exe, err := absoluteBinaryPath(); err == nil {
		dir := filepath.Dir(exe)
		if _, serr := os.Stat(filepath.Join(dir, setup.WindowlessName)); serr == nil {
			return dir
		}
	}
	return defaultSetupDir()
}

// windowsRunPath names the registry value for display.
func windowsRunPath() string {
	return `HKCU\` + setup.RunKeyPath + `\` + setup.RunValueName
}

// Status implements dashapi.LoginStartService.
func (d *loginStartDash) Status(ctx context.Context) (dashapi.LoginStartStatus, error) {
	id, label := d.manager()
	st := dashapi.LoginStartStatus{Manager: id, ManagerLabel: label}
	switch id {
	case loginManagerSystemd:
		home, err := os.UserHomeDir()
		if err != nil {
			return st, fmt.Errorf("login-start status: %w", err)
		}
		st.Supported, st.Path = true, service.UnitPath(service.ScopeUser, home)
		body, rerr := os.ReadFile(st.Path) //nolint:gosec // the unit path is fixed by scope
		if rerr != nil {
			return st, nil
		}
		st.Installed, st.Command = true, service.ExecStartLine(string(body))
		if out, qerr := d.run(ctx, service.Systemctl(service.ScopeUser, "is-enabled", service.UnitName)); qerr == nil {
			st.Enabled = out == "enabled"
		}
		if out, qerr := d.run(ctx, service.Systemctl(service.ScopeUser, "is-active", service.UnitName)); qerr == nil {
			st.Running = out == "active"
		}
	case loginManagerLaunchd:
		home, err := os.UserHomeDir()
		if err != nil {
			return st, fmt.Errorf("login-start status: %w", err)
		}
		st.Supported, st.Path = true, service.LaunchAgentPath(home)
		body, rerr := os.ReadFile(st.Path) //nolint:gosec // fixed per-user path
		if rerr != nil {
			return st, nil
		}
		st.Installed, st.Enabled = true, true // RunAtLoad: the agent starts at the next login
		if prog, ok := service.LaunchAgentProgramArguments(string(body)); ok {
			st.Command = strings.Join(prog, " ")
		}
		uid := os.Getuid()
		if _, qerr := d.run(ctx, service.Launchctl("print", service.LaunchdTarget(uid))); qerr == nil {
			st.Running = true
		}
	case loginManagerWinRun:
		st.Supported, st.Path = true, windowsRunPath()
		cur, err := d.sys.readRun()
		if err != nil {
			return st, fmt.Errorf("login-start status: %w", err)
		}
		st.Installed, st.Enabled, st.Command = cur != "", cur != "", cur
	default:
		st.Reason = "This system has no per-user start-at-login mechanism Observer can write (it needs systemd, launchd or Windows)."
	}
	return st, nil
}

// Apply implements dashapi.LoginStartService.
func (d *loginStartDash) Apply(ctx context.Context, action dashapi.SetupAction, dryRun bool) (dashapi.SetupOutcome, error) {
	out := dashapi.SetupOutcome{Action: action, DryRun: dryRun, Lines: []string{}}
	st, err := d.Status(ctx)
	if err != nil {
		return out, err
	}
	out.Path = st.Path
	if !st.Supported {
		out.Refused, out.Reason = true, st.Reason
		return out, nil
	}
	switch action {
	case dashapi.SetupInstall:
		if st.Installed {
			out.Refused = true
			out.Reason = "A start-at-login entry already exists (" + st.Path + "). Observer will not overwrite it; remove it first if you want a fresh one."
			return out, nil
		}
		return d.install(st, out)
	case dashapi.SetupRemove:
		if !st.Installed {
			out.Lines = append(out.Lines, "Nothing to remove: Observer has no start-at-login entry here.")
			return out, nil
		}
		return d.remove(st, out)
	}
	return out, fmt.Errorf("login-start: unknown action %q", action)
}

// installOptions builds the CLI install's options for a no-start user install.
func (d *loginStartDash) installOptions(w io.Writer) serviceInstallOptions {
	return serviceInstallOptions{scope: service.ScopeUser, configPath: d.configPath, stdout: w, deps: d.deps}
}

// install writes the entry. Nothing is started: systemd gets `enable` without
// --now, launchd's RunAtLoad starts it at the next login, Windows gets the
// Run value.
func (d *loginStartDash) install(st dashapi.LoginStartStatus, out dashapi.SetupOutcome) (dashapi.SetupOutcome, error) {
	exe := d.deps.exe
	if exe == "" {
		b, err := absoluteBinaryPath()
		if err != nil {
			return out, fmt.Errorf("login-start install: %w", err)
		}
		exe = b
	}
	switch st.Manager {
	case loginManagerSystemd:
		args, _ := serviceUnitArgs(&serviceInstallOptions{scope: service.ScopeUser, configPath: d.configPath, stdout: io.Discard}, st.Path, "", exe)
		runs := strings.TrimSpace(exe + " start " + strings.Join(args, " "))
		out.Lines = append(out.Lines,
			"Write "+st.Path+" (a systemd user unit that runs: "+runs+").",
			"Reload systemd, then enable the unit so it starts at your next login.",
			"Nothing is started now, and the running daemon is not touched.")
		if out.DryRun {
			return out, nil
		}
		var buf bytes.Buffer
		if err := runServiceInstall(d.installOptions(&buf)); err != nil {
			return out, fmt.Errorf("login-start install: %w", err)
		}
		probe := defaultServiceProbe()
		if d.deps.probe != nil {
			probe = *d.deps.probe
		}
		if err := probe.run(service.Systemctl(service.ScopeUser, "enable", service.UnitName)); err != nil {
			return out, fmt.Errorf("login-start install: unit written but systemctl enable failed: %w", err)
		}
		out.Changed = true
		return out, nil
	case loginManagerLaunchd:
		out.Lines = append(out.Lines,
			"Write "+st.Path+" (a LaunchAgent that runs: "+exe+" start).",
			"It starts at your next login. Nothing is started now, and the running daemon is not touched.")
		if out.DryRun {
			return out, nil
		}
		var buf bytes.Buffer
		if err := runLaunchdInstall(d.installOptions(&buf), launchdDeps{exe: d.deps.exe, pathDirs: d.deps.pathDirs}); err != nil {
			return out, fmt.Errorf("login-start install: %w", err)
		}
		out.Changed = true
		return out, nil
	case loginManagerWinRun:
		dir := d.windowsAutostartDir()
		launcher := filepath.Join(dir, setup.WindowlessName)
		if _, err := os.Stat(launcher); err != nil {
			out.Refused = true
			out.Reason = "Start at sign-in needs " + setup.WindowlessName + " beside observer.exe. It ships with the Windows setup program from " + setup.DownloadURL + "."
			return out, nil
		}
		out.Lines = append(out.Lines,
			"Set "+windowsRunPath()+" to: "+setup.RunValue(launcher),
			"Observer starts when you next sign in to Windows. Nothing is started now.")
		if out.DryRun {
			return out, nil
		}
		var buf bytes.Buffer
		if err := setupAutostartOn(d.sys, &buf, dir); err != nil {
			return out, fmt.Errorf("login-start install: %w", err)
		}
		out.Changed = true
		return out, nil
	}
	return out, errors.New("login-start install: no start-at-login mechanism on this host")
}

// remove deletes the entry without stopping anything: systemd `disable`
// (no --now) then the unit file, launchd the plist (the loaded agent keeps
// running until logout), Windows the Run value.
func (d *loginStartDash) remove(st dashapi.LoginStartStatus, out dashapi.SetupOutcome) (dashapi.SetupOutcome, error) {
	keep := "The running daemon is not stopped."
	switch st.Manager {
	case loginManagerSystemd:
		out.Lines = append(out.Lines,
			"Disable the unit so it no longer starts at login, then delete "+st.Path+" and reload systemd.", keep)
		if out.DryRun {
			return out, nil
		}
		probe := defaultServiceProbe()
		if d.deps.probe != nil {
			probe = *d.deps.probe
		}
		// disable without --now: a stop would end the daemon this dashboard is served by.
		_ = probe.run(service.Systemctl(service.ScopeUser, "disable", service.UnitName))
		if err := os.Remove(st.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, fmt.Errorf("login-start remove: %w", err)
		}
		if err := probe.run(service.Systemctl(service.ScopeUser, "daemon-reload")); err != nil {
			return out, fmt.Errorf("login-start remove: entry deleted but systemctl daemon-reload failed: %w", err)
		}
		out.Changed = true
		return out, nil
	case loginManagerLaunchd:
		out.Lines = append(out.Lines,
			"Delete "+st.Path+" so Observer no longer starts at login.",
			"The agent stays loaded until you log out, so the running daemon keeps running.")
		if out.DryRun {
			return out, nil
		}
		if err := os.Remove(st.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, fmt.Errorf("login-start remove: %w", err)
		}
		out.Changed = true
		return out, nil
	case loginManagerWinRun:
		out.Lines = append(out.Lines, "Delete "+windowsRunPath()+" so Observer no longer starts when you sign in.", keep)
		if out.DryRun {
			return out, nil
		}
		var buf bytes.Buffer
		if err := setupAutostartOff(d.sys, &buf); err != nil {
			return out, fmt.Errorf("login-start remove: %w", err)
		}
		out.Changed = true
		return out, nil
	}
	return out, errors.New("login-start remove: no start-at-login mechanism on this host")
}

// ------------------------------------------------------------- browser capture

// browserDash adapts `observer init --browser` (the native-messaging host and
// the per-browser manifests).
type browserDash struct {
	configPath string
	// binary, home and winHomes override the ambient inputs (tests).
	binary   string
	home     string
	winHomes []string
	// registry builds the Windows registry writer (nil = reg.exe).
	registry func() (browserhost.RegistryWriter, error)
	// gate overrides the component-active check (tests).
	gate func(id string) bool
}

// inputs resolves the ambient Windows/WSL browser inputs once per call.
func (d *browserDash) inputs() (homes []string, distro string, reg func() (browserhost.RegistryWriter, error)) {
	if d.winHomes != nil || d.registry != nil {
		return d.winHomes, "", d.registry
	}
	return productionWindowsBrowserInputs()
}

// Status implements dashapi.BrowserCaptureSetup.
func (d *browserDash) Status(_ context.Context) (dashapi.BrowserCaptureStatus, error) {
	st := dashapi.BrowserCaptureStatus{HostFiles: []string{}, Candidates: []dashapi.BrowserExtensionCandidate{}}
	if !anyExtensionSupported() {
		st.Reason = "This build has no browser-capture rail."
		return st, nil
	}
	st.Supported = true
	homes, _, _ := d.inputs()
	if files := browserhost.Present(browserhost.PresenceOptions{Home: d.home, WindowsHomes: homes}); len(files) > 0 {
		st.HostFiles, st.Installed = files, true
	}
	for _, c := range discoverExtensionIDs(d.home, homes) {
		st.Candidates = append(st.Candidates, dashapi.BrowserExtensionCandidate{Browser: c.Browser, Profile: c.Profile, ID: c.ID})
	}
	return st, nil
}

// Apply implements dashapi.BrowserCaptureSetup.
func (d *browserDash) Apply(_ context.Context, extensionID string, dryRun bool) (dashapi.SetupOutcome, error) {
	out := dashapi.SetupOutcome{Action: dashapi.SetupInstall, DryRun: dryRun, Lines: []string{}}
	extensionID = strings.TrimSpace(extensionID)
	if extensionID != "" && !browserhost.ValidExtensionID(extensionID) {
		return out, fmt.Errorf("%w: an extension id is 32 lowercase letters a to p", dashapi.ErrSetupInput)
	}
	if !componentGate(d.gate, d.configPath, "capture.browser") {
		out.Refused = true
		out.Reason = "The browser capture component is not active on this node. Turn it on in Settings > Components, then try again."
		return out, nil
	}
	bin := d.binary
	if bin == "" {
		b, err := absoluteBinaryPath()
		if err != nil {
			return out, fmt.Errorf("browser setup: %w", err)
		}
		bin = b
	}
	homes, distro, reg := d.inputs()
	var buf bytes.Buffer
	err := runBrowserOnlyInit(&buf, strings.NewReader(""), browserOnlyOptions{
		BinaryPath:          bin,
		ConfigPath:          d.configPath,
		ExtensionID:         extensionID,
		DryRun:              dryRun,
		HomeDir:             d.home,
		WindowsBrowserHomes: homes,
		WSLDistro:           distro,
		NewWindowsRegistry:  reg,
	})
	out.Lines = browserOutcomeLines(splitOutputLines(buf.String()))
	if err != nil {
		return out, fmt.Errorf("browser setup: %w", err)
	}
	out.Changed = browserLinesChanged(out.Lines)
	return out, nil
}

// browserPlaceholderNote is the dashboard's wording for the follow-up the CLI
// prints when no extension id was given.
const browserPlaceholderNote = "No extension id was given, so a placeholder is written. After you load the extension in your browser, paste its id here and install again."

// browserOutcomeLines rewrites the CLI step's output for the dashboard: the
// block that tells the reader to re-run `observer init` or hand-edit a
// manifest (a "no extension id supplied" line and the indented lines under
// it) becomes one sentence naming this card. Every other line is kept.
func browserOutcomeLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	skipping := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "browser: no extension id supplied"):
			out = append(out, browserPlaceholderNote)
			skipping = true
		case skipping && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")):
			// still inside the CLI follow-up block
		default:
			skipping = false
			out = append(out, l)
		}
	}
	return out
}

// browserLinesChanged reports whether the step wrote (or, in a preview, would
// write) a host file or manifest, from its result lines.
func browserLinesChanged(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "would write") || strings.Contains(l, "wrote native-messaging") {
			return true
		}
	}
	return false
}
