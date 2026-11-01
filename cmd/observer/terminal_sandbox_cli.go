//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_cli.go is the sandboxed CLI launch (sandbox plan v2
// section 9, ruling Q10): `observer <tool> --observer-sandbox <profile> [args]` runs a
// typed launch inside the same sandbox a dashboard New Terminal builds,
// through the same lifecycle seam (Create then Attach), so a CLI launch no
// longer has to be refused and sent to the dashboard when an org requires
// a sandbox. It runs before cobra, like the sandbox helpers: it strips its
// own flag, prepares the run in the current directory (the live source) and
// runs bwrap around `observer <verb> <the remaining args>` with the sandbox
// marker set, so the inner launcher routes, hooks and gates exactly as it
// does in a dashboard sandbox.

// sandboxCLIExit codes: 2 for a usage error, 3 for "not available here".
const (
	sandboxCLIUsage       = 2
	sandboxCLIUnavailable = 3
)

// sandboxCLIRequest is the parsed `--observer-sandbox` launch.
type sandboxCLIRequest struct {
	Verb, Tool, Profile, ConfigPath string
	// Rest is the verb's own arguments with the --observer-sandbox flag removed.
	Rest []string
}

// parseSandboxCLI finds `--observer-sandbox <profile>` / `--observer-sandbox=<profile>` among
// a launcher verb's own arguments (before any "--"). ok=false means the
// invocation is not a sandboxed launch and cobra handles it unchanged.
func parseSandboxCLI(args []string) (sandboxCLIRequest, bool, error) {
	if len(args) < 2 {
		return sandboxCLIRequest{}, false, nil
	}
	tool, ok := integration.ToolForLaunchSubcommand(args[1])
	if !ok {
		return sandboxCLIRequest{}, false, nil
	}
	req := sandboxCLIRequest{Verb: args[1], Tool: tool}
	found := false
	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			req.Rest = append(req.Rest, rest[i:]...)
			break
		}
		switch {
		case a == "--observer-sandbox":
			next := ""
			if i+1 < len(rest) {
				next = rest[i+1]
			}
			if next == "" || next[0] == '-' {
				return sandboxCLIRequest{}, true, errors.New("--observer-sandbox needs a profile (for example --observer-sandbox bwrap, or --observer-sandbox auto)")
			}
			req.Profile, found = next, true
			i++
			continue
		case len(a) > len("--observer-sandbox=") && a[:len("--observer-sandbox=")] == "--observer-sandbox=":
			req.Profile, found = a[len("--observer-sandbox="):], true
			continue
		case a == "--config" && i+1 < len(rest):
			req.ConfigPath = rest[i+1]
		case len(a) > len("--config=") && a[:len("--config=")] == "--config=":
			req.ConfigPath = a[len("--config="):]
		}
		req.Rest = append(req.Rest, a)
	}
	if !found {
		return sandboxCLIRequest{}, false, nil
	}
	return req, true, nil
}

// sandboxCLIDispatch runs a sandboxed CLI launch when args ask for one.
// ok=false hands the invocation to cobra unchanged.
func sandboxCLIDispatch(args []string) (int, bool) {
	req, ok, err := parseSandboxCLI(args)
	if !ok {
		return 0, false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", args[1], err)
		return sandboxCLIUsage, true
	}
	return runSandboxCLI(context.Background(), req, os.Stderr), true
}

// runSandboxCLI prepares the run and executes the chosen backend's wrap
// (bwrap, or a driver's host helper) around the inner launch. Every refusal
// is one line naming why and the setting that lifts it; nothing is ever run
// unsandboxed instead.
func runSandboxCLI(ctx context.Context, req sandboxCLIRequest, stderr io.Writer) int {
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "observer %s --observer-sandbox: "+format+"\n", append([]any{req.Verb}, a...)...)
		return code
	}
	if cliSandboxedEnv() {
		return fail(sandboxCLIUnavailable, "already inside an Observer sandbox; nested sandboxes are not offered")
	}
	backend, err := sandboxCLIBackend(req.Profile)
	if err != nil {
		return fail(sandboxCLIUsage, "%v", err)
	}
	cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: req.ConfigPath})
	if err != nil {
		return fail(sandboxCLIUnavailable, "load config: %v", err)
	}
	var orgBinds sandboxOrgBinds
	cfg.Terminal.Sandbox, orgBinds = cliEffectiveSandbox(ctx, cfg, gov.PinsInForce)
	if !sandboxModuleActive(componentSnapshotForConfig(cfg)) {
		return fail(sandboxCLIUnavailable, "the Sandboxes and VMs component is not active; turn it on in Settings > Components")
	}
	if !cfg.Terminal.Sandbox.Enabled {
		return fail(sandboxCLIUnavailable, "[terminal.sandbox].enabled is false; turn sandboxed terminals on in Settings > Terminal")
	}
	if spec, _ := integration.For(req.Tool); len(spec.Sandbox.StateRW) == 0 {
		return fail(sandboxCLIUnavailable, "%s is not sandbox-launchable yet", req.Tool)
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(sandboxCLIUnavailable, "resolve the observer binary: %v", err)
	}
	cwd, err := cliLaunchDir()
	if err != nil {
		return fail(sandboxCLIUnavailable, "resolve the working directory: %v", err)
	}
	if real, rerr := filepath.EvalSymlinks(cwd); rerr == nil {
		cwd = real
	}
	// The same observer directory the dashboard's runtime uses (P-017 (c)):
	// the directory of the configured DB, not a fixed ~/.observer.
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, cfg.Launch.Tools, sandboxObserverDirFor(cfg), exe, slog.New(slog.DiscardHandler))
	if err != nil {
		return fail(sandboxCLIUnavailable, "%v", err)
	}
	rt.applyDaemonConfig(cfg)
	rt.orgRWBinds, rt.orgSkipScan = orgBinds.rw, orgBinds.skipScan
	// The launcher's own binary-path flag (`--claude-path`) names the tool
	// the inner launcher runs, so the plan grants that binary's directory
	// read-only like a pinned [launch.tools] path (Windows 11 Pro run 4).
	if p := sandboxCLIToolPath(req.Verb, req.Rest, cwd); p != "" {
		rt.launchTools = withLaunchToolPath(rt.launchTools, req.Tool, p)
	}
	// A named profile is never substituted (I1); auto takes the selection
	// table's choice among the enabled backends (lane SBX-P3A).
	if req.Profile != "auto" {
		rt.forceBackend = backend
	}
	// "Routed" comes from a live daemon and proxy, not from config
	// (P-017 (b)).
	rt.requireLiveProxy(func(port int) bool { return proxyServing(ctx, port) })
	av := rt.ProbeSandbox(ctx)
	// The refusal names the backend its reason belongs to: a legacy answer
	// that gave way to the first enabled row (legacyWithinEnabled) carries
	// that row's id, not the auto name (P-111).
	if !av.Available {
		return fail(sandboxCLIUnavailable, "%s", sandboxCLIRefusal(backend, req.Profile != "auto", av))
	}
	backend = sandboxCLIProbedBackend(backend, av.Backend)
	if err := sandboxCLIRelayGate(rt.observerDir); err != nil {
		return fail(sandboxCLIUnavailable, "%v", err)
	}
	preq := termsvc.PrepareRequest{
		Tool: req.Tool, ProjectRoot: cwd, WorkspaceSource: string(workspace.SourceLive), ToolArgs: req.Rest,
		// Sign-in seeding (lane BOXSIGNIN): asked on a terminal only; with
		// no terminal and no remembered consent nothing is copied.
		SignInAsk: sandboxCLICanAsk(),
	}
	prepared, err := termsvc.ComposePrepare(ctx, rt, preq)
	var consent *termsvc.SignInConsentError
	if errors.As(err, &consent) {
		yes, remember, aerr := sandboxCLIAskSignIn(os.Stdin, stderr, consent)
		if aerr != nil {
			return fail(sandboxCLIUnavailable, "%v", aerr)
		}
		if remember {
			if rerr := sandboxRememberSignIn(req.ConfigPath, req.Tool); rerr != nil {
				fmt.Fprintf(stderr, "observer %s: your answer is not remembered: %v\n", req.Verb, rerr)
			}
		}
		preq.SignInSeed, preq.SignInAsk = &yes, false
		prepared, err = termsvc.ComposePrepare(ctx, rt, preq)
	}
	if err != nil {
		return fail(sandboxCLIUnavailable, "%v", err)
	}
	iso := prepared.Isolation
	// The run's terminal_run row (lane sbx-p2d): the same store seam a
	// dashboard launch records through, bound to the relay run, so what
	// lowers the run's capture (capture_degraded, the causes, transcript
	// drift) lands somewhere durable. A row that cannot be written leaves
	// the lowering in the daemon log only; it does not stop the launch.
	runID, rerr := recordSandboxCLIRun(ctx, cfg, req.Tool, cwd, iso)
	if rerr != nil {
		fmt.Fprintf(stderr, "observer %s: the run is not recorded (its capture health will reach the daemon log only): %v\n", req.Verb, rerr)
	} else {
		bindSandboxRelayRun(prepared.WrapArgv, runID)
	}
	fmt.Fprintf(stderr, "observer %s: sandboxed by %s (%s, network %s, capture %s%s)\n",
		req.Verb, backend, iso.Class, iso.EgressTier, sandboxselect.CaptureLabel(sandboxselect.CaptureResult{
			Level: vocab.CaptureLevel(iso.CaptureLevel), GatewayGuarded: iso.CaptureRule == "C6" && iso.CaptureLevel == string(vocab.CaptureFull),
		}), sandboxCLIPassEnvLabel(cfg.Terminal.Sandbox.PassEnv)+sandboxCLIOSC52Label(cfg.Terminal.Sandbox.AllowOSC52Clipboard))
	// The agent's own sandbox: the same rule the dashboard launch applies
	// (termsvc, lane SBX-P3D), from the same recorded state, so the CLI and
	// the dashboard give the same argv.
	switchArgs, serr := integration.NativeSwitchArgsForState(req.Tool, vocab.NativeSandboxState(iso.NativeSandboxState))
	if serr != nil {
		return fail(sandboxCLIUnavailable, "%v", serr)
	}
	argv := sandboxCLIInnerArgv(prepared.WrapArgv, exe, req.Verb, integration.AppendNativeArgs(req.Rest, switchArgs))
	//nolint:gosec // argv is the planner's bwrap prefix plus this binary and the operator's own arguments
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, stderr
	cmd.Dir = prepared.Dir
	// The box's environment is the allow-list; the launch names what it
	// adds (WINFIX2 R-167).
	cmd.Env = withSandboxSignInShared(withSandboxEnvAllow(sandboxTierChildEnv(os.Environ(), prepared.WrapArgv),
		sandboxEnvAllowNames(req.Tool, cfg.Terminal.Sandbox.PassEnv), cfg.Terminal.Sandbox.PassEnv), prepared.SignInShared)
	// The child shares the terminal's foreground group and gets Ctrl-C
	// itself; this process only waits for it. A closed terminal (SIGHUP)
	// or a SIGTERM is passed on to the child instead of ending this process
	// first, so the run's end is still recorded (audit finding F4 of lane
	// sbx-p2d; SIGKILL alone leaves the row to the daemon's shutdown sweep).
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, sandboxCLIForwardedSignals...)
	defer signal.Stop(sigs)
	// Under the org's require_full_capture floor the daemon ends a drifted
	// run; for this launch it leaves an end request this process acts on
	// (watchSandboxCLIEnd), the way it closes a dashboard terminal.
	endReason, stopWatch := watchSandboxCLIEnd(rt.observerDir, runID, sigs, stderr)
	defer stopWatch()
	// The first signal the launch gets (its console window closed, a stop
	// from outside) names the run's end; the run's row records the reason
	// with the exit code and the CLI prints its named line (Windows 11 Pro
	// run 4, N3).
	seen := recordSandboxCLISignals(sigs)
	defer seen.stop()
	finish := func(exit int) int {
		reason := sandboxCLIEndReason(runtime.GOOS, endReason(), seen.first(), exit)
		endSandboxCLIRun(ctx, cfg, runID, exit, reason)
		fmt.Fprintf(stderr, "observer %s: %s\n", req.Verb, termrun.EndLine(reason, &exit))
		return exit
	}
	// A driver whose box shows its output only through the handles its
	// helper inherits gets, on a console window, the launcher's own pseudo
	// console (the dashboard terminal's shape; RERUN2 D1).
	if sandboxCLIHostConsole(sandboxCLIConsoleFactsHere(sandboxDriverRegs[backend].cliConsoleHost)) {
		code, herr := runSandboxCLIOnHostConsole(argv, append(cmd.Env, sandboxConsoleHostedEnv+"=1"), cmd.Dir, seen.ch, sandboxStripsOSC52(true, cfg.Terminal.Sandbox.AllowOSC52Clipboard))
		if herr != nil {
			endSandboxCLIRun(ctx, cfg, runID, -1, endReason())
			return fail(sandboxCLIUnavailable, "run: %v", herr)
		}
		return finish(code)
	}
	code, runErr := superviseSandboxCLIChild(cmd, seen.ch, func(int) {})
	if runErr != nil {
		endSandboxCLIRun(ctx, cfg, runID, -1, endReason())
		return fail(sandboxCLIUnavailable, "run: %v", runErr)
	}
	return finish(code)
}

// sandboxCLIForwardedSignals are the signals a sandboxed CLI launch passes
// on to its child: the terminal closing and a polite stop.
var sandboxCLIForwardedSignals = []os.Signal{syscall.SIGHUP, syscall.SIGTERM}

// superviseSandboxCLIChild starts cmd, passes every signal that arrives on
// sigs on to it until it exits, and then records its end through end: its
// exit code (-1 when a signal ended it, or when it could not run). An error
// is returned only when the child could not be run or waited for.
func superviseSandboxCLIChild(cmd *exec.Cmd, sigs <-chan os.Signal, end func(exit int)) (int, error) {
	if err := cmd.Start(); err != nil {
		end(-1)
		return 0, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
		case err := <-done:
			code := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					end(-1)
					return 0, err
				}
				code = ee.ExitCode()
			}
			end(code)
			return code, nil
		}
	}
}

// recordSandboxCLIRun writes a sandboxed CLI launch's terminal_run row
// through the dashboard launch's recorder (termRunRecorder: the same row
// shape and the same sealed isolation evidence) and returns its id. The
// database is open only for the write.
func recordSandboxCLIRun(ctx context.Context, cfg config.Config, tool, dir string, iso termrun.Isolation) (string, error) {
	runID, err := termrun.NewRunID()
	if err != nil {
		return "", err
	}
	database, closeDB, err := openDBForConfig(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer closeDB()
	defer sealEvidenceOnHandle(cfg, database, nil)() // isolation.seal (evidence_seal.go); off: nothing
	run := termrun.Run{
		RunID: runID, Tool: tool, Kind: termrun.KindFresh,
		ProjectRootHash: termrun.HashProjectRoot(dir), LaunchedAt: time.Now().UTC(), Isolation: iso,
	}
	if err := (termRunRecorder{st: store.New(database)}).RecordRun(ctx, run); err != nil {
		return "", err
	}
	return runID, nil
}

// endSandboxCLIRun records the launch's exit on its row ("" records
// nothing) with reason (child_exit when ""; a reason the daemon stamped
// first is kept by the store, except the daemon_shutdown its graceful stop
// stamps on a run this process outlived: the CLI saw the real end, P-074);
// a write that fails leaves the row live until the daemon's shutdown sweep
// stamps it.
func endSandboxCLIRun(ctx context.Context, cfg config.Config, runID string, exit int, reason string) {
	if runID == "" {
		return
	}
	if reason == "" {
		reason = store.EndReasonChildExit
	}
	database, closeDB, err := openDBForConfig(ctx, cfg)
	if err != nil {
		return
	}
	defer closeDB()
	_ = store.New(database).EndTerminalRunOwned(ctx, runID, time.Now().UTC(), exit, reason)
	// The daemon logs one line for the end (logSandboxCLIEnded).
	writeSandboxCLIEnded(sandboxObserverDirFor(cfg), runID, reason, exit)
}

// sandboxObserverDirFor is the observer directory a runtime is built over:
// the directory of the configured DB, as the dashboard's buildTerminalStack
// does (attach_standalone.go and start.go).
func sandboxObserverDirFor(cfg config.Config) string {
	home, _ := os.UserHomeDir()
	p := cfg.Observer.DBPath
	// A config that never went through Load still holds the default's
	// "~/.observer/observer.db": expand it, so the relay's folders never
	// land under a literal "~" in the working directory (R-183's rule for
	// the database opener, found by the RB1 gate).
	if rest, ok := strings.CutPrefix(p, "~/"); ok && home != "" {
		p = filepath.Join(home, rest)
	} else if rest, ok := strings.CutPrefix(p, `~\`); ok && home != "" {
		p = filepath.Join(home, rest)
	}
	if p != "" && p != "~" {
		return filepath.Dir(p)
	}
	return filepath.Join(home, ".observer")
}

// errSandboxCLINoDaemon is the CLI's refusal when the daemon serves no
// capture relay.
var errSandboxCLINoDaemon = errors.New("the Observer daemon is not running; a sandboxed launch needs it (its hooks reach Observer through the daemon). Start it with `observer start`")

// sandboxCLIRelayGate refuses a sandboxed CLI launch the daemon serves no
// capture relay for: the box's hooks and launch checks reach Observer only
// through it (lane sbx-p2), so without it every checked action in the box
// would be blocked. A daemon that serves the relay (on Linux, or with a
// selected driver whose own OS this is: sandboxRelayOnOS) passes.
func sandboxCLIRelayGate(observerDir string) error {
	if !sandboxRelayReachable(observerDir) {
		return errSandboxCLINoDaemon
	}
	return nil
}

// sandboxCLIRefusal is the refusal headline for a probe that is not
// available. A row the launch named (--observer-sandbox <row>) leads with
// that row and its own verdict and reason, then the probe's whole answer
// (every row's reason); before, the headline named the probe's first
// unavailable row, so asking for mxc-appcontainer or wslc on Windows
// printed "hcs is not available here" (Windows 11 Pro live run, B1). Auto,
// or a named row the answer does not list, keeps naming the backend the
// reason belongs to (P-111).
func sandboxCLIRefusal(requested string, named bool, av dashapi.SandboxAvailability) string {
	if named && requested != "" && requested != av.Backend {
		for _, b := range av.Backends {
			if b.ID != requested {
				continue
			}
			head := requested + " is not available here"
			switch {
			case b.Available:
				head += ": it is available, but the launch could not use it"
			case b.Verdict != "" && b.Reason != "":
				head += " (" + b.Verdict + "): " + b.Reason
			case b.Verdict != "":
				head += " (" + b.Verdict + ")"
			}
			if av.Reason == "" {
				return head
			}
			return head + ". " + av.Reason
		}
	}
	return sandboxCLIProbedBackend(requested, av.Backend) + " is not available here: " + av.Reason
}

// sandboxCLIProbedBackend is the backend a probe answer belongs to: the
// answer's own backend when it names one, else the CLI's choice.
func sandboxCLIProbedBackend(chosen, probed string) string {
	if probed != "" {
		return probed
	}
	return chosen
}

// sandboxCLIBackend resolves a profile name to an offered backend. "auto"
// takes the selection table's choice at launch (the runtime picks a listed
// driver such as oci-runc first when one is available); until then it is
// named by this host's own rows (sandboxCLIAutoName), so a refusal on a Mac
// names seatbelt and apple-container, not bwrap (macOS live run 2026-10-22,
// D3).
func sandboxCLIBackend(profile string) (string, error) {
	if profile == "auto" {
		return sandboxCLIAutoName(sandboxHostKind()), nil
	}
	for _, id := range sandboxCLIProfiles() {
		if id == profile {
			return id, nil
		}
	}
	return "", fmt.Errorf("unknown or unavailable sandbox profile %q (offered: auto, %v)", profile, sandboxCLIProfiles())
}

// sandboxCLIAutoName names what "auto" may take on host, from the registry's
// Hosts column (no operating system is named here): the shipped row that
// runs there when there is one (bwrap on Linux and WSL2, as before), else
// every offered row that runs there ("apple-container or seatbelt" on a
// Mac, "mxc-process" on Windows), else a phrase saying none does.
func sandboxCLIAutoName(host sandboxbackend.HostKind) string {
	var here []string
	for _, row := range sandboxbackend.Offered() {
		if !row.RunsOn(host) || row.ExplicitOnly {
			continue
		}
		if row.Maturity == sandboxbackend.MaturityShipped {
			return row.ID
		}
		here = append(here, row.ID)
	}
	if len(here) == 0 {
		return "no sandbox backend for " + string(host)
	}
	return strings.Join(here, " or ")
}

// sandboxCLIProfiles are the backend ids a CLI launch may name: the offered
// registry rows (planned rows are not drivers yet).
func sandboxCLIProfiles() []string {
	var out []string
	for _, id := range sandboxbackend.IDs() {
		if row, ok := sandboxbackend.Get(id); ok && row.Offered() {
			out = append(out, id)
		}
	}
	return out
}

// sandboxCLIBinaryPathFlag is a launcher verb's binary-path flag, read from
// the command tree (a capability of the verb, never its name, like
// mxcProxyFlagFor): the flag whose name ends in "-path" and whose usage
// names the tool's binary ("claude-path" for claude). "" when it has none.
func sandboxCLIBinaryPathFlag(verb string) string {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{verb})
	if err != nil || cmd == nil || cmd == root {
		return ""
	}
	name := ""
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if name == "" && strings.HasSuffix(f.Name, "-path") && strings.Contains(strings.ToLower(f.Usage), "binary") {
			name = f.Name
		}
	})
	return name
}

// sandboxCLIFlagValue is the value of --name in args (`--name v` or
// `--name=v`), scanning only before a bare "--"; the last one wins, as
// for the launcher's own parse.
func sandboxCLIFlagValue(args []string, name string) string {
	v := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return v
		case a == "--"+name && i+1 < len(args):
			v = args[i+1]
			i++
		case strings.HasPrefix(a, "--"+name+"="):
			v = a[len("--"+name+"="):]
		}
	}
	return v
}

// sandboxCLIToolPath is the tool binary a sandboxed CLI launch's own
// binary-path flag names, absolute against the launch directory (the inner
// launcher runs there), or "".
func sandboxCLIToolPath(verb string, rest []string, cwd string) string {
	flag := sandboxCLIBinaryPathFlag(verb)
	if flag == "" {
		return ""
	}
	p := sandboxCLIFlagValue(rest, flag)
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// withLaunchToolPath is a copy of tools with tool's path set to p (the
// operator's config map is never written).
func withLaunchToolPath(tools map[string]config.LaunchToolConfig, tool, p string) map[string]config.LaunchToolConfig {
	out := make(map[string]config.LaunchToolConfig, len(tools)+1)
	for k, v := range tools {
		out[k] = v
	}
	tc := out[tool]
	tc.Path = p
	out[tool] = tc
	return out
}

// sandboxCLIInnerArgv is the child a sandboxed CLI launch runs: the
// backend's wrap prefix, then this binary, the launcher verb and every one
// of the user's own arguments in order ("--" and what follows it included;
// parseSandboxCLI removes only the --observer-sandbox flag itself).
func sandboxCLIInnerArgv(wrap []string, exe, verb string, rest []string) []string {
	return append(append(append([]string(nil), wrap...), exe, verb), rest...)
}

// sandboxLauncherHelp is what every launcher's --help adds about
// --observer-sandbox, which sandboxCLIDispatch takes before Cobra runs and
// so is no launcher's registered flag (Windows 11 Pro live run 2026-10-22:
// no launcher's help named it). launcher_argv.go prints it, once for all.
func sandboxLauncherHelp() string {
	return "\nSandboxed launch (every launcher):\n" +
		"      --observer-sandbox <profile>   run this launch inside an Observer sandbox: auto, or one of\n" +
		"                                     " + strings.Join(sandboxCLIProfiles(), ", ") + ".\n" +
		"                                     It needs the daemon running, [terminal.sandbox] enabled and the\n" +
		"                                     backend in [terminal.sandbox].backends; see `observer help sandbox`.\n"
}
