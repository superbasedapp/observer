// ssh.go — `observer ssh <profile>` CLI parity with the dashboard's SSH
// remote-system instance switcher
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §11 Phase C, items
// C1/C2).
//
// This command is config-only: it never opens the observer DB and never
// requires `observer start` to be running. It reads [terminal.ssh] straight
// off disk, builds the exact argv sshprofile.Argv composes for the
// dashboard's own Connect action, and execs it attached to this process's
// stdio — an ordinary interactive SSH login, not the daemon-owned PTY the
// dashboard drives for its port-forwarded instance switcher.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sshforward"
	"github.com/marmutapp/superbased-observer/internal/sshprofile"
)

// newSSHCmd implements `observer ssh <profile>` — connect to a configured
// [[terminal.ssh.profiles]] remote system from the CLI, with --print and
// --test diagnostic modes that never open a connection.
func newSSHCmd() *cobra.Command {
	var (
		configPath string
		printOnly  bool
		testOnly   bool
	)
	cmd := &cobra.Command{
		Use:   "ssh <profile>",
		Short: "Connect to a configured [[terminal.ssh.profiles]] remote system",
		Long: "Builds the exact ssh argv the dashboard's SSH instance switcher uses for\n" +
			"the named profile and runs it as an interactive login attached to this\n" +
			"terminal (docs/ssh-terminals.md). Config-only — does not require\n" +
			"`observer start` to be running.\n\n" +
			"--print shows the composed argv (shell-quoted) without connecting.\n" +
			"--test runs the same bounded, non-interactive connectivity probe the\n" +
			"dashboard's \"Test\" affordance runs (known_hosts + auth) and prints a\n" +
			"pass/fail report instead of connecting.",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSH(cmd.Context(), args[0], sshCmdOptions{
				configPath: configPath,
				print:      printOnly,
				test:       testOnly,
				stdout:     cmd.OutOrStdout(),
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&printOnly, "print", false, "Print the composed ssh argv (shell-quoted) and exit without connecting")
	cmd.Flags().BoolVar(&testOnly, "test", false, "Run the bounded connectivity probe (known_hosts + auth) and exit without connecting")
	return cmd
}

type sshCmdOptions struct {
	configPath string
	print      bool
	test       bool
	stdout     io.Writer
	stderr     io.Writer
}

// runSSH resolves the named profile from [terminal.ssh.profiles] and either
// prints its argv (--print), runs the diagnostic probe (--test), or execs an
// interactive login attached to this process's stdio (the default) — the
// SAME argv sshprofile.Argv composes for the dashboard's own Connect action.
//
// Every failure path here self-prints to opts.stderr: the command sets
// SilenceErrors on its cobra.Command, which stops main() from printing the
// returned error itself (see main.go), so a caller that only checked the
// exit code would otherwise see nothing.
func runSSH(_ context.Context, name string, opts sshCmdOptions) error {
	if opts.print && opts.test {
		fmt.Fprintln(opts.stderr, "observer ssh: --print and --test are mutually exclusive")
		return exitErr(1)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: opts.configPath})
	if err != nil {
		fmt.Fprintf(opts.stderr, "observer ssh: load config: %v\n", err)
		return err
	}

	// Combined kill switch, matching the established
	// cfg.Terminal.Enabled && cfg.Terminal.SSH.Enabled pattern used by both
	// attach_standalone.go and launch_dashboard.go's terminalLaunchPolicy.
	if !cfg.Terminal.Enabled || !cfg.Terminal.SSH.Enabled {
		fmt.Fprintln(opts.stderr,
			"observer ssh: remote-system terminals are disabled — set [terminal.ssh].enabled = true\n"+
				"(and [terminal].enabled = true) in your config.toml. See docs/ssh-terminals.md.")
		return exitErr(1)
	}

	profiles := config.SSHProfiles(cfg.Terminal.SSH)
	if len(profiles) == 0 {
		fmt.Fprintln(opts.stderr,
			"observer ssh: no [[terminal.ssh.profiles]] are configured. Add at least one\n"+
				"profile to config.toml — see docs/ssh-terminals.md.")
		return exitErr(1)
	}

	profile, ok := sshprofile.Find(profiles, name)
	if !ok {
		fmt.Fprintf(opts.stderr, "observer ssh: unknown profile %q. Configured profiles: %s\n",
			name, strings.Join(sshProfileNames(profiles), ", "))
		return exitErr(1)
	}

	sshOpts := config.SSHOptions(cfg.Terminal.SSH)

	if opts.test {
		return runSSHTest(profile, sshOpts, opts)
	}

	argv, err := sshprofile.Argv(profile, sshOpts)
	if err != nil {
		fmt.Fprintf(opts.stderr, "observer ssh: %v\n", err)
		return exitErr(1)
	}

	if opts.print {
		fmt.Fprintln(opts.stdout, shellJoinArgv(argv))
		return nil
	}

	//nolint:gosec // G204: argv is composed by sshprofile.Argv from an
	// operator-authored [[terminal.ssh.profiles]] entry, never from request
	// input — the same argv the dashboard's own Connect action uses.
	child := exec.Command(argv[0], argv[1:]...)
	child.Stdout = opts.stdout
	child.Stderr = opts.stderr
	child.Stdin = os.Stdin
	runErr := child.Run()
	exitCode := exitCodeFrom(runErr)
	if exitCode != 0 {
		return exitErr(exitCode)
	}
	return nil
}

// runSSHTest runs the bounded, non-interactive connectivity probe (C2) via a
// local sshforward.Manager scoped to just the resolved profile — the same
// core sshforward.Manager.Test the dashboard's "Test" affordance calls
// through launchManagerAdapter.TestInstance (internal/intelligence/dashboard
// POST /api/instances/{name}/test). It never touches the observer DB or
// daemon state.
func runSSHTest(profile sshprofile.Profile, sshOpts sshprofile.Options, opts sshCmdOptions) error {
	mgr := sshforward.New(sshforward.Options{
		Enabled:    true,
		Profiles:   []sshprofile.Profile{profile},
		SSHOptions: sshOpts,
	})
	result, err := mgr.Test(profile.Name)
	if err != nil {
		fmt.Fprintf(opts.stderr, "observer ssh: test failed to run: %v\n", err)
		return exitErr(1)
	}

	fmt.Fprintf(opts.stdout, "target: %s\n", profile.Target())
	switch {
	case !result.KnownHostsChecked:
		fmt.Fprintln(opts.stdout, "known_hosts: not checked (could not resolve the host alias via `ssh -G`)")
	case result.KnownHostsOK:
		fmt.Fprintln(opts.stdout, "known_hosts: known")
	default:
		fmt.Fprintf(opts.stdout, "known_hosts: NOT known yet — the first `observer ssh %s` login will prompt to accept the host key\n", profile.Name)
	}

	if result.AuthOK {
		fmt.Fprintf(opts.stdout, "auth: ok (%s)\n", result.Latency.Round(time.Millisecond))
		return nil
	}
	fmt.Fprintf(opts.stdout, "auth: FAILED (%s)\n", result.Latency.Round(time.Millisecond))
	if result.Stderr != "" {
		fmt.Fprintf(opts.stdout, "  %s\n", result.Stderr)
	}
	return exitErr(1)
}

// sshProfileNames returns the sorted list of configured profile names, used
// to build an honest "did you mean one of these" message for an unknown
// profile.
func sshProfileNames(profiles []sshprofile.Profile) []string {
	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

// shellJoinArgv renders argv as one POSIX shell command for --print's
// output, single-quoting any element that needs it. It is a deliberate local
// duplicate of internal/launch/launch.go's unexported shellJoin/shellQuote
// (same character set, same escaping algorithm) rather than an import — that
// helper is private to internal/launch and this is the only other call site
// that needs it.
func shellJoinArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuoteArg(a)
	}
	return strings.Join(parts, " ")
}

func shellQuoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"\\$`&|;<>(){}*?#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
