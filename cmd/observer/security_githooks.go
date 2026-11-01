//go:build !sbo_omit_security

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secgithooks"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_githooks.go is the cmd side of the opt-in local git hooks
// (component security.githooks; security pillar plan section 5.8, ruling
// Q12, ledger SECP-14; lane sec-c3): `observer security githooks install |
// uninstall | status` (per-repository consent from the CLI, the dashboard
// has the same actions), and `observer security precommit | prepush`, the
// advisory checks the hooks run. Off in every distro. The checks fail
// open: only a blocking finding exits secgithooks.RefuseExit (any other
// status, observer's generic error 1 included, lets the hook go on), and
// `--no-verify` still skips them for a human.

// securityGithooksComponent is the catalog id.
const securityGithooksComponent = "security.githooks"

// githookQuietExit ends the command with code and no cobra banner: the
// line already printed is the whole message.
func githookQuietExit(cmd *cobra.Command, code int) error {
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	if r := cmd.Root(); r != nil {
		r.SilenceErrors = true
	}
	return exitErr(code)
}

// githooksSelected is the component's one switch: securitySelected
// (security_optin.go), which keeps it opt-in, so an install with no
// [components] block never reads it as on (plans decision log P-025).
func githooksSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, securityGithooksComponent)
}

// githooksActive reports whether the component is selected for
// configPath, writing the refusal line when it is not.
func githooksActive(cmd *cobra.Command, configPath string) bool {
	snap := componentSnapshotFor(configPath)
	if githooksSelected(snap) {
		return true
	}
	if !snap.Configured {
		fmt.Fprintln(cmd.ErrOrStderr(), "components: security.githooks is off by default; turn it on with `observer components add security.githooks`")
		return false
	}
	fmt.Fprintln(cmd.ErrOrStderr(), snap.RefusalLine(securityGithooksComponent))
	return false
}

func newSecurityGithooksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "githooks",
		Short: "Opt-in local git hooks that check a commit or push for secrets (per repository)",
		Long: "Writes a marked block into this repository's pre-commit and pre-push hooks that runs\n" +
			"`observer security precommit` / `prepush` and then the rest of the hook. Advisory for a\n" +
			"human (git commit --no-verify skips it) and fail-open. Removal is byte-exact. Component\n" +
			"security.githooks, off by default; installing is the developer's consent for this\n" +
			"repository only.",
	}
	var configPath, dir string
	var asJSON bool
	target := func(cmd *cobra.Command) (secsvc.GithookTarget, error) {
		root, err := securityProjectRoot(dir)
		if err != nil {
			return secsvc.GithookTarget{}, err
		}
		return secsvc.ResolveGithookTarget(cmd.Context(), gitview.RunReadOnlyTimeout, root)
	}
	install := &cobra.Command{
		Use:   "install",
		Short: "Install the hooks in this repository",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !githooksActive(cmd, configPath) {
				return githookQuietExit(cmd, 3)
			}
			t, err := target(cmd)
			if err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if err := secsvc.InstallGithooks(t, exe); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed in %s (pre-commit, pre-push). Remove with: observer security githooks uninstall\n", t.HooksDir)
			return nil
		},
	}
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the hooks from this repository (works while the component is off)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := target(cmd)
			if err != nil {
				return err
			}
			n, err := secsvc.UninstallGithooks(t)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed Observer's block from %d hook(s) in %s.\n", n, t.HooksDir)
			return nil
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether the hooks are installed in this repository",
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := target(cmd)
			if err != nil {
				return err
			}
			st, err := secsvc.GithooksStatus(t)
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), map[string]any{"hooks_dir": t.HooksDir, "refusal": t.Refusal, "hooks": st})
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Hooks directory: %s\n", t.HooksDir)
			if t.Refusal != "" {
				fmt.Fprintln(w, "Not installable:", t.Refusal)
			}
			for _, s := range st {
				state := "not installed"
				switch {
				case s.Installed:
					state = "installed"
				case s.Outdated:
					state = "outdated (an earlier release's block; run `observer security githooks install` to update it)"
				}
				if s.Foreign {
					state += ", chained with your own hook"
				}
				fmt.Fprintf(w, "  %-10s %s\n", s.Hook, state)
			}
			return nil
		},
	}
	for _, c := range []*cobra.Command{install, uninstall, status} {
		c.Flags().StringVar(&configPath, "config", "", "path to config.toml")
		c.Flags().StringVar(&dir, "project", "", "repository directory (default: the working directory)")
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.AddCommand(install, uninstall, status)
	return cmd
}

// githookBudget is the advisory checks' budget (section 6.4: 2 s).
const githookBudget = secquickscan.IndividualBudget

// githookEngine is the advisory checks' scanner: the native secret rows
// over the read-only git envelope; nothing is stored.
func githookEngine() *secquickscan.Engine {
	e := newSecurityQuickScanEngine(nil)
	e.Budget = githookBudget
	return e
}

// githookVerdictLine is the one line the check prints, and whether the
// commit or push is refused.
func githookVerdictLine(what string, r secquickscan.Result) (string, bool) {
	switch r.Verdict {
	case secquickscan.VerdictBlocking:
		f := r.Findings[0]
		line := fmt.Sprintf("observer: %s refused: a %s secret in %s:%d", what, secdetect.SanitizeLocation(f.Type), secdetect.SanitizeLocation(f.Path), f.Line)
		if len(r.Findings) > 1 {
			line += fmt.Sprintf(" and %d more", len(r.Findings)-1)
		}
		return line + ". Remove it and retry; to skip this check once, use --no-verify.", true
	case secquickscan.VerdictUnknown:
		return fmt.Sprintf("observer: %s check did not finish (%s); not blocking.", what, r.Reason), false
	default:
		return fmt.Sprintf("observer: %s checked %d file(s): no secret found.", what, r.Files), false
	}
}

func newSecurityPrecommitCmd() *cobra.Command {
	var configPath string
	return &cobra.Command{
		Use:    "precommit",
		Short:  "The pre-commit hook's advisory secret check of the staged change",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !githooksSelected(componentSnapshotFor(configPath)) {
				fmt.Fprintln(cmd.ErrOrStderr(), "observer: security.githooks is not active; skipping (run `observer security githooks uninstall` to remove the hook)")
				return nil
			}
			// The staged change is the checkout's own index: in a linked
			// worktree that is the worktree, not the main checkout (lane
			// sec-gate4 audit finding 7, P-041).
			root, err := securityCheckoutRoot("")
			if err != nil {
				return nil // fail open
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), githookBudget+time.Second)
			defer cancel()
			line, refuse := githookVerdictLine("commit", githookEngine().Scan(ctx, secquickscan.Request{Root: root}))
			fmt.Fprintln(cmd.ErrOrStderr(), line)
			if refuse {
				return githookQuietExit(cmd, secgithooks.RefuseExit)
			}
			return nil
		},
	}
}

// zeroSHA reports git's all-zero id (a ref being created or deleted).
func zeroSHA(s string) bool { return strings.Trim(s, "0") == "" }

// prepushRanges reads git's pre-push stdin ("<local ref> <local sha>
// <remote ref> <remote sha>" per line) into scan forms: the commits from
// the remote's sha to the local one, or the local tip alone for a new
// branch; a deletion pushes nothing.
func prepushRanges(r io.Reader) []secquickscan.Form {
	var out []secquickscan.Form
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 || zeroSHA(f[1]) {
			continue
		}
		form := secquickscan.Form{To: f[1]}
		if !zeroSHA(f[3]) {
			form.From = f[3]
		}
		out = append(out, form)
	}
	return out
}

// securityCheckoutRoot is securityProjectRoot for a caller that reads the
// checkout's own files or index: inside a linked worktree it is the
// worktree's top level, not the main checkout's.
func securityCheckoutRoot(dir string) (string, error) {
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	root, ok := git.FindCheckoutRoot(dir)
	if !ok {
		return "", fmt.Errorf("%s is not inside a git repository", dir)
	}
	return root, nil
}

// githookHeld reads the held commits from the project's signed posture
// (lane sec-gate4 milestone 1d), and whether the list was capped (audit
// finding 8); none when the posture cannot be used: the hook fails open.
func githookHeld(configPath, root string) ([]secgithooks.HeldCommit, bool) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return nil, false
	}
	gp := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	r := secposture.Load(secposture.LayoutFor(resolved), root, secposture.ModuleSignalFrom(gp.State, gp.Posture), time.Now(), secposture.Versions{})
	held, ok := secposture.HeldOf(r)
	if !ok {
		return nil, false
	}
	out := make([]secgithooks.HeldCommit, 0, len(held))
	for _, h := range held {
		out = append(out, secgithooks.HeldCommit{Commit: h.Commit, Remotes: h.Remotes})
	}
	return out, secposture.HeldOverflowOf(r)
}

// githookSends reports whether the pushed ranges send commit: an ancestor
// of a pushed tip and not of the remote's old tip. A range git cannot
// answer does not stop the walk (audit finding 8): a later range that
// sends it still decides; only when no range sends it and one could not be
// answered is the answer unknown.
func githookSends(ctx context.Context, root string, forms []secquickscan.Form) secgithooks.Sends {
	isAncestor := func(a, b string) (bool, bool) {
		_, _, err := gitview.RunReadOnlyNoLazyFetch(ctx, root, 4096, githookBudget, "merge-base", "--is-ancestor", a, b)
		if err == nil {
			return true, true
		}
		if f, ok := gitview.InspectError(err); ok && !f.TimedOut && f.ExitCode == 1 {
			return false, true
		}
		return false, false
	}
	return func(commit string) (bool, bool) {
		unknown := false
		for _, form := range forms {
			in, known := isAncestor(commit, form.To)
			if !known {
				unknown = true
				continue
			}
			if !in {
				continue
			}
			if form.From != "" {
				already, known := isAncestor(commit, form.From)
				if !known {
					unknown = true
					continue
				}
				if already {
					continue
				}
			}
			return true, true
		}
		return false, !unknown
	}
}

// githookPrepushCheck is the pre-push check: the pushed ranges scanned
// for secrets, then the history-only hold. A secret removed from the files
// is still in its commit: a push that sends a held commit to a remote that
// does not have it yet is refused like the agent's push (S-792); pre-commit
// never is (lane sec-gate4 milestone 1d). args are the hook's arguments
// (the remote's name or URL, then its URL).
func githookPrepushCheck(ctx context.Context, configPath, root string, args []string, stdin io.Reader) (string, bool) {
	e := githookEngine()
	forms := prepushRanges(stdin)
	for _, form := range forms {
		if line, refuse := githookVerdictLine("push", e.Scan(ctx, secquickscan.Request{Root: root, Form: form})); refuse {
			return line, true
		}
	}
	if len(forms) == 0 {
		return "", false
	}
	remote := ""
	if len(args) > 0 && policy.IsRemoteName(args[0]) {
		remote = args[0]
	}
	held, overflow := githookHeld(configPath, root)
	if commit, refuse := secgithooks.PrepushHold(remote, held, overflow, githookSends(ctx, root, forms)); refuse {
		return secgithooks.HeldRefusalLine(commit, remote), true
	}
	return "", false
}

func newSecurityPrepushCmd() *cobra.Command {
	var configPath string
	return &cobra.Command{
		Use:    "prepush [remote] [url]",
		Short:  "The pre-push hook's advisory secret check of the commits being pushed",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !githooksSelected(componentSnapshotFor(configPath)) {
				fmt.Fprintln(cmd.ErrOrStderr(), "observer: security.githooks is not active; skipping (run `observer security githooks uninstall` to remove the hook)")
				return nil
			}
			root, err := securityProjectRoot("")
			if err != nil {
				return nil // fail open
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), githookBudget+time.Second)
			defer cancel()
			if line, refuse := githookPrepushCheck(ctx, configPath, root, args, cmd.InOrStdin()); refuse {
				fmt.Fprintln(cmd.ErrOrStderr(), line)
				return githookQuietExit(cmd, secgithooks.RefuseExit)
			}
			return nil
		},
	}
}

// securityGithookSubcommands are the git hook verbs.
func securityGithookSubcommands() []*cobra.Command {
	return []*cobra.Command{newSecurityGithooksCmd(), newSecurityPrecommitCmd(), newSecurityPrepushCmd()}
}
