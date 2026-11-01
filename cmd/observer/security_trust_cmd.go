//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/sectrustitem"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_trust_cmd.go is `observer security trust` (security pillar plan
// section 5.1 items 2 and 5): run the repository trust check where you are
// and accept the exact commands a repository makes an agent run. An accept
// is Observer's own record (sec_config_baseline: who and when); Observer
// never marks anything trusted inside the vendor's tool (PR13). An agent
// running `accept` is refused by guard rule R-165.
//
// Every verb refuses unless the security.trust component is active under
// the optional-module predicate (fail invisible).

// newSecurityTrustCmd builds `observer security trust`.
func newSecurityTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Repository trust: what a repository makes an agent run, and your accepts",
		Long: "The repository trust check reads a fixed table of agent config files at\n" +
			"the repository root and the directory you start in (no repository walk)\n" +
			"and says clean, flagged or untrusted. A command the repository makes an\n" +
			"agent run (a project hook, an MCP server, a plugin, a folder-open task)\n" +
			"is untrusted until you accept its exact content; any change asks again.",
	}
	cmd.AddCommand(newSecurityTrustCheckCmd(), newSecurityTrustAcceptCmd(), newSecurityTrustListCmd(), newSecurityTrustRevokeCmd())
	return cmd
}

// trustCmdState is what a trust verb works on: the store and the launch
// target of --dir.
type trustCmdState struct {
	st       *store.Store
	target   repoTrustTarget
	rootHash string
	close    func()
	// paths and devcontainer are the conditional rows the launch gate reads
	// (repoTrustConditional; N2's initializeCommand row on every install),
	// so the check lists, and accept accepts, what a launch decides on.
	paths        []agentconfig.TrustPath
	devcontainer sectrust.DevcontainerParser
}

// openTrustCmd checks the component, loads the store and resolves dir.
func openTrustCmd(ctx context.Context, configPath, dir string) (trustCmdState, error) {
	if !componentSnapshotFor(configPath).ModuleActive(repoTrustComponent) {
		return trustCmdState{}, fmt.Errorf("the %s component is not active (observer components status)", repoTrustComponent)
	}
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return trustCmdState{}, fmt.Errorf("working directory: %w", err)
		}
		dir = wd
	}
	target, err := resolveRepoTrustTarget(dir)
	if err != nil {
		return trustCmdState{}, err
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return trustCmdState{}, err
	}
	paths, parse := repoTrustConditional(cfg, componentSnapshotForConfig(cfg))
	return trustCmdState{
		st: store.New(database), target: target, rootHash: guard.HashProjectRoot(target.root), close: cleanup,
		paths: paths, devcontainer: parse,
	}, nil
}

// runTrustCheck runs the check with the stored accepts and records what it
// raised.
func (s trustCmdState) runTrustCheck(ctx context.Context) (sectrust.Result, error) {
	accepted, err := s.st.AcceptedSecTrustDigests(ctx, s.rootHash)
	if err != nil {
		return sectrust.Result{}, err
	}
	// Observer's own entries in the home directory are left out the way the
	// launch row leaves them out (repoTrustOwnAt: only when the checked root
	// is the home directory), so the check reports what a launch there
	// decides on and records nothing Observer registered.
	own := repoTrustOwnAt(s.target.root)
	res, err := sectrust.Check(ctx, sectrust.OSFS(s.target.root), sectrust.Request{
		LaunchRel:    s.target.launchRel,
		Accepted:     func(d string) bool { return accepted[d] },
		Own:          own,
		Paths:        s.paths,
		Devcontainer: s.devcontainer,
	})
	if err != nil {
		return sectrust.Result{}, err
	}
	if own != nil {
		res = res.WithoutObserver()
	}
	if items := secTrustItems(res); len(items) > 0 {
		if err := s.st.RecordSecTrustItems(ctx, s.rootHash, items, time.Now()); err != nil {
			return sectrust.Result{}, err
		}
	}
	return res, nil
}

func newSecurityTrustCheckCmd() *cobra.Command {
	var configPath, dir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run the repository trust check where an agent would start",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openTrustCmd(cmd.Context(), configPath, dir)
			if err != nil {
				return err
			}
			defer s.close()
			res, err := s.runTrustCheck(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Root string `json:"root"`
					sectrust.Result
				}{s.target.root, res})
			}
			printTrustResult(cmd.OutOrStdout(), s.target, res)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&dir, "dir", "", "the directory an agent would start in (default: the working directory)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}

// printTrustResult prints a result for a person.
func printTrustResult(w io.Writer, target repoTrustTarget, res sectrust.Result) {
	fmt.Fprintf(w, "repository %s: %s\n", target.root, res.Verdict)
	if target.launchRel != "" {
		fmt.Fprintf(w, "  also read: every directory down to %s\n", target.launchRel)
	}
	for _, r := range res.Reasons {
		line := fmt.Sprintf("  %-9s %-26s %s", r.Level, r.Code, r.File)
		if r.Key != "" {
			line += " " + r.Key
		}
		fmt.Fprintln(w, line)
		if r.Excerpt != "" {
			fmt.Fprintf(w, "            %s\n", r.Excerpt)
		}
		if len(r.Files) > 0 {
			fmt.Fprintf(w, "            runs %s (their bytes are part of the digest)\n", strings.Join(r.Files, ", "))
		}
		if len(r.Indicators) > 0 {
			fmt.Fprintf(w, "            it %s\n", strings.Join(r.Indicators, ", "))
		}
		switch {
		case r.Accepted:
			fmt.Fprintf(w, "            accepted (%s)\n", r.Digest)
		case r.Digest != "":
			fmt.Fprintf(w, "            not accepted; accept with: observer security trust accept %s\n", r.Digest)
		}
	}
	if res.Truncated {
		fmt.Fprintln(w, "  note: a bound cut the read short; some entries were not read, and accept --all refuses until they are")
	}
}

// trustAcceptor names who accepted: the surface and the local account.
func trustAcceptor(surface string) string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return surface + ":" + name
}

func newSecurityTrustAcceptCmd() *cobra.Command {
	var configPath, dir string
	var all, yes bool
	cmd := &cobra.Command{
		Use:   "accept [<digest>...]",
		Short: "Accept the exact commands a repository makes an agent run",
		Long: "Accepts each named digest (from `observer security trust check`), or with\n" +
			"--all every command the check reports as not accepted. An accepted\n" +
			"command is reported as flagged instead of untrusted; any change to it\n" +
			"makes a new digest and asks again. The accept records who and when.\n\n" +
			"--all runs the check, prints every item it would accept, and accepts\n" +
			"exactly those once you confirm at the terminal (or pass --yes). It\n" +
			"refuses while the check could not read everything (a truncated result).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return errors.New("name the digests to accept, or pass --all (not both)")
			}
			s, err := openTrustCmd(cmd.Context(), configPath, dir)
			if err != nil {
				return err
			}
			defer s.close()
			res, err := s.runTrustCheck(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			var confirm func(string) bool
			if all && !yes {
				confirm = trustAcceptConfirm(cmd.ErrOrStderr())
				if confirm == nil {
					return errors.New("accept --all needs a terminal to confirm, or --yes")
				}
			}
			items, err := trustAcceptSelection(res, args, all)
			if err != nil {
				return err
			}
			if len(items) == 0 {
				fmt.Fprintln(w, "nothing to accept")
				return nil
			}
			if all {
				printTrustAcceptItems(w, s.target, res, items)
				if confirm != nil && !confirm(fmt.Sprintf("Accept these %d item(s)?", len(items))) {
					return errors.New("nothing accepted")
				}
			}
			n, err := s.st.AcceptSecTrustItems(cmd.Context(), s.rootHash, items, trustAcceptor("cli"), time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "accepted %d command(s) in %s\n", n, s.target.root)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&dir, "dir", "", "the directory an agent would start in (default: the working directory)")
	cmd.Flags().BoolVar(&all, "all", false, "accept every command the check reports as not accepted (prints each one and asks)")
	cmd.Flags().BoolVar(&yes, "yes", false, "with --all, accept without asking at the terminal")
	return cmd
}

// trustAcceptConfirm is the confirmation `accept --all` asks at the
// terminal (nil when stdin and stderr are not terminals); a variable so a
// test can answer it.
var trustAcceptConfirm = func(stderr io.Writer) func(string) bool { return terminalAsk(os.Stdin, stderr) }

// trustAcceptSelection picks the items an accept stores from the check it
// just ran (sectrust.Result.Select): the named digests, each one the check
// reports, or with all every digest not yet accepted, refused over a
// truncated result whose unread entries nobody saw (plans decision log
// P-004).
func trustAcceptSelection(res sectrust.Result, digests []string, all bool) ([]store.SecTrustItem, error) {
	picked, err := res.Select(digests, all)
	if err != nil {
		if errors.Is(err, sectrust.ErrTruncatedAccept) {
			return nil, err
		}
		return nil, fmt.Errorf("%w (run observer security trust check)", err)
	}
	return sectrustitem.FromReasons(picked), nil
}

// printTrustAcceptItems prints every item an accept --all would store,
// with what the check read for it.
func printTrustAcceptItems(w io.Writer, target repoTrustTarget, res sectrust.Result, items []store.SecTrustItem) {
	fmt.Fprintf(w, "repository %s: %d item(s) to accept\n", target.root, len(items))
	for _, it := range items {
		i := slices.IndexFunc(res.Reasons, func(r sectrust.Reason) bool { return r.Digest == it.ContentHash })
		fmt.Fprintf(w, "  %-26s %s %s\n", it.ReasonCode, it.RelPath, it.ItemKey)
		if i >= 0 {
			r := res.Reasons[i]
			if r.Excerpt != "" {
				fmt.Fprintf(w, "            %s\n", r.Excerpt)
			}
			if len(r.Files) > 0 {
				fmt.Fprintf(w, "            runs %s\n", strings.Join(r.Files, ", "))
			}
		}
		fmt.Fprintf(w, "            %s\n", it.ContentHash)
	}
}

func newSecurityTrustListCmd() *cobra.Command {
	var configPath, dir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the commands recorded for this repository and their accepts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openTrustCmd(cmd.Context(), configPath, dir)
			if err != nil {
				return err
			}
			defer s.close()
			recs, err := s.st.ListSecTrustItems(cmd.Context(), s.rootHash)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(recs) == 0 {
				fmt.Fprintf(w, "nothing recorded for %s\n", s.target.root)
				return nil
			}
			for _, r := range recs {
				state := "not accepted"
				if r.Accepted() {
					state = fmt.Sprintf("accepted by %s at %s", r.AcceptedBy, r.AcceptedAt.Format(time.RFC3339))
				}
				fmt.Fprintf(w, "%-26s %s %s\n  %s\n  %s\n", r.ReasonCode, r.RelPath, r.ItemKey, r.ContentHash, state)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&dir, "dir", "", "the repository directory (default: the working directory)")
	return cmd
}

func newSecurityTrustRevokeCmd() *cobra.Command {
	var configPath, dir string
	cmd := &cobra.Command{
		Use:   "revoke <digest>",
		Short: "Withdraw the accept of one command",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openTrustCmd(cmd.Context(), configPath, dir)
			if err != nil {
				return err
			}
			defer s.close()
			ok, err := s.st.RevokeSecTrustAccept(cmd.Context(), s.rootHash, args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no accept of %s in %s", args[0], s.target.root)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "accept withdrawn: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&dir, "dir", "", "the repository directory (default: the working directory)")
	return cmd
}

// securityTrustSubcommands are the trust verbs under `observer security`.
func securityTrustSubcommands() []*cobra.Command {
	return []*cobra.Command{newSecurityTrustCmd()}
}
