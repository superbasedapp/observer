//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_exceptions.go is the cmd wiring of the security pillar's local
// finding exceptions and baselines (security pillar plan sections 4.5.2
// and 6.3, lane sec-c3): the `observer security exception` and
// `observer security baseline` verbs, the security.exceptions sweep loop
// (a moduleGates row of the module root) and the baseline driver set.
// Every action here is also on the Code security page (D-003). Granting
// an exception or approving a baseline lifts a finding, so R-165 denies
// an agent that runs these verbs under enforce.

// securityExceptionEvery is how often the sweep ends expired exceptions
// and those whose file changed.
const securityExceptionEvery = time.Minute

// securityExceptionDeps are the exceptions' injected I/O over st.
func securityExceptionDeps(st *store.Store) secsvc.ExceptionDeps {
	return secsvc.ExceptionDeps{Store: st, HashFile: secsvc.HashProjectFile, RootFor: secsvc.RootsResolver(st.ProjectRoots)}
}

// securityBaselineDriverSet is the driver set the lazy baseline rescan
// reads a baseline commit's tree with: the native workflow rules while
// security.code is active. Secrets are never pre_existing, so the secret
// rows need no baseline driver.
func securityBaselineDriverSet(codeActive bool) []secscan.Driver {
	if !codeActive {
		return nil
	}
	return []secscan.Driver{secsvc.WorkflowBaselineDriver{Git: gitview.RunReadOnlyTimeout}}
}

// startSecurityExceptions starts the security.exceptions sweep on ng: it
// ends exceptions past their expiry or whose file changed, reopening the
// finding, and prunes ended ones past the retention.
func startSecurityExceptions(ctx context.Context, ng *gatedGroup, configPath string) {
	startSecurityNotify(ctx, ng, configPath)
	ng.Go("security.exceptions", func() error {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			return nil
		}
		defer cleanup()
		var identify func(typ, value string) string
		if resolved, err := config.ResolveGlobalPath(configPath); err == nil {
			identify = securityIdentify(resolved)
		}
		runSecurityExceptionSweep(ctx, store.New(database), cfg.Security.Retention.Days, newLogger(cfg.Observer.LogLevel), identify)
		return nil
	})
}

// securitySecretPresence is the sweep's presence check (lane sec-gate2,
// decision log P-025): before an ended exception reopens a secret finding,
// every file the finding is sighted in is rescanned with the node-keyed
// detector. The finding is present when one file still holds its secret;
// gone when every file was read whole (or deleted) without it; unknown
// otherwise. nil without the node key (then a finding always reopens).
func securitySecretPresence(st *store.Store, identify func(typ, value string) string) secsvc.PresenceCheck {
	if identify == nil {
		return nil
	}
	scanner := secdetect.Scanner{Identify: identify}
	resolve := secsvc.RootsResolver(st.ProjectRoots)
	lim := secdetect.PostWriteLimits(0)
	return func(ctx context.Context, f secfinding.Finding) (bool, bool) {
		root, ok := resolve(ctx, f.Project.RootHash)
		if !ok {
			return false, false
		}
		paths, err := st.SecFindingSightings(ctx, f.ID)
		if err != nil || len(paths) == 0 {
			return false, false
		}
		for _, rel := range paths {
			if securityFileDeleted(root, rel) {
				continue
			}
			b, err := secpostwrite.ReadFile(root, rel, lim.MaxBytes)
			if err != nil {
				return false, false
			}
			r := scanner.Scan(string(b), rel, lim)
			if r.Status == secdetect.StatusIncomplete {
				return false, false
			}
			for _, h := range r.Hits {
				if h.Identity == "" {
					continue
				}
				id := secfinding.MatchIdentity{Kind: secfinding.MatchSecret, Value: h.Identity}
				if secfinding.LocalKey(f.Project.RootHash, secdetect.SecretRulePrefix+h.Type, id) == f.LocalKey {
					return true, true
				}
			}
		}
		return false, true
	}
}

func runSecurityExceptionSweep(ctx context.Context, st *store.Store, retentionDays int, logger *slog.Logger, identify func(typ, value string) string) {
	d := securityExceptionDeps(st)
	d.StillPresent = securitySecretPresence(st, identify)
	t := time.NewTicker(securityExceptionEvery)
	defer t.Stop()
	lastPrune := time.Time{}
	var untilChange int64
	d.UntilChangeCursor = &untilChange
	for {
		if r, err := secsvc.SweepExceptions(ctx, d); err != nil {
			logger.Warn("security: exception sweep failed", "err", err)
		} else if r.Expired+r.FileChanged > 0 {
			logger.Info("security: exceptions ended", "expired", r.Expired, "file_changed", r.FileChanged, "closed_secret_gone", r.Gone)
			securityRT.notify()
		}
		// The org's finding exceptions (lane SEC-E3) are applied after the
		// sweep, so a window the sweep just ended is applied again at once.
		if r, err := syncOrgFindingExceptions(ctx, st); err != nil {
			logger.Warn("security: org exception sync failed", "err", err)
		} else if r.Applied+r.Ended > 0 {
			logger.Info("security: org exceptions synced", "applied", r.Applied, "ended", r.Ended)
			securityRT.notify()
		}
		if retentionDays > 0 && time.Since(lastPrune) >= securityRetentionEvery {
			if _, err := st.PruneSecExceptions(ctx, time.Now().AddDate(0, 0, -retentionDays)); err != nil {
				logger.Warn("security: exception retention failed", "err", err)
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncOrgFindingExceptions applies the honoured org finding_exception
// grants to the local register on a MANAGED node (security plan 7.5, lane
// SEC-E3); an individual node applies none, so any org exception it once
// held ends.
func syncOrgFindingExceptions(ctx context.Context, st *store.Store) (secsvc.OrgSyncResult, error) {
	now := time.Now()
	var grants []secsvc.OrgException
	managed, err := securityNodeManaged(ctx, st, now)
	if err != nil {
		return secsvc.OrgSyncResult{}, err
	}
	if managed {
		honoured, err := orgclient.FindingExceptionGrants(ctx, st, now)
		if err != nil {
			return secsvc.OrgSyncResult{}, err
		}
		for _, g := range honoured {
			e := secsvc.OrgException{GrantID: g.GrantID, FindingRef: g.FindingRef, RuleID: g.RuleID}
			if g.UntilNs > 0 {
				e.ExpiresAt = time.Unix(0, g.UntilNs)
			}
			grants = append(grants, e)
		}
	}
	return secsvc.SyncOrgExceptions(ctx, secsvc.OrgExceptionDeps{
		Store: st,
		OpenFindings: func(ctx context.Context) ([]secfinding.Finding, error) {
			return st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen, Limit: 1000})
		},
		Ref: store.SecurityFindingRef,
	}, grants)
}

// securityExceptionSubcommands are the exception and baseline verbs.
func securityExceptionSubcommands() []*cobra.Command {
	return append([]*cobra.Command{newSecurityExceptionCmd(), newSecurityBaselineCmd(), newSecurityScanCmd()}, securityGithookSubcommands()...)
}

// securityHistoryDeps are the history scan's parts (secsvc.LocalHistoryDeps).
func securityHistoryDeps(configPath string, st *store.Store) (secsvc.HistoryDeps, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return secsvc.HistoryDeps{}, err
	}
	return secsvc.LocalHistoryDeps(resolved, secrules.PackVersion, st), nil
}

func newSecurityScanCmd() *cobra.Command {
	var configPath, dir string
	var history, asJSON bool
	var maxCommits int
	cmd := &cobra.Command{
		Use:   "scan --history",
		Short: "Scan a project's commit history for secrets (bounded, on demand)",
		Long: "Scans the newest commits of HEAD one by one with the native secret detectors, so a\n" +
			"secret that was added and later removed is still found. Bounded by --max-commits\n" +
			"and a 60-second deadline; a partial clone never fetches a missing object. Each hit\n" +
			"is a finding: a secret in history is a live credential until it is rotated, and\n" +
			"secrets are never pre-existing, so an open one blocks an agent's commits like any\n" +
			"other (except it on the Code security page if it was rotated).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !history {
				return errors.New("only --history is built in this release")
			}
			root, err := securityProjectRoot(dir)
			if err != nil {
				return err
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			deps, err := securityHistoryDeps(configPath, store.New(database))
			if err != nil {
				return err
			}
			res, err := secsvc.ScanHistory(cmd.Context(), deps, root, secsvc.HistoryOptions{MaxCommits: maxCommits})
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), res)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "History scan: %d commit(s) read, %d secret hit(s), %d new finding(s).\n", res.Commits, res.Hits, res.NewFindings)
			if !res.Complete() {
				fmt.Fprintf(w, "Not complete: %d commit(s) could not be judged, %d not reached before the deadline. Not a clean answer.\n", res.Unknown, res.Remaining)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&dir, "project", "", "project directory (default: the working directory)")
	cmd.Flags().BoolVar(&history, "history", false, "scan the commit history")
	cmd.Flags().IntVar(&maxCommits, "max-commits", secsvc.DefaultHistoryCommits, "newest commits to read (at most 5000)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newSecurityExceptionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exception",
		Short: "Except one finding for a while (local, expiring, never rule-wide)",
		Long: "An exception says one finding is not a real problem, for a while: it is scoped\n" +
			"to that finding in that project, it always expires, and the rule keeps firing\n" +
			"everywhere else. Granting one is the developer's decision, never an agent's.",
	}
	cmd.AddCommand(newSecurityExceptionAddCmd(), newSecurityExceptionListCmd(), newSecurityExceptionRevokeCmd(), newSecurityExceptionRequestCmd())
	return cmd
}

// newSecurityExceptionRequestCmd asks the organization for an exception on
// one finding (security plan 7.5, lane SEC-E3): a finding_exception request
// naming the finding's wire handle and rule, for the stated duration. An
// approver other than the developer decides it; a granted exception reaches
// this node on its next sync and is applied by the exception loop (on a
// managed node). Nothing about the finding beyond its handle and rule is
// sent.
func newSecurityExceptionRequestCmd() *cobra.Command {
	var f requestFlags
	cmd := &cobra.Command{
		Use:   "request <finding-id> <why>",
		Short: "Ask your organization to except one finding for a while",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), f.configPath)
			if err != nil {
				return err
			}
			fnd, found, err := store.New(database).SecFindingByID(cmd.Context(), args[0])
			cleanup()
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("no finding %s on this machine", args[0])
			}
			ref := store.SecurityFindingRef(fnd.ID)
			return sendTypedRequest(cmd, f, orgcontract.AccessRequestCreate{
				RequestType: accessgrant.TypeFindingException, Message: args[1], Target: ref,
				Payload: &orgcontract.AccessRequestPayload{RuleID: fnd.Rule.ID, Target: ref},
			})
		},
	}
	f.bind(cmd)
	return cmd
}

func newSecurityExceptionAddCmd() *cobra.Command {
	var configPath, reason, expiry string
	cmd := &cobra.Command{
		Use:   "add <finding-id>",
		Short: "Except an open finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			ex, err := secsvc.GrantException(cmd.Context(), securityExceptionDeps(store.New(database)), secexcept.Request{
				FindingID: args[0], Reason: reason, Expiry: expiry, Origin: secexcept.OriginCLI,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Exception %d for finding %s (%s), until %s.\n", ex.ID, ex.FindingID, ex.Reason, ex.ExpiresAt.Local().Format(time.RFC1123))
			if ex.Expiry == string(secexcept.ExpiryUntilChange) {
				fmt.Fprintln(cmd.OutOrStdout(), "It also ends as soon as the file changes.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&reason, "reason", "", "false_positive, test_fixture or accepted_risk")
	cmd.Flags().StringVar(&expiry, "expires", "", "1d, 7d, 30d or until_change")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("expires")
	return cmd
}

func newSecurityExceptionListCmd() *cobra.Command {
	var configPath, project string
	var all, asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List exceptions (those still applying, or --all)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			got, err := store.New(database).ListSecExceptions(cmd.Context(), store.SecExceptionFilter{ProjectRootHash: project, OpenOnly: !all})
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), got)
			}
			if len(got) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No exceptions.")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tFINDING\tRULE\tWHERE\tREASON\tUNTIL\tSTATE")
			for _, e := range got {
				state := "applies"
				if !e.EndedAt.IsZero() {
					state = "ended (" + e.EndReason + ")"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.FindingID, e.RuleID, e.RelPath, e.Reason, e.ExpiresAt.Local().Format("2006-01-02 15:04"), state)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&project, "project", "", "project root hash")
	cmd.Flags().BoolVar(&all, "all", false, "include ended exceptions")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newSecurityExceptionRevokeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "revoke <exception-id>",
		Short: "End an exception now; its finding is open again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("exception id %q is not a number", args[0])
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := secsvc.RevokeException(cmd.Context(), securityExceptionDeps(store.New(database)), id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Exception %d ended; its finding is open again.\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

// securityProjectRoot resolves --project (a directory, default the
// working directory) to its git root.
func securityProjectRoot(dir string) (string, error) {
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	root, ok := git.FindRoot(dir)
	if !ok {
		return "", fmt.Errorf("%s is not inside a git repository", dir)
	}
	return root, nil
}

func newSecurityBaselineCmd() *cobra.Command {
	var configPath, dir, approve string
	var reset, asJSON bool
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Show, approve or reset a project's baseline commit",
		Long: "A baseline is a commit you approve as the project's starting point: a finding\n" +
			"the same rules also report at that commit is pre-existing, a backlog rather\n" +
			"than a wall. Secrets and malicious packages are never pre-existing. Without\n" +
			"--approve or --reset it shows the current baseline and the commits you can pick\n" +
			"(the merge base with the default branch first).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if approve != "" && reset {
				return errors.New("--approve and --reset are exclusive")
			}
			root, err := securityProjectRoot(dir)
			if err != nil {
				return err
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			w := cmd.OutOrStdout()
			switch {
			case approve != "":
				b, err := secsvc.ApproveBaseline(cmd.Context(), gitview.RunReadOnlyTimeout, st, root, approve, secexcept.OriginCLI, secrules.PackVersion, time.Now())
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "Baseline approved: %s. Findings the rules also report there become pre-existing at the daemon's next pass (secrets never do).\n", b.Ref)
				return nil
			case reset:
				if err := secsvc.ResetBaseline(cmd.Context(), st, root, secexcept.OriginCLI, time.Now()); err != nil {
					return err
				}
				fmt.Fprintln(w, "Baseline reset: no trusted baseline until you approve another commit.")
				return nil
			}
			view, err := secsvc.LoadBaselineView(cmd.Context(), gitview.RunReadOnlyTimeout, st, root)
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(w, view)
			}
			if view.Current == nil {
				fmt.Fprintln(w, "No baseline: findings read as untrusted_baseline (flag, never pre-existing).")
			} else {
				fmt.Fprintf(w, "Baseline: %s, approved from the %s on %s\n", view.Current.Ref, view.Current.Approver, view.Current.CreatedAt.Local().Format(time.RFC1123))
				if line := securityBaselineOrgLine(view.Current); line != "" {
					fmt.Fprintln(w, line)
				}
			}
			if view.ProposalError != "" {
				fmt.Fprintln(w, "No commits to offer:", view.ProposalError)
			}
			for _, c := range view.Proposed {
				mark := "  "
				if c.MergeBase {
					mark = "* "
				}
				fmt.Fprintf(w, "%s%s  %s  %s\n", mark, c.SHA[:12], c.When.Local().Format("2006-01-02"), c.Subject)
			}
			if len(view.Proposed) > 0 {
				fmt.Fprintln(w, "Approve one with: observer security baseline --approve <commit>  (* is the merge base)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&dir, "project", "", "project directory (default: the working directory)")
	cmd.Flags().StringVar(&approve, "approve", "", "approve this commit (an id, branch or tag) as the baseline")
	cmd.Flags().BoolVar(&reset, "reset", false, "reset: no trusted baseline")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// securityNotifyEvery is how often the critical-finding notification
// looks for new findings.
const securityNotifyEvery = 30 * time.Second

// securityNotifyBatch bounds the findings one pass reads.
const securityNotifyBatch = 20

// startSecurityNotify starts the security.notify loop on ng: one desktop
// notification, through the guard notifier, per pass that saw new critical
// findings (security pillar plan section 6.1 "Desktop notification", lane
// sec-c3). It does nothing unless [security.notify].critical is on, and it
// never announces findings that were already there when it started.
func startSecurityNotify(ctx context.Context, ng *gatedGroup, configPath string) {
	ng.Go("security.notify", func() error {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			return nil
		}
		defer cleanup()
		if !cfg.Security.Notify.Critical {
			return nil
		}
		runSecurityNotify(ctx, store.New(database), notify.NewDesktop().Notify, newLogger(cfg.Observer.LogLevel))
		return nil
	})
}

func runSecurityNotify(ctx context.Context, st *store.Store, send func(title, body string), logger *slog.Logger) {
	last, err := st.SecMaxFindingEventID(ctx)
	if err != nil {
		logger.Warn("security: notification not started", "err", err)
		return
	}
	t := time.NewTicker(securityNotifyEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		seen, err := st.SecSeenAfter(ctx, last, policy.FindingSeverityCritical, securityNotifyBatch)
		if err != nil {
			logger.Warn("security: notification read failed", "err", err)
			continue
		}
		if len(seen) == 0 {
			continue
		}
		last = seen[len(seen)-1].EventID
		send(securityNotifyText(seen))
	}
}

// securityNotifyText is one notification for a batch of new critical
// findings: rule ids and paths only, every path through the deny text's
// safe-character filter, because a file name is repository text.
func securityNotifyText(seen []store.SecSeenFinding) (title, body string) {
	title = "Observer: new critical code security finding"
	if len(seen) > 1 {
		title = fmt.Sprintf("Observer: %d new critical code security findings", len(seen))
	}
	f := seen[0]
	body = fmt.Sprintf("%s in %s", f.RuleID, secdetect.SanitizeLocation(f.RelPath))
	if len(seen) > 1 {
		body += fmt.Sprintf(" and %d more", len(seen)-1)
	}
	return title, body + ". See Code security > Findings."
}
