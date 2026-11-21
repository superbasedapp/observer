//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_lookup_cmd.go is the package lookup posture (OS and CI
// vulnerability scanning plan section 13.10, lane RM-2): one owner of the
// state, the node config's [security.deps] match / remote_kinds /
// remote_private plus three signed consent records, written through one
// function (applyLookupChange) that both surfaces call: `observer security
// lookup` on the CLI and PUT /api/security/lookup on the dashboard's
// Privacy page. Every data-sending choice carries its own consent: the
// database accept for local, the SuperBased lookup's for remote and both,
// a separate one for sending private names. An agent can give none of
// them (R-165 denies the verbs, the route, the keys and the records). A
// managed node's organization decides: every change is refused there.

// lookupChooseHint is the one sentence a scan that waits for the posture
// prints.
var lookupChooseHint = fmt.Sprintf("choose how dependencies are checked: download the OSV databases (about %d MB, `observer security lookup mode local`) "+
	"or the superbased lookup with no download (`observer security lookup mode remote`), or on the dashboard's Privacy page (Package lookup)", osvdb.ApproxDownloadMB)

// The posture's config keys.
const (
	lookupMatchKey   = "security.deps.match"
	lookupKindsKey   = "security.deps.remote_kinds"
	lookupPrivateKey = "security.deps.remote_private"
)

// lookupStatus is the posture for the dashboard and the CLI.
func lookupStatus(ctx context.Context, e *depsScanEnv) dashapi.PackageLookupStatus {
	d := e.cfg.Security.Deps
	via := d.RemoteVia
	if via == "" {
		via = "shards"
	}
	private := d.RemotePrivate
	if private == "" {
		private = "withhold"
	}
	st := dashapi.PackageLookupStatus{
		Mode: e.lookupMode(), Configured: d.Match, Via: via, ViaChoices: slices.Clone(config.SecurityDepsRemoteVia),
		Kinds: e.lookupKinds(), KindChoices: slices.Clone(config.SecurityDepsRemoteKinds),
		Private: private, PrivateSending: e.remotePrivateSending(), Managed: e.managed,
		Download:      lookupConsentOf(e.consent, osvdb.ConsentText),
		Remote:        lookupConsentOf(e.remoteConsent.Consent, osvdb.RemoteConsentText),
		RemotePrivate: lookupConsentOf(e.remotePrivate.Consent, osvdb.RemotePrivateConsentText),
		Blocked:       e.scanWaitReason(), RemoteBlocked: e.remoteBlocked(),
		RemoteHosts: []string{osvdb.FeedHost, osvdb.RemoteShardHost}, ApproxMB: osvdb.ApproxDownloadMB,
		CacheBytes: osvshard.Cache{Dir: filepath.Join(e.dir, osvshard.CacheDirName)}.Bytes(),
		Drivers: []dashapi.LookupDriver{
			{Driver: depscan.ScalibrComponent, Remote: scalibrfacade.Compiled, Note: map[bool]string{true: "", false: "remote lookup: the SCALIBR driver, which matches it, is not in this build"}[scalibrfacade.Compiled]},
			{Driver: depscan.OSVComponent, Remote: false, Note: "remote lookup: not available for osv-scanner in this build (it matches local databases only)"},
			{Driver: trivyImageComponent, Remote: false, Note: "remote lookup: not available for Trivy (it needs its own database)"},
			{Driver: imageRouteAComponent, Remote: false, Note: "remote lookup: not available for image OS packages in this build"},
		},
	}
	if e.managed {
		// The organization decides (lane RM-3): the mode reads what its
		// signed policy says, and the developer's own records are not
		// part of it.
		st.Configured = ""
		org := &dashapi.OrgLookupStatus{
			On: e.orgLookup.On, Private: "withhold", Kinds: e.lookupKinds(), Version: e.orgLookup.Version, Source: "org",
		}
		if e.orgLookup.Private {
			org.Private = "send"
		}
		st.Private = org.Private
		if e.st != nil {
			if enr, err := e.st.LoadEnrolment(ctx); err == nil && enr != nil {
				org.OrgName = enr.OrgName
			}
		}
		st.Org = org
		st.RemoteHosts = []string{"your organization's server"}
	}
	// The sets the installed manifest lists, read from disk only (a status
	// read never fetches).
	if st.RemoteBlocked == "" {
		if l, err := depsContentStore(depsConfigPath(e.configPath)).Load(content.OSVShards, depsTrust(), depsAdvisoryFloor(e.cfg.Security)); err == nil {
			st.Sets = lookupSetsOf(l)
		}
	}
	return st
}

// lookupSetsOf lists the shard sets a loaded manifest names, by set name.
func lookupSetsOf(l contentchan.Loaded) []dashapi.LookupSet {
	var out []dashapi.LookupSet
	for _, d := range shardSetsOf(l) {
		out = append(out, dashapi.LookupSet{Set: d.Set, Ecosystem: d.Ecosystem, Epoch: d.Epoch, Bits: d.Bits})
	}
	return out
}

func lookupConsentOf(c osvdb.Consent, text string) dashapi.LookupConsent {
	out := dashapi.LookupConsent{Text: text}
	if c.Verified && !c.AcceptedAt.IsZero() && osvdb.ConsentSurfaces[c.Surface] {
		out.Accepted = true
		out.AcceptedAt, out.AcceptedOn, out.By = c.AcceptedAt.UTC().Format(time.RFC3339), c.Surface, c.By
	}
	return out
}

// lookupChange is one requested change, with the surface that asks.
type lookupChange struct {
	dashapi.PackageLookupChange
	surface string
}

// errLookupManaged refuses a change on a managed node.
var errLookupManaged = errors.New("this node is managed by your organization: it sets the package lookup posture (lookups go to its server), so it cannot be changed here")

// applyLookupChange validates a change, records the consents it carries
// and writes the keys, in that order: a consent is recorded only for a
// change that needs it or one asked for by name, and a key that sends data
// is never written before its consent is on disk.
//
//nolint:gocyclo // one ordered step per posture field (mode, kinds, private names, withdraw), each refusing before any write; splitting would hide the consent-before-key order this function exists to keep.
func applyLookupChange(ctx context.Context, e *depsScanEnv, ch lookupChange) error {
	if e.managed {
		return errLookupManaged
	}
	if ch.surface != "cli" && ch.surface != "dashboard" {
		return errors.New("a package lookup change needs the CLI or the dashboard")
	}
	if ch.Mode != nil && !slices.Contains(config.SecurityDepsMatchModes, *ch.Mode) {
		return fmt.Errorf("unknown lookup mode %q: use %s", *ch.Mode, strings.Join(config.SecurityDepsMatchModes, ", "))
	}
	if ch.Kinds != nil {
		for _, k := range *ch.Kinds {
			if !slices.Contains(config.SecurityDepsRemoteKinds, k) {
				if slices.Contains(config.SecurityDepsRemoteKindsReserved, k) {
					return fmt.Errorf("the %q kind is not in this build (only %s)", k, strings.Join(config.SecurityDepsRemoteKinds, ", "))
				}
				return fmt.Errorf("unknown lookup kind %q: use %s", k, strings.Join(config.SecurityDepsRemoteKinds, ", "))
			}
		}
	}
	if ch.Private != nil && !slices.Contains(config.SecurityDepsRemotePrivate, *ch.Private) {
		return fmt.Errorf("unknown private-names choice %q: use withhold or send", *ch.Private)
	}
	if ch.Mode != nil {
		switch *ch.Mode {
		case lookupLocal:
			if !e.consent.Accepted() && !e.osvImportOnly() && !ch.AcceptDownload {
				return errors.New("local lookup downloads the OSV databases: it needs the database accept (accept_download, or `--yes` after reading the text)")
			}
		case lookupRemote, lookupBoth:
			if (!e.remoteConsent.Accepted() || ch.WithdrawRemote) && !ch.AcceptRemote {
				return errors.New("the superbased lookup sends hash prefixes of your package names: it needs its own consent (accept_remote, or `--yes` after reading the text)")
			}
		}
	}
	if ch.Private != nil && *ch.Private == "send" && (!e.remotePrivate.Accepted() || ch.WithdrawPrivate) && !ch.AcceptPrivate {
		return errors.New("sending private package names needs its own consent (accept_private, or `--yes` after reading the text)")
	}
	needKey := ch.AcceptDownload || ch.AcceptRemote || ch.AcceptPrivate
	var key []byte
	if needKey {
		k, err := depsRecordSigningKey(e.dir)
		if err != nil {
			return err
		}
		key = k
	}
	now := time.Now()
	if ch.WithdrawRemote {
		if err := osvdb.WithdrawRemoteConsent(e.dir); err != nil {
			return err
		}
		e.remoteConsent = osvdb.RemoteConsent{}
	}
	if ch.WithdrawPrivate {
		if err := osvdb.WithdrawRemotePrivate(e.dir); err != nil {
			return err
		}
		e.remotePrivate = osvdb.RemotePrivateConsent{}
	}
	if ch.AcceptDownload && !e.consent.Accepted() {
		c, err := osvdb.RecordConsent(e.dir, ch.surface, depsLocalAccount(), now, key)
		if err != nil {
			return err
		}
		e.consent = c
	}
	if ch.AcceptRemote && !e.remoteConsent.Accepted() {
		c, err := osvdb.RecordRemoteConsent(e.dir, ch.surface, depsLocalAccount(), now, key)
		if err != nil {
			return err
		}
		e.remoteConsent = c
	}
	if ch.AcceptPrivate && !e.remotePrivate.Accepted() {
		c, err := osvdb.RecordRemotePrivateConsent(e.dir, ch.surface, depsLocalAccount(), now, key)
		if err != nil {
			return err
		}
		e.remotePrivate = c
	}
	var sets [][2]string
	if ch.Mode != nil {
		sets = append(sets, [2]string{lookupMatchKey, *ch.Mode})
	}
	if ch.Kinds != nil {
		ks := slices.Clone(*ch.Kinds)
		sort.Strings(ks)
		sets = append(sets, [2]string{lookupKindsKey, strings.Join(slices.Compact(ks), ",")})
	}
	if ch.Private != nil {
		sets = append(sets, [2]string{lookupPrivateKey, *ch.Private})
	}
	return writeLookupKeys(ctx, e.configPath, sets)
}

// writeLookupKeys writes each key through `config set`'s checks and writer.
func writeLookupKeys(ctx context.Context, configPath string, sets [][2]string) error {
	if len(sets) == 0 {
		return nil
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	for _, kv := range sets {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: resolved})
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		gov, err := configSetGovernance(ctx, cfg)
		if err != nil {
			return err
		}
		plan, err := planConfigSet(cfg, kv[0], kv[1], gov, true)
		if err != nil {
			return err
		}
		if err := writeConfigSet(resolved, plan); err != nil {
			return err
		}
	}
	return nil
}

// writeLookupState prints the posture lines of `observer security scan
// status` and `observer security lookup`.
func writeLookupState(ctx context.Context, w io.Writer, e *depsScanEnv) {
	st := lookupStatus(ctx, e)
	if st.Managed {
		writeOrgLookupState(w, st)
		return
	}
	mode := st.Mode
	if mode == "" {
		mode = "not chosen"
	}
	fmt.Fprintf(w, "package lookup: %s", mode)
	if st.Configured == "" && st.Mode != "" {
		fmt.Fprint(w, " (the install's databases; [security.deps] match unset)")
	}
	fmt.Fprintln(w)
	switch st.Mode {
	case "":
		fmt.Fprintln(w, "  "+lookupChooseHint)
	case lookupRemote, lookupBoth:
		fmt.Fprintf(w, "  superbased lookup via %s, kinds %s; private names %s\n", st.Via, strings.Join(st.Kinds, ", "), map[bool]string{true: "sent", false: "withheld"}[st.PrivateSending])
		if st.Remote.Accepted {
			fmt.Fprintf(w, "  consent recorded %s (%s)\n", st.Remote.AcceptedAt, st.Remote.AcceptedOn)
		}
		if st.RemoteBlocked != "" {
			fmt.Fprintf(w, "  remote lookup not running: %s\n", st.RemoteBlocked)
		}
		for _, s := range st.Sets {
			fmt.Fprintf(w, "  set %-18s %s, epoch %d, %d bits\n", s.Set, s.Ecosystem, s.Epoch, s.Bits)
		}
		fmt.Fprintf(w, "  shard cache: %d bytes\n", st.CacheBytes)
		for _, d := range st.Drivers {
			if d.Note != "" {
				fmt.Fprintf(w, "  %s: %s\n", d.Driver, d.Note)
			}
		}
	}
	if st.Blocked != "" {
		fmt.Fprintf(w, "  dependency scans wait: %s\n", depscan.ReasonWords(st.Blocked))
	}
}

// writeOrgLookupState prints a managed node's org-decided posture
// (read-only, lane RM-3).
func writeOrgLookupState(w io.Writer, st dashapi.PackageLookupStatus) {
	o := st.Org
	if o == nil {
		o = &dashapi.OrgLookupStatus{Private: "withhold"}
	}
	server := "your organization's server"
	if o.OrgName != "" {
		server += " (" + o.OrgName + ")"
	}
	fmt.Fprintf(w, "package lookup: set by your organization (security policy version %d); nothing is downloaded from or sent to a public host\n", o.Version)
	if !o.On {
		fmt.Fprintln(w, "  superbased lookup: off by your organization's policy; no package lookup leaves this machine")
	} else {
		fmt.Fprintf(w, "  lookups go to %s, mirror mode: local databases from its mirror first, its shards for the rest\n", server)
		fmt.Fprintf(w, "  kinds %s; private package names %s (your organization's rule)\n", strings.Join(o.Kinds, ", "), map[string]string{"send": "sent", "withhold": "withheld"}[o.Private])
		if st.RemoteBlocked != "" {
			fmt.Fprintf(w, "  remote lookup not running: %s\n", st.RemoteBlocked)
		}
		for _, s := range st.Sets {
			fmt.Fprintf(w, "  set %-18s %s, epoch %d, %d bits\n", s.Set, s.Ecosystem, s.Epoch, s.Bits)
		}
		fmt.Fprintf(w, "  shard cache: %d bytes\n", st.CacheBytes)
	}
	fmt.Fprintln(w, "  the choice is your organization's: `observer security lookup` cannot change it on this node")
}

// newSecurityLookupCmd is `observer security lookup`.
func newSecurityLookupCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "lookup",
		Short: "Show, or choose, how dependencies are checked: downloaded databases (local), the superbased lookup (remote), or both",
		Long: "The package lookup posture (the dashboard's Privacy page, Package lookup). local downloads the OSV databases\n" +
			"and matches here; remote downloads nothing and looks every ecosystem up at superbased, sending a short hash\n" +
			"prefix of each package name, never a name, a version or code; both matches locally where a database is\n" +
			"installed and looks up only the rest. Each choice that sends or downloads data asks for its own consent.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runLookupStatus(cmd) },
	}
	status := &cobra.Command{Use: "status", Short: "Show the package lookup posture", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runLookupStatus(cmd) }}
	var yes bool
	mode := &cobra.Command{
		Use:   "mode local|remote|both",
		Short: "Choose the lookup mode, recording its consent (the database accept for local, the superbased lookup's for remote and both)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withLookupEnv(cmd, func(e *depsScanEnv, w io.Writer, in io.Reader, tty bool) error {
				m := args[0]
				ch := lookupChange{surface: "cli"}
				ch.Mode = &m
				switch m {
				case lookupLocal:
					if !e.consent.Accepted() && !e.osvImportOnly() {
						ok, err := askLookupConsent(w, in, osvdb.ConsentText, fmt.Sprintf("Download about %d MB from %s now and keep it up to date?", osvdb.ApproxDownloadMB, osvdb.Source), yes, tty)
						if err != nil || !ok {
							return err
						}
						ch.AcceptDownload = true
					}
				case lookupRemote, lookupBoth:
					if !e.remoteConsent.Accepted() {
						ok, err := askLookupConsent(w, in, osvdb.RemoteConsentText, "Use the superbased lookup for your dependency scans?", yes, tty)
						if err != nil || !ok {
							return err
						}
						ch.AcceptRemote = true
					}
				}
				if err := applyLookupChange(cmd.Context(), e, ch); err != nil {
					return err
				}
				fmt.Fprintf(w, "set %s = %s\n", lookupMatchKey, m)
				return nil
			})
		},
	}
	mode.Flags().BoolVar(&yes, "yes", false, "record the consent without asking (you read the text above)")
	kinds := &cobra.Command{
		Use:   "kinds LIST",
		Short: "Choose which package kinds the superbased lookup covers (comma separated: " + strings.Join(config.SecurityDepsRemoteKinds, ", ") + ")",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withLookupEnv(cmd, func(e *depsScanEnv, w io.Writer, _ io.Reader, _ bool) error {
				var ks []string
				for _, k := range strings.Split(args[0], ",") {
					if k = strings.TrimSpace(k); k != "" {
						ks = append(ks, k)
					}
				}
				if len(ks) == 0 {
					return errors.New("name at least one kind")
				}
				ch := lookupChange{surface: "cli"}
				ch.Kinds = &ks
				if err := applyLookupChange(cmd.Context(), e, ch); err != nil {
					return err
				}
				fmt.Fprintf(w, "set %s = %s\n", lookupKindsKey, strings.Join(ks, ","))
				return nil
			})
		},
	}
	var yesPrivate bool
	private := &cobra.Command{
		Use:   "private withhold|send",
		Short: "Choose whether the superbased lookup sends private and internal package names too (send records its own consent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withLookupEnv(cmd, func(e *depsScanEnv, w io.Writer, in io.Reader, tty bool) error {
				v := args[0]
				ch := lookupChange{surface: "cli"}
				ch.Private = &v
				if v == "send" && !e.remotePrivate.Accepted() {
					ok, err := askLookupConsent(w, in, osvdb.RemotePrivateConsentText, "Look private and internal package names up too?", yesPrivate, tty)
					if err != nil || !ok {
						return err
					}
					ch.AcceptPrivate = true
				}
				if err := applyLookupChange(cmd.Context(), e, ch); err != nil {
					return err
				}
				fmt.Fprintf(w, "set %s = %s\n", lookupPrivateKey, v)
				return nil
			})
		},
	}
	private.Flags().BoolVar(&yesPrivate, "yes", false, "record the consent without asking (you read the text above)")
	var withdrawPrivate bool
	withdraw := &cobra.Command{
		Use:   "withdraw",
		Short: "Withdraw the superbased lookup's consent (or, with --private, only the private-names consent); takes effect at the next lookup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withLookupEnv(cmd, func(e *depsScanEnv, w io.Writer, _ io.Reader, _ bool) error {
				ch := lookupChange{surface: "cli"}
				ch.WithdrawPrivate = true
				if !withdrawPrivate {
					ch.WithdrawRemote = true
				}
				if err := applyLookupChange(cmd.Context(), e, ch); err != nil {
					return err
				}
				if withdrawPrivate {
					fmt.Fprintln(w, "Withdrawn: private package names are withheld from the next lookup on.")
				} else {
					fmt.Fprintln(w, "Withdrawn: the next dependency scan makes no superbased lookup (ecosystems it would have looked up read not scanned).")
				}
				return nil
			})
		},
	}
	withdraw.Flags().BoolVar(&withdrawPrivate, "private", false, "withdraw only the private-names consent")
	root.AddCommand(status, mode, kinds, private, withdraw)
	return root
}

// runLookupStatus prints the posture.
func runLookupStatus(cmd *cobra.Command) error {
	configPath, _ := cmd.Flags().GetString("config")
	if err := requireDepsScanSelected(configPath); err != nil {
		return err
	}
	e, err := openDepsScanEnv(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	writeLookupState(cmd.Context(), cmd.OutOrStdout(), e)
	return nil
}

// withLookupEnv opens the env for a posture verb; a managed node prints
// the organization's posture and refuses.
func withLookupEnv(cmd *cobra.Command, f func(e *depsScanEnv, w io.Writer, in io.Reader, tty bool) error) error {
	configPath, _ := cmd.Flags().GetString("config")
	if err := requireDepsScanSelected(configPath); err != nil {
		return err
	}
	e, err := openDepsScanEnv(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	w := cmd.OutOrStdout()
	if e.managed {
		writeLookupState(cmd.Context(), w, e)
		return errLookupManaged
	}
	return f(e, w, cmd.InOrStdin(), term.IsTerminal(int(os.Stdin.Fd())))
}

// askLookupConsent shows a consent's text and asks on a terminal; without
// one it consents only with --yes. false with no error records nothing.
func askLookupConsent(w io.Writer, in io.Reader, text, question string, yes, tty bool) (bool, error) {
	fmt.Fprintln(w, text)
	if !yes && tty {
		fmt.Fprintf(w, "\n%s [y/N] ", question)
		yes = depsReadYes(in)
	}
	if !yes {
		fmt.Fprintln(w, "\nNothing recorded. Choose on the dashboard's Privacy page (Package lookup), or re-run with --yes.")
		return false, nil
	}
	return true, nil
}
