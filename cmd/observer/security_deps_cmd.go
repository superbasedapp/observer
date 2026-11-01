//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_deps_cmd.go is `observer security deps` (security pillar plan
// sections 5.4, 8.3 and 8.5): the install gate's status, the online
// checks' disclosure, an offline index import (an air-gapped or managed
// node, or a test), and a dry-run check of one command against the
// installed index.

func securityDepsSubcommands() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "deps",
		Short: "Package checks: the install gate, its index and its online lane (component security.deps)",
	}
	cmd.AddCommand(newSecurityDepsStatusCmd(), newSecurityDepsDisclosureCmd(), newSecurityDepsImportCmd(), newSecurityDepsCheckCmd())
	return []*cobra.Command{cmd}
}

// depsCmdEnv resolves the config and the security directory.
func depsCmdEnv(cmd *cobra.Command) (config.Config, string, string, error) {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return config.Config{}, "", "", err
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return config.Config{}, "", "", err
	}
	return cfg, resolved, secposture.LayoutFor(resolved).Dir, nil
}

func newSecurityDepsStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the install gate's state: component, online checks, disclosure, index and cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, resolved, dir, err := depsCmdEnv(cmd)
			if err != nil {
				return err
			}
			active := securitySelected(componentSnapshotForConfig(cfg), securityDepsComponent)
			// Read the floors and the managed pull in force, as the daemon
			// does (P-051): the status shows the floored online setting.
			configPath, _ := cmd.Flags().GetString("config")
			bindDepsFloorsForCLI(cmd.Context(), cfg, configPath)
			writeDepsStatus(cmd.Context(), cmd.OutOrStdout(), cfg, resolved, dir, active)
			return nil
		},
	}
}

// writeDepsStatus renders the status.
func writeDepsStatus(ctx context.Context, w io.Writer, cfg config.Config, resolved, dir string, active bool) {
	state := "active"
	if !active {
		state = "not active (Settings > Components)"
	}
	fmt.Fprintf(w, "component security.deps: %s\n", state)
	online := "on"
	if !depsInForce(cfg.Security).Online {
		online = "off (offline lists only)"
	}
	d := readDepsDisclosure(dir)
	shown := "not shown yet: no online query is sent until it is (observer security deps disclosure)"
	if d.Shown() {
		shown = "shown " + d.ShownAt.Local().Format(time.RFC3339) + " (" + d.Surface + ")"
	}
	fmt.Fprintf(w, "online checks: %s; disclosure %s\n", online, shown)
	fmt.Fprintf(w, "install-gate wait: %d ms; minimum package age: %d h\n", cfg.Security.Deps.InstallWaitMS, cfg.Security.Deps.MinPackageAgeH)
	fmt.Fprintln(w, depsIndexDownloadLine(cfg.Security.Deps))
	store := depsContentStore(resolved)
	for _, k := range depsFeedKinds {
		st, err := store.State(k.kind)
		switch {
		case err != nil:
			fmt.Fprintf(w, "index %s: unreadable state\n", k.kind)
		case st.Accepted == nil:
			fmt.Fprintf(w, "index %s: not installed (verdicts read unknown until it is)\n", k.kind)
		default:
			fresh := "unknown"
			if l, err := store.Load(k.kind, depsTrust(), depsAdvisoryFloor(cfg.Security)); err == nil {
				fresh = string(l.Freshness)
			}
			fmt.Fprintf(w, "index %s: version %d, epoch %d, issued %s, %s\n", k.kind, st.Accepted.ManifestVersion, st.Accepted.Epoch, st.IssuedAt, fresh)
		}
		if st.LastFailure != "" {
			fmt.Fprintf(w, "  last refresh failed (%s) at %s; the last verified index stays\n", st.LastFailure, st.LastFailureAt)
		}
	}
	// A managed node's index comes from its org mirror (lane SEC-E4): what
	// the last fetch did, with the data's freshness (never clean on its
	// own).
	if fetched := readMirrorFetch(store); len(fetched) > 0 {
		var kinds []content.Kind
		for k := range fetched {
			kinds = append(kinds, content.Kind(k))
		}
		for _, line := range depsMirrorLines(store, depsTrust(), depsAdvisoryFloor(cfg.Security), kinds) {
			fmt.Fprintln(w, "org mirror "+line)
		}
	}
	if database, err := openDepsDB(ctx, cfg); err == nil {
		defer func() { _ = database.Close() }()
		if n, newest, err := database.st.SecPkgCacheStats(ctx); err == nil {
			age := "never"
			if !newest.IsZero() {
				age = time.Since(newest).Round(time.Minute).String() + " ago"
			}
			fmt.Fprintf(w, "online answers cached: %d; last online refresh: %s\n", n, age)
		}
	}
}

func newSecurityDepsDisclosureCmd() *cobra.Command {
	var accept bool
	cmd := &cobra.Command{
		Use:   "disclosure",
		Short: "Show what the online package checks send, and turn them on when you say yes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _, dir, err := depsCmdEnv(cmd)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, secfeed.DisclosureText)
			if readDepsDisclosure(dir).Shown() {
				fmt.Fprintln(out, "\nAlready accepted; online package checks are on while security.deps.online is true.")
				return nil
			}
			yes := accept
			if !yes && term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprint(out, "\nTurn online package checks on? [y/N] ")
				yes = depsReadYes(cmd.InOrStdin())
			}
			if !yes {
				fmt.Fprintln(out, "\nNothing recorded. Accept on the dashboard's Code security page, or re-run with --accept.")
				return nil
			}
			if _, err := recordDepsDisclosure(dir, "cli", time.Now()); err != nil {
				return err
			}
			fmt.Fprintln(out, "\nRecorded. Online package checks are on (turn them off with security.deps.online = false).")
			return nil
		},
	}
	cmd.Flags().BoolVar(&accept, "accept", false, "record that you read the disclosure and turn online checks on")
	return cmd
}

// depsReadYes reads one answer line: only y or yes counts.
func depsReadYes(r io.Reader) bool {
	line, _ := bufio.NewReader(io.LimitReader(r, 64)).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func newSecurityDepsImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <dir>",
		Short: "Install a signed package index from a directory (content channel layout; offline)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolved, _, err := depsCmdEnv(cmd)
			if err != nil {
				return err
			}
			if !securitySelected(componentSnapshotForConfig(cfg), securityDepsComponent) {
				return errors.New("security.deps is not active (Settings > Components)")
			}
			n, err := importDepsIndex(args[0], depsContentStore(resolved))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %d index kind(s)\n", n)
			return nil
		},
	}
}

// importDepsIndex installs every index kind found under src.
func importDepsIndex(src string, dst contentchan.Store) (int, error) {
	n := 0
	var errs []error
	for _, k := range depsFeedKinds {
		dir := filepath.Join(src, string(k.kind))
		env, err := readDepsFile(filepath.Join(dir, contentchan.ManifestFile), content.MaxEnvelopeBytes)
		if err != nil {
			continue
		}
		data, err := readDepsFile(filepath.Join(dir, k.name), secfeed.MaxIndexBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k.kind, err))
			continue
		}
		if _, err := dst.Install(k.kind, env, map[string][]byte{k.name: data}, depsTrust()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k.kind, err))
			continue
		}
		n++
	}
	if n == 0 && len(errs) == 0 {
		return 0, fmt.Errorf("no index kind found under %s", src)
	}
	return n, errors.Join(errs...)
}

func newSecurityDepsCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <command>",
		Short: "Check one install command against the installed index and cache (offline dry run; nothing is installed or sent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, resolved, _, err := depsCmdEnv(cmd)
			if err != nil {
				return err
			}
			in := secfeed.ParseInstalls(&policy.Event{Kind: policy.KindShellExec, Target: args[0]})
			if len(in.Specs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no package install in that command")
				return nil
			}
			ix, fresh := loadInstallIndexCached(depsContentStore(resolved), depsTrust())
			wd, _ := os.Getwd()
			ev := &policy.Event{Kind: policy.KindShellExec, Target: args[0], Cwd: wd}
			scope := hookDepsScope(hookctx.InstallRequest{ProjectRoot: hookRootOf(wd), Event: ev}, os.Environ())
			for _, c := range secfeed.Gate(cmd.Context(), secfeed.GateInput{Specs: in.Specs, Index: ix, IndexFreshness: fresh, Public: depsClassifier(scope), MinAge: depsDefaultMinAge, Now: time.Now()}) {
				v := string(c.Verdict)
				if v == "" {
					v = "not checked"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %q: %s (%s)\n", c.Ecosystem, c.Name, v, c.Reason)
			}
			if in.CustomRegistry {
				fmt.Fprintln(cmd.OutOrStdout(), "the command names a custom registry or index (S-745)")
			}
			return nil
		},
	}
}

// depsDB is a store handle for the CLI.
type depsDB struct {
	st    *store.Store
	close func()
}

func (d depsDB) Close() error { d.close(); return nil }

func openDepsDB(ctx context.Context, cfg config.Config) (depsDB, error) {
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return depsDB{}, err
	}
	return depsDB{st: store.New(database), close: func() { _ = database.Close() }}, nil
}
