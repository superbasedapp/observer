//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secinventory"
	"github.com/marmutapp/superbased-observer/internal/seclicense"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_licenses.go is the cmd seam of licence compliance (security
// coverage gaps plan item 4): it walks a project for the dependency files
// internal/seclicense reads (lockfile licence fields, installed package
// metadata, vendored crates), joins the licences to the SBOM, prints them
// (`observer security licenses`) and, when [security.licenses] names a
// policy, records the policy's findings through secsvc.RecordRun under
// driver "license": flag only, medium at most, baseline unknown, so never
// in the commit gate's blocking set. Local only: nothing is sent anywhere.

// Walk caps: files visited, files read and bytes read per project.
const (
	licenceMaxVisited = 200_000
	licenceMaxRead    = 20_000
	licenceMaxBytes   = 256 << 20
)

// licenceSkipDirs are directory names the walk never enters.
var licenceSkipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "__pycache__": true, ".cache": true, "target": true, "dist": true, "build": true}

// licenceWalk is one project's licence read.
type licenceWalk struct {
	Entries []seclicense.Entry
	// Files are the project-relative files read (the paths a complete
	// record closes findings at).
	Files []string
	// Capped: a cap stopped the walk, so the read is partial.
	Capped bool
}

// walkProjectLicences reads every dependency file seclicense has a reader
// for, under root.
func walkProjectLicences(ctx context.Context, root string) licenceWalk {
	var w licenceWalk
	visited, read, bytes := 0, 0, 0
	stop := errors.New("stop")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			w.Capped = true
			return stop
		}
		if d.IsDir() {
			if p != root && licenceSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		visited++
		if visited > licenceMaxVisited {
			w.Capped = true
			return stop
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if _, ok := seclicense.ReaderFor(rel); !ok {
			return nil
		}
		if read >= licenceMaxRead || bytes >= licenceMaxBytes {
			w.Capped = true
			return stop
		}
		f, err := os.Open(p) //nolint:gosec // G304: a dependency file inside the project; only read and parsed.
		if err != nil {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, seclicense.MaxFileBytes+1))
		_ = f.Close()
		if err != nil || len(data) > seclicense.MaxFileBytes {
			return nil
		}
		read++
		bytes += len(data)
		w.Files = append(w.Files, rel)
		w.Entries = append(w.Entries, seclicense.Read(rel, data)...)
		return nil
	})
	return w
}

// licenceKey keys an entry like the SBOM's packages.
func licenceKey(eco, name, version string) string { return eco + "\x00" + name + "\x00" + version }

// projectLicenceMap returns the licences known for a project's inventory,
// keyed eco\x00name\x00version.
func projectLicenceMap(root string, snap secinventory.Snapshot) map[string][]string {
	if len(snap.Packages) == 0 {
		return nil
	}
	w := walkProjectLicences(context.Background(), root)
	out := map[string][]string{}
	for _, e := range w.Entries {
		if e.License == "" {
			continue
		}
		k := licenceKey(e.Ecosystem, e.Name, e.Version)
		if !slices.Contains(out[k], e.License) {
			out[k] = append(out[k], e.License)
		}
	}
	return out
}

// licencePolicy is the node's policy from [security.licenses].
func licencePolicy(cfg config.Config) seclicense.Policy {
	l := cfg.Security.Licenses
	return seclicense.Policy{Deny: l.Deny, Allow: l.Allow, Unknown: l.Unknown}
}

// recordProjectLicences evaluates the policy over a walk and records the
// run. A capped walk is unknown and closes nothing; a complete one closes
// the licence findings of the files it read (when there are at most 256 of
// them, the store's per-close cap; more closes nothing).
func recordProjectLicences(ctx context.Context, st secsvc.RunStore, root string, p seclicense.Policy, w licenceWalk, now time.Time) (int, error) {
	findings := seclicense.ProjectFindings(secposture.ProjectRootHash(root), p, w.Entries, now)
	cov := secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: len(w.Files)}
	if len(findings) > 0 {
		cov.Outcome = secscan.OutcomeFindings
	}
	gone := secsvc.Gone{}
	if w.Capped {
		cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "walk_capped"
	} else if len(w.Files) <= 256 {
		gone = secsvc.Gone{Pack: seclicense.Driver, Paths: w.Files}
	}
	res := secscan.Result{Findings: findings, Coverage: cov, Engine: secscan.EngineIdentity{Name: seclicense.Driver, Version: seclicense.Version, RulePackVersion: seclicense.Version}}
	return secsvc.RecordRun(ctx, st, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}, res, now, 0, gone, securityRT.notify)
}

// licenceAfterScan runs after a dependency scan stored its inventory:
// with a policy set it records the project's licence findings; with none
// it does nothing.
func (e *depsScanEnv) licenceAfterScan(root string) {
	p := licencePolicy(e.cfg)
	if !p.Active() || e.st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := recordProjectLicences(ctx, e.st, root, p, walkProjectLicences(ctx, root), time.Now()); err != nil && e.logger != nil {
		e.logger.Warn("security: the licence findings could not be recorded", "err", err)
	}
}

func newSecurityLicensesCmd() *cobra.Command {
	var project string
	var asJSON, record bool
	c := &cobra.Command{
		Use:   "licenses",
		Short: "List the licences a project's dependencies declare, checked against [security.licenses] (local only)",
		Long: "Reads the licence fields of the project's lockfiles and installed package metadata (package-lock.json,\n" +
			"node_modules/*/package.json, composer.lock, *.dist-info/METADATA, vendor/*/Cargo.toml), normalizes them\n" +
			"to SPDX, and checks them against the [security.licenses] policy (deny, allow, unknown). Nothing is sent\n" +
			"anywhere. --record stores the policy's findings (flag only, medium at most).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := securityProjectRoot(project)
			if err != nil {
				return err
			}
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			p := licencePolicy(e.cfg)
			w := walkProjectLicences(cmd.Context(), root)
			if record {
				if !p.Active() {
					return errors.New("no licence policy is set: add deny, allow or unknown = \"flag\" under [security.licenses]")
				}
				if _, err := recordProjectLicences(cmd.Context(), e.st, root, p, w, time.Now()); err != nil {
					return err
				}
			}
			return printLicences(cmd.OutOrStdout(), p, w, asJSON, record)
		},
	}
	c.Flags().StringVar(&project, "project", "", "project directory (default: the git root of the working directory)")
	c.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	c.Flags().BoolVar(&record, "record", false, "store the policy's findings against the project")
	return c
}

// licenceRowView is one dependency's licence as printed.
type licenceRowView struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	License   string `json:"license"`
	Class     string `json:"class"`
	Path      string `json:"path"`
	Rule      string `json:"policy_rule,omitempty"`
}

func printLicences(w io.Writer, p seclicense.Policy, walk licenceWalk, asJSON, recorded bool) error {
	rows := make([]licenceRowView, 0, len(walk.Entries))
	classes := map[string]int{}
	for _, e := range walk.Entries {
		r := licenceRowView{Ecosystem: e.Ecosystem, Name: e.Name, Version: e.Version, License: e.License, Class: string(seclicense.Classify(e.License)), Path: e.Path}
		if v, ok := seclicense.Evaluate(p, e); ok && p.Active() {
			r.Rule = v.RuleID
		}
		classes[r.Class]++
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Ecosystem != rows[j].Ecosystem {
			return rows[i].Ecosystem < rows[j].Ecosystem
		}
		return rows[i].Name < rows[j].Name
	})
	if asJSON {
		return writeSecurityJSON(w, map[string]any{"packages": rows, "classes": classes, "files_read": len(walk.Files), "capped": walk.Capped, "policy_active": p.Active(), "recorded": recorded})
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "No declared licence found: Observer reads lockfile licence fields and installed package metadata; install the dependencies, or check that a lockfile with licence fields is committed.")
		return nil
	}
	for _, r := range rows {
		mark := ""
		if r.Rule != "" {
			mark = "  <- " + r.Rule
		}
		lic := r.License
		if lic == "" {
			lic = "(none declared)"
		}
		fmt.Fprintf(w, "%-10s %s@%s  %s [%s]%s\n", r.Ecosystem, r.Name, r.Version, lic, r.Class, mark)
	}
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, c)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, c := range names {
		parts = append(parts, fmt.Sprintf("%s %d", c, classes[c]))
	}
	fmt.Fprintf(w, "\n%d packages from %d files: %s.\n", len(rows), len(walk.Files), strings.Join(parts, ", "))
	if walk.Capped {
		fmt.Fprintln(w, "The walk stopped at a cap: some dependency files were not read.")
	}
	if !p.Active() {
		fmt.Fprintln(w, "No licence policy is set ([security.licenses] deny, allow, unknown): nothing is flagged or stored.")
	}
	return nil
}
