//go:build !sbo_omit_security && !sbo_omit_security_scan_actionlint

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/actionlint"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_actionlint.go is the cmd seam of `security.scan.actionlint`
// (security pillar plan sections 4.4, 5.6 and 8.7, lane SEC-G5): the
// linked actionlint over a project's .github/workflows/*.y*ml, read
// through os.Root under the CI rule caps, recorded as one run. It starts
// no process (internal/secscan/actionlint). The component is opt-in
// (securityOptIn), needs security.code and is compiled only in the
// managed and full distros.

const actionlintComponent = actionlint.ComponentID

// actionlintMaxFiles caps the workflow files one run reads.
const actionlintMaxFiles = 200

// actionlintSelected is the optional-module predicate with the opt-in rule.
func actionlintSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, actionlintComponent) && securitySelected(snap, "security.code")
}

var errActionlintNotSelected = fmt.Errorf("the %s component is not selected: add it (and security.code) under [components] (observer components status)", actionlintComponent)

// readWorkflowFiles reads checkout/.github/workflows/*.y*ml through
// os.Root: regular files only (a symlink is skipped), each at most
// secciwf.MaxWorkflowBytes, at most actionlintMaxFiles. A missing
// directory is no files.
func readWorkflowFiles(_ context.Context, checkout string) ([]actionlint.File, []secscan.Skip, error) {
	r, err := os.OpenRoot(checkout)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = r.Close() }()
	const dir = ".github/workflows"
	entries, err := fs.ReadDir(r.FS(), dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var files []actionlint.File
	var skipped []secscan.Skip
	for _, e := range entries {
		rel := path.Join(dir, e.Name())
		if !actionlint.IsWorkflowPath(rel) {
			continue
		}
		if !e.Type().IsRegular() {
			skipped = append(skipped, secscan.Skip{Path: rel, Reason: "not_a_regular_file"})
			continue
		}
		if len(files) >= actionlintMaxFiles {
			skipped = append(skipped, secscan.Skip{Path: rel, Reason: "file_cap"})
			continue
		}
		b, err := readCapped(r, rel, secciwf.MaxWorkflowBytes)
		if err != nil {
			skipped = append(skipped, secscan.Skip{Path: rel, Reason: err.Error()})
			continue
		}
		files = append(files, actionlint.File{Rel: rel, Content: b})
	}
	return files, skipped, nil
}

// readCapped reads one file under r whole, or names why not.
func readCapped(r *os.Root, rel string, limit int) ([]byte, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, errors.New("unreadable")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	switch {
	case err != nil:
		return nil, errors.New("unreadable")
	case len(b) > limit:
		return nil, errors.New("too_large")
	}
	return b, nil
}

// actionlintReport is what one run reports (`--json`).
type actionlintReport struct {
	Project  string   `json:"project_root_hash"`
	Outcome  string   `json:"outcome"`
	Reason   string   `json:"reason,omitempty"`
	Files    int      `json:"files"`
	Findings int      `json:"findings"`
	New      int      `json:"new"`
	Skipped  []string `json:"skipped,omitempty"`
	// LinkedWorktree: the run read a linked worktree; it closed nothing.
	LinkedWorktree bool `json:"linked_worktree,omitempty"`
}

// runActionlint is THE run seam: it lints root's (or its linked
// worktree's) workflows and records one run. A complete run in the main
// checkout closes the actionlint findings at the files it read that it
// did not report again; a linked worktree closes nothing (P-041).
func runActionlint(ctx context.Context, st *store.Store, root, checkout string) (actionlintReport, error) {
	d := actionlint.Driver{Read: readWorkflowFiles, RootHash: secposture.ProjectRootHash}
	t := secscan.Target{ProjectRoot: root, CheckoutRoot: checkout, Scope: policy.FindingScopeManual}
	started := time.Now()
	res, err := d.Scan(ctx, t)
	if err != nil {
		return actionlintReport{}, err
	}
	linked := checkout != "" && filepath.Clean(checkout) != filepath.Clean(root)
	gone := secsvc.Gone{Pack: actionlint.RulePack, Paths: res.Coverage.Scanned}
	if linked {
		gone = secsvc.Gone{}
	}
	rep := actionlintReport{
		Project: secposture.ProjectRootHash(root), Outcome: string(res.Coverage.Outcome), Reason: res.Coverage.Reason,
		Files: res.Coverage.FilesScanned, Findings: len(res.Findings), LinkedWorktree: linked,
	}
	for _, s := range res.Coverage.Skipped {
		rep.Skipped = append(rep.Skipped, s.Path+": "+s.Reason)
	}
	if res.Coverage.Outcome == secscan.OutcomeNotScanned {
		return rep, nil
	}
	rep.New, err = secsvc.RecordRun(ctx, st, t, res, started, time.Since(started), gone, nil)
	return rep, err
}

// securityActionlintSubcommands is `observer security actionlint`.
func securityActionlintSubcommands() []*cobra.Command {
	var configPath, project string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "actionlint",
		Short: "Lint a project's GitHub Actions workflows with the linked actionlint (component security.scan.actionlint; opt-in)",
		Long: "Lints .github/workflows/*.yml and *.yaml with actionlint " + actionlint.PinnedVersion + " (MIT), linked into\n" +
			"Observer. Its shellcheck and pyflakes integrations are off: no process starts and no\n" +
			"repository actionlint config is read. Findings are flag only. Opt-in: add\n" +
			"security.scan.actionlint and security.code under [components] (managed and full builds).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !actionlintSelected(componentSnapshotFor(configPath)) {
				return errActionlintNotSelected
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			root, checkout, err := securityKnownProjectRoot(cmd.Context(), st, project)
			if err != nil {
				return err
			}
			rep, err := runActionlint(cmd.Context(), st, root, checkout)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "actionlint: %d workflow file(s), %d finding(s) (%d new); outcome %s", rep.Files, rep.Findings, rep.New, rep.Outcome)
			if rep.Reason != "" {
				_, _ = fmt.Fprintf(out, " (%s)", rep.Reason)
			}
			_, _ = fmt.Fprintln(out)
			for _, s := range rep.Skipped {
				_, _ = fmt.Fprintf(out, "  not scanned: %s\n", s)
			}
			if rep.LinkedWorktree {
				_, _ = fmt.Fprintln(out, "  read a linked worktree: findings are recorded on the project and nothing was closed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&project, "project", ".", "a directory inside the project")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return []*cobra.Command{cmd}
}

// securityActionlintDoctorCheck is the doctor's one line: it starts and
// reads nothing.
func securityActionlintDoctorCheck(_ context.Context, configPath string) diag.Check {
	c := diag.Check{Name: actionlintComponent, Status: diag.StatusOK}
	if !actionlintSelected(componentSnapshotFor(configPath)) {
		c.Message = "actionlint: not selected (opt-in; add security.scan.actionlint and security.code under [components])"
		return c
	}
	c.Message = "actionlint " + actionlint.PinnedVersion + ": selected, linked; shellcheck and pyflakes off, starts no process (observer security actionlint)"
	return c
}
