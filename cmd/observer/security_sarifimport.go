//go:build !sbo_omit_security && !sbo_omit_security_scan_sarif_import

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/sarifimport"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_sarifimport.go is the cmd seam of `security.scan.sarif-import`
// (security pillar plan sections 4.4 and 4.5.3 "In", lane SEC-G5): ONE
// function, importSARIFFile, reads one SARIF file the developer names and
// records it, and `observer security import-sarif` is its CLI. Observer
// never runs the producing tool and never watches a folder. The component
// is opt-in (securityOptIn) and needs security.code.

// sarifImportComponent is the catalog id.
const sarifImportComponent = sarifimport.ComponentID

// sarifImportSelected is the optional-module predicate with the opt-in rule.
func sarifImportSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, sarifImportComponent) && securitySelected(snap, "security.code")
}

var errSARIFImportNotSelected = fmt.Errorf("the %s component is not selected: add it (and security.code) under [components] (observer components status)", sarifImportComponent)

// sarifImportLineageWindow is how far back the lineage lookup reads AI
// edits.
const sarifImportLineageWindow = 90 * 24 * time.Hour

// sarifImportReport is what one import reports (`--json`).
type sarifImportReport struct {
	Project     string         `json:"project_root_hash"`
	Tool        string         `json:"tool"`
	Outcome     string         `json:"outcome"`
	Reason      string         `json:"reason,omitempty"`
	Findings    int            `json:"findings"`
	New         int            `json:"new"`
	WithLineage int            `json:"with_lineage"`
	Refused     map[string]int `json:"refused,omitempty"`
	Truncated   bool           `json:"truncated,omitempty"`
}

// readSARIFFile reads one regular file, at most sarif.MaxBytes.
func readSARIFFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the developer names the file; it is only read and parsed.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, sarif.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > sarif.MaxBytes {
		return nil, fmt.Errorf("%s is over the %d MB SARIF cap", path, sarif.MaxBytes>>20)
	}
	return data, nil
}

// importSARIFFile is THE import seam (the CLI calls it; a dashboard upload
// would call it too): it maps data through the strict adapter, attaches
// inferred lineage, and records the findings as one manual run that
// closes nothing.
func importSARIFFile(ctx context.Context, st *store.Store, root, tool string, data []byte) (sarifImportReport, error) {
	hash := secposture.ProjectRootHash(root)
	res, err := sarifimport.Import(sarifimport.Input{
		Data: data, Tool: tool, ProjectRoot: root, ProjectRootHash: hash,
		Lineage: sarifImportLineage(ctx, st, root),
	})
	if err != nil {
		return sarifImportReport{}, sarifInputError{err}
	}
	rep := sarifImportReport{
		Project: hash, Tool: tool, Outcome: string(res.Coverage.Outcome), Reason: res.Coverage.Reason,
		Findings: len(res.Findings), Truncated: res.Coverage.Truncated,
	}
	for _, f := range res.Findings {
		if f.Lineage.SessionID != "" {
			rep.WithLineage++
		}
	}
	for _, s := range res.Coverage.Skipped {
		if rep.Refused == nil {
			rep.Refused = map[string]int{}
		}
		rep.Refused[s.Reason]++
	}
	// An import closes nothing (an empty Gone): Observer did not run the
	// tool, so a finding missing from the file proves nothing gone.
	started := time.Now()
	created, err := secsvc.RecordRun(ctx, st, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}, res, started, 0, secsvc.Gone{}, nil)
	rep.New = created
	return rep, err
}

// sarifInputError is an import the file itself refused: its text is the
// adapter's, and the dashboard upload answers it 400
// (dashapi.ErrSARIFImportInput) where a store error answers 500.
type sarifInputError struct{ err error }

func (e sarifInputError) Error() string { return e.err.Error() }
func (e sarifInputError) Unwrap() error { return e.err }

// Is matches dashapi.ErrSARIFImportInput.
func (e sarifInputError) Is(target error) bool { return target == dashapi.ErrSARIFImportInput }

// sarifImportDash is the dashboard seam of the SARIF upload (lane SEC-P4
// decision 13): the CLI's own picker and file cap, and importSARIFFile.
// Nil without a database.
func sarifImportDash(database *sql.DB) *dashapi.SARIFImport {
	if database == nil {
		return nil
	}
	tools := make([]dashapi.SARIFImportTool, 0, len(sarifimport.Tools))
	for _, t := range sarifimport.Tools {
		tools = append(tools, dashapi.SARIFImportTool{ID: t.ID, Label: t.Label})
	}
	return &dashapi.SARIFImport{
		Tools: tools, MaxBytes: sarif.MaxBytes,
		Import: func(ctx context.Context, root, tool string, data []byte) (any, error) {
			if !sarifimport.KnownTool(tool) {
				return nil, sarifInputError{fmt.Errorf("tool %q is not one of: %s", tool, sarifImportToolIDs())}
			}
			return importSARIFFile(ctx, store.New(database), root, tool, data)
		},
	}
}

// sarifImportLineage returns the lineage lookup for root: a result's path
// matched to the latest AI edit of that path in the project's sessions
// (file_changes, by internal/loc.PathHash), with the latest prompt of that
// session before the edit. The match is by file, not by line
// (file_changes keeps no line ranges), and is an inference: it says an AI
// edit touched the file last, never that the AI wrote the reported line.
// A store error yields no lineage.
func sarifImportLineage(ctx context.Context, st *store.Store, root string) sarifimport.LineageFunc {
	pid, err := st.ProjectIDForRoot(ctx, root)
	if err != nil || pid == 0 {
		return nil
	}
	until := time.Now().Add(time.Minute)
	since := until.Add(-sarifImportLineageWindow)
	edits, _, err := st.LoadProjectAIEdits(ctx, pid, since, until, 0)
	if err != nil || len(edits) == 0 {
		return nil
	}
	prompts, _, _ := st.LoadProjectPrompts(ctx, pid, since, until, 5000)
	latest := map[string]secfinding.Lineage{}
	for _, e := range edits { // newest first: the first per path is the latest
		if _, seen := latest[e.PathHash]; seen || e.PathHash == "" {
			continue
		}
		lin := secfinding.Lineage{SessionID: e.SessionID, ActionID: strconv.FormatInt(e.ActionID, 10)}
		for _, p := range prompts { // newest first
			if p.SessionID == e.SessionID && !p.At.After(e.At) {
				lin.PromptActionID, lin.Tool = strconv.FormatInt(p.ActionID, 10), p.Tool
				break
			}
		}
		latest[e.PathHash] = lin
	}
	return func(rel string) (secfinding.Lineage, bool) {
		l, ok := latest[loc.PathHash(root, rel)]
		return l, ok
	}
}

// sarifImportProjectRoot resolves dir to a project the store knows.
func sarifImportProjectRoot(ctx context.Context, st *store.Store, dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	root, ok := git.FindRoot(abs)
	if !ok {
		return "", fmt.Errorf("%s is not inside a git repository", abs)
	}
	roots, err := st.ProjectRoots(ctx)
	if err != nil {
		return "", err
	}
	if !slices.Contains(roots, root) {
		return "", fmt.Errorf("%s is not a project Observer knows (open it with an AI tool Observer watches first)", root)
	}
	return root, nil
}

func sarifImportToolIDs() string {
	ids := make([]string, 0, len(sarifimport.Tools))
	for _, t := range sarifimport.Tools {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ", ")
}

// securitySARIFImportSubcommands is `observer security import-sarif`.
func securitySARIFImportSubcommands() []*cobra.Command {
	var configPath, tool, project string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "import-sarif FILE",
		Short: "Import one SARIF file your own scanner wrote (component security.scan.sarif-import; opt-in)",
		Long: "Reads ONE SARIF 2.1.0 file that a tool you ran yourself produced (CodeQL, gosec, Bandit,\n" +
			"Semgrep, the Claude Security or Codex Security plugin) and records its results as\n" +
			"flag-only findings on the project. Observer never runs the tool. Locations must lie\n" +
			"inside the project; anything else is refused and counted. Each finding carries an\n" +
			"inferred lineage (the latest AI edit of that file), never a claim of authorship. An\n" +
			"import never shows a project clean and closes no finding. Opt-in: add\n" +
			"security.scan.sarif-import and security.code under [components].",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !sarifImportSelected(componentSnapshotFor(configPath)) {
				return errSARIFImportNotSelected
			}
			if !sarifimport.KnownTool(tool) {
				return fmt.Errorf("--tool %q is not one of: %s", tool, sarifImportToolIDs())
			}
			data, err := readSARIFFile(args[0])
			if err != nil {
				return err
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			root, err := sarifImportProjectRoot(cmd.Context(), st, project)
			if err != nil {
				return err
			}
			rep, err := importSARIFFile(cmd.Context(), st, root, tool, data)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "imported %d finding(s) from %s (%d new, %d with an inferred AI-edit lineage); outcome %s", rep.Findings, tool, rep.New, rep.WithLineage, rep.Outcome)
			if rep.Reason != "" {
				_, _ = fmt.Fprintf(out, " (%s)", rep.Reason)
			}
			_, _ = fmt.Fprintln(out)
			for _, r := range sarifRefusedKeys(rep.Refused) {
				_, _ = fmt.Fprintf(out, "  refused %d result(s): %s\n", rep.Refused[r], r)
			}
			if rep.Truncated {
				_, _ = fmt.Fprintln(out, "  the file held more results than the cap; the rest were not imported")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&tool, "tool", "", "the tool that wrote the file: "+sarifImportToolIDs())
	cmd.Flags().StringVar(&project, "project", ".", "a directory inside the project the file describes")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	_ = cmd.MarkFlagRequired("tool")
	return []*cobra.Command{cmd}
}

func sarifRefusedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// securitySARIFImportDoctorCheck is the doctor's one line: it starts and
// reads nothing.
func securitySARIFImportDoctorCheck(_ context.Context, configPath string) diag.Check {
	c := diag.Check{Name: sarifImportComponent, Status: diag.StatusOK}
	if !sarifImportSelected(componentSnapshotFor(configPath)) {
		c.Message = "SARIF import: not selected (opt-in; add security.scan.sarif-import and security.code under [components])"
		return c
	}
	c.Message = "SARIF import: selected; reads only a file you name (observer security import-sarif FILE --tool ...); never runs a tool, never watches a folder"
	return c
}
