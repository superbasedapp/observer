package actionlint

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	upstream "github.com/marmutapp/superbased-observer/internal/thirdparty/actionlint"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// DriverID is the registry id; the component is "security.scan." + DriverID.
const DriverID = "actionlint"

// ComponentID is the catalog row that owns the driver.
const ComponentID = "security.scan." + DriverID

// PinnedVersion is the reviewed actionlint module version (go.mod); the
// compatibility test fails when the build carries another.
const PinnedVersion = "v1.7.12"

// RulePack is the pack findings are recorded under (closure is keyed by it).
const RulePack = "actionlint"

// MaxFindings caps the findings one run keeps.
const MaxFindings = 1000

// lintName is the name every workflow is linted under: actionlint's own
// stdin sentinel. Linter.Lint skips its os.Stat and its project lookup for
// exactly this name, so no folder on any OS is ever read for an
// actionlint.yaml or local actions (a path such as
// /__observer__/.github/workflows/ci.yml resolves to C:\__observer__ on
// Windows, a folder any local user can create, audit finding 7). The
// project-relative path travels separately, in File.Rel.
const lintName = "<stdin>"

// lintPath is the path one workflow is linted under: lintName whatever rel
// is, so no rel, absolute or relative, on any OS, can name a directory.
func lintPath(rel string) string {
	_ = rel
	return lintName
}

// File is one workflow file the caller read whole.
type File struct {
	// Rel is project-relative and slash-separated.
	Rel     string
	Content []byte
}

// Problem is one actionlint error, reduced to what a finding keeps.
type Problem struct {
	Kind string
	Line int
}

// newLinter returns a linter with every external command off: Shellcheck
// and Pyflakes empty (the rules are not created), no config file, no log,
// no colour writer. WorkingDir is set only so NewLinter does not call
// os.Getwd; with no project (lintName) actionlint never resolves a path
// against it.
func newLinter() (*upstream.Linter, error) {
	return upstream.NewLinter(io.Discard, &upstream.LinterOptions{
		Shellcheck: "",
		Pyflakes:   "",
		WorkingDir: ".",
	})
}

// Lint lints one workflow's bytes, never a file (lintPath). A library panic is caught and returned
// as an error (the file then counts as not scanned).
func Lint(rel string, content []byte) (ps []Problem, err error) {
	defer func() {
		if r := recover(); r != nil {
			ps, err = nil, fmt.Errorf("actionlint: panic linting %s", rel)
		}
	}()
	l, err := newLinter()
	if err != nil {
		return nil, fmt.Errorf("actionlint: %w", err)
	}
	errs, err := l.Lint(lintPath(rel), content, nil)
	if err != nil {
		return nil, fmt.Errorf("actionlint: %w", err)
	}
	for _, e := range errs {
		if e == nil {
			continue
		}
		ps = append(ps, Problem{Kind: e.Kind, Line: e.Line})
	}
	return ps, nil
}

// canary is the self-test workflow: one undefined context in an
// expression, which actionlint must report as kind "expression".
const canary = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ observer_canary_undefined.x }}\n"

// SelfTest reports whether the linked engine reports the canary's known
// error. Without it no run is clean.
func SelfTest() bool {
	ps, err := Lint(".github/workflows/observer-canary.yml", []byte(canary))
	if err != nil {
		return false
	}
	for _, p := range ps {
		if p.Kind == "expression" {
			return true
		}
	}
	return false
}

// validKind is the rule-id charset for an actionlint kind.
func validKind(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// IsWorkflowPath reports whether rel is a workflow the driver reads:
// directly under .github/workflows with a .yml or .yaml extension.
func IsWorkflowPath(rel string) bool {
	dir, base := path.Split(rel)
	ext := strings.ToLower(path.Ext(base))
	return dir == ".github/workflows/" && (ext == ".yml" || ext == ".yaml") && base != ext
}

// Input is one run.
type Input struct {
	ProjectRootHash string
	Scope           secfinding.Scope
	Files           []File
	// Skipped are the workflow files the caller could not read whole.
	Skipped []secscan.Skip
}

// Run lints every file and maps the problems onto findings. The run is
// clean only when the self-test passed, every file was linted and nothing
// was skipped or cut.
func Run(in Input) secscan.Result {
	row, _ := secscan.Adapter(DriverID)
	res := secscan.Result{Engine: secscan.EngineIdentity{Name: DriverID, Version: PinnedVersion}}
	cov := secscan.Coverage{Skipped: append([]secscan.Skip(nil), in.Skipped...)}
	selfTest := SelfTest()
	if !selfTest {
		cov.Notes = append(cov.Notes, "The linked actionlint self-test did not report its canary error, so no run is shown clean.")
	}
	for _, f := range in.Files {
		if !IsWorkflowPath(f.Rel) {
			cov.Skipped = append(cov.Skipped, secscan.Skip{Path: f.Rel, Reason: "not_a_workflow"})
			continue
		}
		ps, err := Lint(f.Rel, f.Content)
		if err != nil {
			cov.Skipped = append(cov.Skipped, secscan.Skip{Path: f.Rel, Reason: "lint_failed"})
			continue
		}
		cov.FilesScanned++
		cov.Scanned = append(cov.Scanned, f.Rel)
		occur := map[string]int{}
		for _, p := range ps {
			if len(res.Findings) >= MaxFindings {
				cov.Truncated = true
				break
			}
			if !validKind(p.Kind) {
				cov.Skipped = append(cov.Skipped, secscan.Skip{Path: f.Rel, Reason: "bad_rule_id"})
				continue
			}
			id := DriverID + "/" + p.Kind
			n := occur[id]
			occur[id] = n + 1
			res.Findings = append(res.Findings, secfinding.Normalize(secfinding.Finding{
				LocalKey: secfinding.LocalKey(in.ProjectRootHash, id, secfinding.TextIdentity(fmt.Sprintf("path:%s#%d", f.Rel, n))),
				Location: secfinding.Location{RelPath: f.Rel, StartLine: p.Line, EndLine: p.Line},
				Rule:     secfinding.Rule{ID: id, Pack: RulePack},
				Engine:   secfinding.Engine{Driver: DriverID, DriverVersion: PinnedVersion},
				Category: row.Category, Severity: row.Default, Confidence: row.Confidence,
				Scope: in.Scope, Project: secfinding.Project{RootHash: in.ProjectRootHash},
				Message:  "Reported by actionlint rule " + p.Kind,
				Baseline: policy.FindingBaselineUnknown, Status: policy.FindingStatusOpen,
			}))
		}
	}
	switch {
	case len(res.Findings) > 0:
		cov.Outcome = secscan.OutcomeFindings
	case cov.FilesScanned == 0 && len(cov.Skipped) == 0:
		cov.Outcome, cov.Reason = secscan.OutcomeNotScanned, "no_workflows"
	case selfTest && len(cov.Skipped) == 0 && !cov.Truncated:
		cov.Outcome = secscan.OutcomeClean
	default:
		cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "no_self_test"
		if len(cov.Skipped) > 0 || cov.Truncated {
			cov.Reason = "results_refused"
		}
	}
	res.Coverage = cov
	return res
}

// Reader returns the workflow files of a checkout (read whole under the
// CI rule caps) and the ones it could not read.
type Reader func(ctx context.Context, checkout string) ([]File, []secscan.Skip, error)

// Driver is the registry driver.
type Driver struct {
	Read     Reader
	RootHash func(root string) string
}

// Row is the registry row (section 4.4).
func (Driver) Row() secscan.DriverRow { return Row() }

// Row is the driver's registry row.
func Row() secscan.DriverRow {
	return secscan.DriverRow{
		ID: DriverID, Kind: secscan.KindLinked, ComponentID: ComponentID,
		Categories:      []secfinding.Category{policy.FindingCIConfig},
		Triggers:        []secfinding.Scope{policy.FindingScopeManual},
		Offline:         secscan.Offline{NoNetwork: true},
		MinVersion:      PinnedVersion,
		TestedRange:     PinnedVersion,
		SemanticAdapter: DriverID,
		ConfigInputs:    []string{"none: no .github/actionlint.yaml is read; shellcheck and pyflakes off"},
		Licence:         "MIT (github.com/rhysd/actionlint), linked; shellcheck (GPL-3.0) and pyflakes never bundled or started",
	}
}

// Probe answers without scanning: linked, so always installed when built.
func (Driver) Probe(context.Context) secscan.Probe {
	return secscan.Probe{Installed: true, Version: PinnedVersion, Verified: SelfTest(), Platform: secscan.SupportSupported}
}

// Scan reads the checkout's workflows and lints them.
func (d Driver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	if d.Read == nil || d.RootHash == nil {
		return secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: "not_wired"}}, nil
	}
	checkout := t.CheckoutRoot
	if checkout == "" {
		checkout = t.ProjectRoot
	}
	files, skipped, err := d.Read(ctx, checkout)
	if err != nil {
		return secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: "unreadable_checkout"}}, err
	}
	return Run(Input{ProjectRootHash: d.RootHash(t.ProjectRoot), Scope: t.Scope, Files: files, Skipped: skipped}), nil
}
