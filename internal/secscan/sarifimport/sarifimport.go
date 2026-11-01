package sarifimport

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// DriverID is the registry id; the component is "security.scan." + DriverID.
const DriverID = "sarif-import"

// ComponentID is the catalog row that owns the driver.
const ComponentID = "security.scan." + DriverID

// LineageMethod names the lineage inference on each finding.
const LineageMethod = "sarifimport.lineage.v1"

// Tool is one row of the closed producer picker (`--tool`): the id is the
// rule-id prefix of every finding the file carries, so two tools' rules
// never share an id.
type Tool struct {
	ID    string
	Label string
}

// Tools is THE producer picker. A tool not listed imports as "other".
var Tools = []Tool{
	{ID: "codeql", Label: "CodeQL (installed by you)"},
	{ID: "gosec", Label: "gosec"},
	{ID: "bandit", Label: "Bandit"},
	{ID: "semgrep", Label: "Semgrep (your own rules or subscription)"},
	{ID: "claude-security", Label: "Claude Security plugin"},
	{ID: "codex-security", Label: "Codex Security plugin"},
	{ID: "other", Label: "Another tool that writes SARIF"},
}

// KnownTool reports whether id is in the picker.
func KnownTool(id string) bool {
	return slices.ContainsFunc(Tools, func(t Tool) bool { return t.ID == id })
}

// ErrUnknownTool is returned for a tool id outside the picker.
var ErrUnknownTool = errors.New("sarifimport: unknown tool (see the picker)")

// LineageFunc returns the lineage of the latest AI edit of rel (a
// project-relative, slash-separated path) in the project's sessions, and
// whether there is one.
type LineageFunc func(rel string) (secfinding.Lineage, bool)

// Input is one import.
type Input struct {
	// Data is the SARIF file's bytes (at most sarif.MaxBytes; the decoder
	// refuses more).
	Data []byte
	// Tool is a picker id.
	Tool            string
	ProjectRoot     string
	ProjectRootHash string
	// Lineage may be nil: no lineage is attached.
	Lineage LineageFunc
}

// rootBaseIDs are the uriBaseId values read as the project root; any other
// is refused (the file's own originalUriBaseIds are never read: they could
// redirect a location anywhere).
var rootBaseIDs = []string{"%SRCROOT%", "SRCROOT", "PROJECTROOT"}

// maxLine bounds a reported line number.
const maxLine = 10_000_000

// maxURI bounds a reported URI.
const maxURI = 1024

// StrictLocation is the import's location rule (the strictest default,
// section 4.5.3): it returns the project-relative path, or the closed
// reason the location was refused.
func StrictLocation(uri, baseID, root string) (string, string) {
	switch {
	case uri == "":
		return "", "empty_uri"
	case len(uri) > maxURI:
		return "", "uri_too_long"
	case strings.ContainsRune(uri, '\\'):
		return "", "backslash"
	case strings.ContainsAny(uri, "?#"):
		return "", "query_or_fragment"
	case strings.IndexFunc(uri, unicode.IsControl) >= 0:
		return "", "control_character"
	}
	file := strings.HasPrefix(strings.ToLower(uri), "file:")
	if baseID != "" && (file || !slices.Contains(rootBaseIDs, baseID)) {
		return "", "foreign_base_id"
	}
	if !file {
		if i := strings.Index(uri, ":"); i > 0 && !strings.Contains(uri[:i], "/") {
			return "", "remote_uri"
		}
		if strings.HasPrefix(uri, "/") {
			return "", "absolute_without_scheme"
		}
	}
	rel, why := secscan.NormalizeLocation(uri, root)
	if why != secscan.LocOK {
		return "", string(why)
	}
	if strings.IndexFunc(rel, unicode.IsControl) >= 0 {
		return "", "control_character"
	}
	return rel, ""
}

// Import maps one SARIF file onto findings (never decides an outcome
// beyond the coverage rules): every finding is flag-only (low confidence,
// unknown baseline), refused results are counted as skips, an empty file
// is unknown and nothing an import reports is ever "clean".
func Import(in Input) (secscan.Result, error) {
	if !KnownTool(in.Tool) {
		return secscan.Result{}, ErrUnknownTool
	}
	if in.ProjectRoot == "" || in.ProjectRootHash == "" {
		return secscan.Result{}, errors.New("sarifimport: no project root")
	}
	log, err := sarif.Decode(in.Data)
	if err != nil {
		return secscan.Result{}, fmt.Errorf("sarifimport: %w", err)
	}
	row, _ := secscan.Adapter(DriverID)
	res := secscan.Result{Engine: secscan.EngineIdentity{Name: DriverID, Version: in.Tool}}
	var skipped []secscan.Skip
	truncated := false
	results := 0
	files := map[string]bool{}
	for _, run := range log.Runs {
		results += len(run.Results) + run.Dropped
		kept := sarif.Run{Tool: run.Tool, Dropped: run.Dropped, RulesDropped: run.RulesDropped}
		for _, r := range run.Results {
			id := r.RuleID
			if id == "" && r.RuleIndex >= 0 && r.RuleIndex < len(run.Tool.Rules) {
				id = run.Tool.Rules[r.RuleIndex].ID
			}
			if id == "" {
				skipped = append(skipped, secscan.Skip{Reason: "bad_rule_id"})
				continue
			}
			if len(r.Locations) == 0 {
				skipped = append(skipped, secscan.Skip{Reason: "no_location"})
				continue
			}
			l := r.Locations[0]
			if _, why := StrictLocation(l.URI, l.URIBaseID, in.ProjectRoot); why != "" {
				skipped = append(skipped, secscan.Skip{Reason: why})
				continue
			}
			sl, el := l.StartLine, l.EndLine
			if el == 0 {
				el = sl
			}
			if sl < 0 || sl > maxLine || el < sl || el > maxLine {
				skipped = append(skipped, secscan.Skip{Reason: "line_out_of_range"})
				continue
			}
			r.RuleID, r.RuleIndex = in.Tool+"/"+id, -1
			r.Locations = []sarif.Location{{URI: l.URI, StartLine: sl, EndLine: el}}
			kept.Results = append(kept.Results, r)
		}
		fs, cov := secscan.Adapt(row, kept, secscan.AdaptOptions{
			ProjectRoot: in.ProjectRoot, ProjectRootHash: in.ProjectRootHash, Scope: policy.FindingScopeManual,
			Engine: res.Engine,
		})
		skipped = append(skipped, cov.Skipped...)
		truncated = truncated || cov.Truncated
		for _, f := range fs {
			if len(res.Findings) >= row.MaxResults {
				truncated = true
				break
			}
			f.Rule.Pack = DriverID
			f.Message = "Imported from " + in.Tool + " SARIF, rule " + f.Rule.ID
			// The lineage match is by file, not by line: an AI edit of the
			// file says nothing about who wrote the flagged line, so the
			// class stays unknown and the org rollup never counts an import
			// as agent-introduced (audit finding 3). The lineage is attached
			// for the reader to follow.
			f.Attribution = secfinding.InferredAttribution{Class: policy.FindingAttributionUnknown, Method: LineageMethod, Confidence: policy.FindingConfidenceLow}
			if in.Lineage != nil {
				if lin, ok := in.Lineage(f.Location.RelPath); ok {
					f.Lineage = lin
				}
			}
			files[f.Location.RelPath] = true
			res.Findings = append(res.Findings, secfinding.Normalize(f))
		}
	}
	res.Coverage = secscan.Coverage{Skipped: skipped, Truncated: truncated, FilesScanned: len(files)}
	switch {
	case len(res.Findings) > 0:
		res.Coverage.Outcome = secscan.OutcomeFindings
	case results == 0:
		// An empty file proves nothing: the tool may not have run, may have
		// scanned nothing, or may have been pointed elsewhere.
		res.Coverage.Outcome, res.Coverage.Reason = secscan.OutcomeUnknown, "empty_import"
	default:
		res.Coverage.Outcome, res.Coverage.Reason = secscan.OutcomeUnknown, "results_refused"
	}
	res.Coverage.Notes = []string{"Imported from a SARIF file the developer named; Observer did not run " + in.Tool + ", so an import never shows a project clean and closes no finding."}
	return res, nil
}

// Source returns the bytes of the file one import reads.
type Source func(ctx context.Context) ([]byte, error)

// Driver is the registry driver over one import: Scan reads Source once.
type Driver struct {
	Tool    string
	Source  Source
	Lineage LineageFunc
	// RootHash maps a project root to its hash (secposture.ProjectRootHash).
	RootHash func(root string) string
}

// Row is the registry row (section 4.4).
func (Driver) Row() secscan.DriverRow { return Row() }

// Row is the driver's registry row.
func Row() secscan.DriverRow {
	return secscan.DriverRow{
		ID: DriverID, Kind: secscan.KindSARIFImport, ComponentID: ComponentID,
		Categories:      []secfinding.Category{policy.FindingCodeVuln},
		Triggers:        []secfinding.Scope{policy.FindingScopeManual},
		Offline:         secscan.Offline{NoNetwork: true},
		SemanticAdapter: DriverID,
		Licence:         "the producing tool's licence is the developer's; Observer reads its output file only",
	}
}

// Probe always answers installed: there is no engine, only a file.
func (Driver) Probe(context.Context) secscan.Probe {
	return secscan.Probe{Installed: true, Verified: true, Platform: secscan.SupportSupported}
}

// Scan reads the file and imports it against t.ProjectRoot.
func (d Driver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	if d.Source == nil || d.RootHash == nil {
		return secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: "no_file"}}, nil
	}
	data, err := d.Source(ctx)
	if err != nil {
		return secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: "unreadable_file"}}, err
	}
	return Import(Input{Data: data, Tool: d.Tool, ProjectRoot: t.ProjectRoot, ProjectRootHash: d.RootHash(t.ProjectRoot), Lineage: d.Lineage})
}
