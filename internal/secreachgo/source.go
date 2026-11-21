package secreachgo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// source.go is the pure core of the source-mode symbol check, 3b-src (plan
// section 14.5 item 3b, spike RG-0 "Answer" item 2): osv-scanner's Go call
// analysis (--call-analysis=go, which runs govulncheck over the module's
// source with the project's own Go toolchain) once per go.mod. This file
// reads what one such run printed and decides it through the same table as
// binary mode (secreach.DecideSymbol); the run itself, the isolation and
// the store are the cmd layer's.
//
// osv-scanner's own reading is never used as is (RG-0): its "called" is
// module level and it reports a package-only record as called through the
// package's init. Observer reads the record's affected entry itself
// (ParseRecord): a record that lists no symbols gets no claim, and a
// record that lists a package without symbols gets no claim either, since
// osv-scanner's answer does not say which listed package the trace
// reached.

// SourceGroup is one advisory group osv-scanner reported against one Go
// package of the go.mod: the package (a module path, or "stdlib") and its
// version, the group's ids and aliases, and the call analysis per id (true
// called, false not called; an id with no entry was not analysed).
type SourceGroup struct {
	Module, Version string
	IDs             []string
	Aliases         []string
	Analysis        map[string]bool
}

// scannerOutput is the part of osv-scanner's JSON ParseScannerOutput reads.
type scannerOutput struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Groups []struct {
				IDs      []string `json:"ids"`
				Aliases  []string `json:"aliases"`
				Analysis map[string]struct {
					Called bool `json:"called"`
				} `json:"experimental_analysis"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ParseScannerOutput reads osv-scanner's --format json output of one go.mod
// run into its Go advisory groups, sorted by module, version and first id.
// Packages of any other ecosystem are left out.
func ParseScannerOutput(stdout []byte) ([]SourceGroup, error) {
	var out scannerOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		return nil, fmt.Errorf("secreachgo.ParseScannerOutput: %w", err)
	}
	var groups []SourceGroup
	for _, r := range out.Results {
		for _, p := range r.Packages {
			if p.Package.Ecosystem != "Go" || p.Package.Name == "" {
				continue
			}
			for _, g := range p.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				sg := SourceGroup{
					Module: p.Package.Name, Version: p.Package.Version,
					IDs: append([]string(nil), g.IDs...), Aliases: append([]string(nil), g.Aliases...),
				}
				if len(g.Analysis) > 0 {
					sg.Analysis = make(map[string]bool, len(g.Analysis))
					for id, a := range g.Analysis {
						sg.Analysis[id] = a.Called
					}
				}
				groups = append(groups, sg)
			}
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.IDs[0] < b.IDs[0]
	})
	return groups, nil
}

// SourceInput is one go.mod's check.
type SourceInput struct {
	// Groups are osv-scanner's groups for the go.mod (ParseScannerOutput).
	Groups []SourceGroup
	// Records are the OSV records read for the groups' ids (ParseRecord);
	// an id with no record adds nothing.
	Records map[string]RecordImports
}

// SourceVerdicts decides every group of one go.mod run and returns one
// record per id and alias of each group that has a claim (called or not
// called), sorted by module, version and id. A member record that lists no
// imports for the module adds nothing; a group combines its members
// through combineRows, as binary mode does. A standard library record
// carries the Go release the run evaluated it at (AssumedGo: the version
// osv-scanner read from the go.mod, its toolchain line else its go line).
func SourceVerdicts(in SourceInput) []secreach.SymbolRecord {
	var out []secreach.SymbolRecord
	for _, g := range in.Groups {
		var vs []memberVerdict
		for _, id := range g.IDs {
			rec, ok := in.Records[id]
			if !ok {
				continue
			}
			mi, ok := rec.Modules[g.Module]
			if !ok || len(mi.Packages) == 0 {
				continue
			}
			vs = append(vs, memberVerdict{verdict: secreach.DecideSymbol(sourceFacts(g, id, mi))})
		}
		v, _ := combine(vs)
		if v == secreach.VerdictNone {
			continue
		}
		assumed := ""
		if g.Module == "stdlib" {
			assumed = g.Version
		}
		seen := map[string]bool{}
		for _, id := range append(append([]string(nil), g.IDs...), g.Aliases...) {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, secreach.SymbolRecord{ID: id, Module: g.Module, Version: g.Version, Verdict: v, AssumedGo: assumed})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ID < b.ID
	})
	return out
}

// sourceFacts builds one member record's facts from osv-scanner's
// analysis. A "called" answer counts as a symbol-level trace only when every
// package the record lists for the module lists symbols: osv-scanner's
// answer is per module, so with a whole-package entry beside them the
// trace may be that package's init (RG-0 G1 f5), and no claim is made.
func sourceFacts(g SourceGroup, id string, mi ModuleImports) secreach.SymbolFacts {
	f := secreach.SymbolFacts{ListsImports: true}
	for _, p := range mi.Packages {
		if len(p.Symbols) > 0 {
			f.ListsSymbols = true
		} else {
			f.PackageWithoutSymbols = true
		}
	}
	called, analysed := g.Analysis[id]
	f.Analysed = analysed
	f.SymbolTrace = analysed && called && !f.PackageWithoutSymbols
	return f
}

// RunFacts are what the cmd layer observed of one go.mod run.
type RunFacts struct {
	// TimedOut: the run passed its wall cap and was killed.
	TimedOut bool
	// Killed: the program died of a signal the runner did not send. Under
	// the run's memory cap that is the kernel's OOM killer.
	Killed bool
	// Capped: the run passed its output or task cap and was killed.
	Capped bool
	// Exited: the program exited with one of its result codes (0 or 1).
	Exited bool
	// Stderr is the program's stderr (osv-scanner's log at info level).
	Stderr string
}

// The fixed lines osv-scanner v2.6 (internal/sourceanalysis/go.go) logs
// when the call analysis did not run, and the toolchain's own words for
// the failures the run's environment makes certain.
const (
	lineSkippedNoGo     = "Skipping call analysis on Go code since Go is not installed"
	lineAnalysisFailed  = "Failed to run code analysis"
	lineRequiresNewerGo = "requires go >="
)

// oomWords, modulesMissingWords: what a run that ran out of memory, or
// needed a module the cache lacks, prints (the Go runtime, the go command
// under GOPROXY=off and GOFLAGS=-mod=readonly).
var (
	oomWords            = []string{"out of memory", "cannot allocate memory", "signal: killed"}
	modulesMissingWords = []string{"GOPROXY=off", "module lookup disabled", "missing go.sum entry", "no required module provides", "cannot find module providing", "updates to go.mod needed"}
)

// runFacts adds what runRules read beyond RunFacts: whether the run or its
// call analysis failed.
type runFacts struct {
	RunFacts
	failed bool
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// runRule is one row of the run table.
type runRule struct {
	Name   string
	When   func(runFacts) bool
	Reason secreach.Reason
}

// runRules is walked top-down (one test case per row in source_test.go):
// the first row that holds names why the run decided nothing, "" for a run
// whose answers stand.
var runRules = []runRule{
	{Name: "timed out", When: func(f runFacts) bool { return f.TimedOut }, Reason: secreach.ReasonTimedOut},
	{Name: "killed under the memory cap", When: func(f runFacts) bool { return f.Killed }, Reason: secreach.ReasonOutOfMemory},
	{Name: "output or task cap", When: func(f runFacts) bool { return f.Capped }, Reason: secreach.ReasonSymbolCheckFailed},
	// osv-scanner found no `go` and skipped the analysis while exiting as
	// if it had run: every group would read "not analysed".
	{Name: "no toolchain", When: func(f runFacts) bool { return strings.Contains(f.Stderr, lineSkippedNoGo) }, Reason: secreach.ReasonNoToolchain},
	{Name: "ran", When: func(f runFacts) bool { return !f.failed }, Reason: ""},
	{Name: "out of memory", When: func(f runFacts) bool { return containsAny(f.Stderr, oomWords) }, Reason: secreach.ReasonOutOfMemory},
	{Name: "toolchain too old", When: func(f runFacts) bool { return strings.Contains(f.Stderr, lineRequiresNewerGo) }, Reason: secreach.ReasonToolchainTooOld},
	{Name: "modules missing", When: func(f runFacts) bool { return containsAny(f.Stderr, modulesMissingWords) }, Reason: secreach.ReasonModulesMissing},
	{Name: "failed", When: func(runFacts) bool { return true }, Reason: secreach.ReasonSymbolCheckFailed},
}

// ClassifyRun says why one go.mod run decided nothing, or "" when its
// answers stand. A run failed when it did not exit with a result code, or
// osv-scanner logged that the call analysis failed (it then prints its
// results without any analysis, which must never read "not called").
func ClassifyRun(f RunFacts) secreach.Reason {
	rf := runFacts{RunFacts: f, failed: !f.Exited || strings.Contains(f.Stderr, lineAnalysisFailed)}
	for _, r := range runRules {
		if r.When(rf) {
			return r.Reason
		}
	}
	return secreach.ReasonSymbolCheckFailed
}

// GoModIDs returns the advisory ids of the groups (ids and aliases), each
// once and sorted, for reading their records.
func GoModIDs(groups []SourceGroup) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, id := range append(append([]string(nil), g.IDs...), g.Aliases...) {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
