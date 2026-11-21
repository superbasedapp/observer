//go:build !sbo_omit_security

package dashboard

import (
	"fmt"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail/projectfs"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// security_depdetail.go is the dependency block of the Code security
// finding drawer (GET /api/security/findings/{id}): the package and
// version a vulnerable_dependency finding names, where its lockfile holds
// it (a scrubbed line window read from the project root), what the
// lockfile says about the relationship, the advisories the LOCAL OSV
// database holds for it and the smallest fixed version. The composition is
// the pure internal/secdepdetail; this file owns the lockfile read, and
// security_depdetail_osv.go the record read.
//
// Advisory prose (an OSV record's summary and details) is third-party
// text read here at VIEW time into this one local response only: it is
// never written into a sec_findings row, an MCP result, the Explain prompt
// or the org push wire. No record is fetched from the network: one the
// local database does not hold reads "not_in_local_database".

// maxDependencyLockfileBytes caps the lockfile read (a large monorepo
// package-lock.json is tens of MB); beyond it the location reads
// file_too_large.
const maxDependencyLockfileBytes = 32 << 20

// securityDependencyJS is the drawer's dependency block. The frontend
// codes against these field names exactly; every empty field is omitted
// except location.found.
type securityDependencyJS struct {
	Ecosystem        string                  `json:"ecosystem"`
	Name             string                  `json:"name"`
	Version          string                  `json:"version"`
	Relationship     string                  `json:"relationship,omitempty"`
	Scope            string                  `json:"scope,omitempty"`
	IntroducedBy     []string                `json:"introduced_by,omitempty"`
	Location         securityDepLocationJS   `json:"location"`
	FixedVersions    []string                `json:"fixed_versions,omitempty"`
	SuggestedVersion string                  `json:"suggested_version,omitempty"`
	AdvisorySource   string                  `json:"advisory_source"`
	Advisories       []securityDepAdvisoryJS `json:"advisories,omitempty"`
}

type securityDepLocationJS struct {
	RelPath   string                 `json:"rel_path,omitempty"`
	Found     bool                   `json:"found"`
	Reason    string                 `json:"reason,omitempty"`
	StartLine int                    `json:"start_line,omitempty"`
	EndLine   int                    `json:"end_line,omitempty"`
	Context   []securityDepContextJS `json:"context,omitempty"`
}

type securityDepContextJS struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Match bool   `json:"match"`
}

type securityDepAdvisoryJS struct {
	ID               string               `json:"id"`
	Aliases          []string             `json:"aliases,omitempty"`
	Summary          string               `json:"summary,omitempty"`
	Details          string               `json:"details,omitempty"`
	DetailsTruncated bool                 `json:"details_truncated,omitempty"`
	Published        string               `json:"published,omitempty"`
	Modified         string               `json:"modified,omitempty"`
	CWE              []string             `json:"cwe,omitempty"`
	CVSS             []string             `json:"cvss,omitempty"`
	References       []securityDepRefJS   `json:"references,omitempty"`
	Ranges           []securityDepRangeJS `json:"ranges,omitempty"`
	AffectedSymbols  []string             `json:"affected_symbols,omitempty"`
}

type securityDepRefJS struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

type securityDepRangeJS struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// depLineScrubber scrubs every shown lockfile line (a lockfile can carry a
// registry token in a resolved URL); built once.
var depLineScrubber = sync.OnceValue(scrub.New)

// securityDependencyPackage is the "name@version" and ecosystem a list row
// shows: only for a dependency finding, from its dependency evidence (the
// store returns no other category's evidence).
func securityDependencyPackage(f secfinding.Finding, evidence string) (pkg, eco string) {
	p, ok := secdepdetail.ParsePackage(string(f.Category), evidence)
	if !ok {
		return "", ""
	}
	return p.String(), p.Ecosystem
}

// securityDependencyDetail builds the drawer's dependency block of a
// dependency finding (nil for any other finding, or one whose evidence
// names no package). root is the project's root path ("" when the
// projects row is gone: the location is then unreadable).
func securityDependencyDetail(f secfinding.Finding, evidence, root string, lookup func(eco, id string) ([]byte, error)) *securityDependencyJS {
	if f.Category != policy.FindingVulnerableDependency {
		return nil
	}
	in := secdepdetail.Input{
		Category: string(f.Category), Evidence: evidence, RuleID: f.Rule.ID, Message: f.Message,
		RelPath: f.Location.RelPath, LookupRecord: lookup,
		CleanLine: func(s string) string { return depLineScrubber().String(s) },
	}
	if root != "" {
		in.ReadFile = func(rel string) ([]byte, error) { return readProjectFile(root, rel, maxDependencyLockfileBytes) }
	}
	d, ok := secdepdetail.Build(in)
	if !ok {
		return nil
	}
	return securityDependencyJSOf(d)
}

// securityDependencyFixHint is the drawer's fix hint when one upgrade is
// clear.
func securityDependencyFixHint(d *securityDependencyJS) string {
	return fmt.Sprintf("Upgrade %s from %s to %s or later, then regenerate the lockfile.", d.Name, d.Version, d.SuggestedVersion)
}

func securityDependencyJSOf(d secdepdetail.Detail) *securityDependencyJS {
	out := &securityDependencyJS{
		Ecosystem: d.Ecosystem, Name: d.Name, Version: d.Version,
		Relationship: d.Relationship.Relationship, Scope: d.Scope, IntroducedBy: d.IntroducedBy,
		Location: securityDepLocationJS{
			RelPath: d.Location.RelPath, Found: d.Location.Found, Reason: d.Location.Reason,
			StartLine: d.Location.StartLine, EndLine: d.Location.EndLine,
		},
		FixedVersions: d.FixedVersions, SuggestedVersion: d.SuggestedVersion, AdvisorySource: d.AdvisorySource,
	}
	for _, l := range d.Location.Context {
		out.Location.Context = append(out.Location.Context, securityDepContextJS{Line: l.Number, Text: l.Text, Match: l.Match})
	}
	for _, a := range d.Advisories {
		js := securityDepAdvisoryJS{
			ID: a.ID, Aliases: a.Aliases, Summary: a.Summary, Details: a.Details, DetailsTruncated: a.DetailsTruncated,
			Published: a.Published, Modified: a.Modified, CWE: a.CWE, CVSS: a.CVSS, AffectedSymbols: a.AffectedSymbols,
		}
		for _, r := range a.References {
			js.References = append(js.References, securityDepRefJS{Type: r.Type, URL: r.URL})
		}
		for _, r := range a.Ranges {
			js.Ranges = append(js.Ranges, securityDepRangeJS{Introduced: r.Introduced, Fixed: r.Fixed, LastAffected: r.LastAffected})
		}
		out.Advisories = append(out.Advisories, js)
	}
	return out
}

// readProjectFile reads a project-relative file under root, at most max
// bytes, through projectfs.Read (the one contained read the MCP tool and
// `explain --fix` use too): a path outside the root is
// secdepdetail.ErrOutsideProject, a larger file secdepdetail.ErrFileTooLarge.
func readProjectFile(root, rel string, max int64) ([]byte, error) {
	return projectfs.Read(root, rel, max)
}
