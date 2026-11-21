package secmcp

import (
	"context"
	"math"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// enrich.go is the per-finding enrichment of get_security_findings
// (os-and-ci plan section 14.8): the dependency fields read at VIEW time
// from secdepdetail, and the three extension points other lanes fill (reach,
// kev, epss). Everything here is a version, an enum, a boolean, a date or a
// number; advisory prose (an OSV summary or details) is never read into an
// MCP result (secdepdetail's rule).

// KEV is a finding's CISA Known Exploited Vulnerabilities state, filled by
// an Enricher (the lead wires the data; this package computes nothing).
type KEV struct {
	// Listed is true when an advisory of the finding is on the KEV list.
	Listed bool `json:"listed"`
	// DateAdded is the day it was added, YYYY-MM-DD; "" when unknown.
	DateAdded string `json:"date_added,omitempty"`
}

// Enrichment is what an Enricher adds to one finding. The zero value adds
// nothing.
type Enrichment struct {
	// Reach is the reachability tier (a short lowercase token such as
	// "reachable" or "imported"); "" when none was computed. A value that
	// is not a short [a-z0-9_-] token is dropped.
	Reach string
	// KEV is the exploited-in-the-wild state; nil when not known.
	KEV *KEV
	// EPSS is the exploit-prediction score in [0,1]; nil when not known.
	EPSS *float64
}

// EnrichInput is what an Enricher is given for one finding.
type EnrichInput struct {
	// Finding is the open finding.
	Finding secfinding.Finding
	// Root is the project root the finding is listed under.
	Root string
	// Dependency is the package a dependency finding names; nil for any
	// other finding.
	Dependency *secdepdetail.Package
	// AdvisoryIDs are the advisory ids the finding names (CVE and GHSA
	// ids from its rule id and templated message), for a KEV or EPSS
	// lookup; empty for a non-dependency finding.
	AdvisoryIDs []string
}

// Enricher is the injected provider of reach, kev and epss (nil: absent).
// It is called once per listed finding, must not block on the network and
// must not return advisory prose; its output is validated before it
// reaches the answer.
type Enricher func(ctx context.Context, in EnrichInput) Enrichment

// maxReachBytes caps a reach tier token.
const maxReachBytes = 32

// cleanEnrichment drops anything an Enricher returned that is not the
// declared shape, so a provider cannot put free text into an MCP result.
func cleanEnrichment(e Enrichment) Enrichment {
	out := Enrichment{}
	if validReach(e.Reach) {
		out.Reach = e.Reach
	}
	if e.KEV != nil {
		k := KEV{Listed: e.KEV.Listed}
		if _, err := time.Parse("2006-01-02", e.KEV.DateAdded); err == nil {
			k.DateAdded = e.KEV.DateAdded
		}
		out.KEV = &k
	}
	if e.EPSS != nil && !math.IsNaN(*e.EPSS) && *e.EPSS >= 0 && *e.EPSS <= 1 {
		v := *e.EPSS
		out.EPSS = &v
	}
	return out
}

func validReach(s string) bool {
	if s == "" || len(s) > maxReachBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// depSource is the dependency-detail reads of one answer, memoized so a
// project with many findings in one lockfile reads it once.
type depSource struct {
	d     Deps
	root  string
	files map[string]fileRes
	recs  map[string]fileRes
}

type fileRes struct {
	b   []byte
	err error
}

func newDepSource(d Deps, root string) *depSource {
	return &depSource{d: d, root: root, files: map[string]fileRes{}, recs: map[string]fileRes{}}
}

// depFields are the dependency fields of one finding.
type depFields struct {
	pkg         secdepdetail.Package
	fixed       string
	direct, dev *bool
	advisoryIDs []string
}

// fields reads a dependency finding's package, relationship and fix.
// ok is false for any other finding, or when the evidence names no package
// or cannot be read.
func (s *depSource) fields(ctx context.Context, f secfinding.Finding) (depFields, bool) {
	if s.d.Evidence == nil || f.Category != policy.FindingVulnerableDependency {
		return depFields{}, false
	}
	ev, err := s.d.Evidence(ctx, f.ID)
	if err != nil || ev == "" {
		return depFields{}, false
	}
	in := secdepdetail.Input{
		Category: string(f.Category), Evidence: ev, RuleID: f.Rule.ID, Message: f.Message, RelPath: f.Location.RelPath,
	}
	if s.d.ReadFile != nil {
		in.ReadFile = func(rel string) ([]byte, error) {
			r, ok := s.files[rel]
			if !ok {
				r.b, r.err = s.d.ReadFile(s.root, rel)
				s.files[rel] = r
			}
			return r.b, r.err
		}
	}
	if s.d.LookupRecord != nil {
		in.LookupRecord = func(eco, id string) ([]byte, error) {
			k := eco + "\x00" + id
			r, ok := s.recs[k]
			if !ok {
				r.b, r.err = s.d.LookupRecord(eco, id)
				s.recs[k] = r
			}
			return r.b, r.err
		}
	}
	d, ok := secdepdetail.Build(in)
	if !ok {
		return depFields{}, false
	}
	out := depFields{pkg: d.Package, fixed: d.SuggestedVersion, advisoryIDs: secdepdetail.AdvisoryIDs(f.Rule.ID, f.Message)}
	switch d.Relationship.Relationship {
	case secdepdetail.RelDirect:
		out.direct = boolPtr(true)
	case secdepdetail.RelTransitive:
		out.direct = boolPtr(false)
	}
	switch d.Scope {
	case secdepdetail.ScopeDev:
		out.dev = boolPtr(true)
	case secdepdetail.ScopeRuntime:
		out.dev = boolPtr(false)
	}
	return out, true
}

func boolPtr(b bool) *bool { return &b }
