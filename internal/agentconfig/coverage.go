package agentconfig

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// CoverageStatus says where a registry tool's catalogue stands.
type CoverageStatus string

// The closed CoverageStatus vocabulary.
const (
	// CoverageGenerated: rows generated from a pinned vendor schema plus
	// the hand-written overlay (phase P1).
	CoverageGenerated CoverageStatus = "generated"
	// CoverageAuthored: no published schema; every row is doc-authored
	// (catalog_<tool>.go, phase P2), each with its Source, and live
	// key-name evidence where a host had the tool installed.
	CoverageAuthored CoverageStatus = "authored"
	// CoveragePending: no published schema; the rows are doc-authored by
	// a phase P2 lane (plan section 8, P2a-d). Honest, not a gap in the
	// table: Coverage() reports zero rows for it.
	CoveragePending CoverageStatus = "pending"
	// CoverageNoSurface: the tool has no local settings or instruction
	// file to edit (plan section 2.1 "honest zero").
	CoverageNoSurface CoverageStatus = "no_surface"
)

// pendingTools are registry tools with neither a generated nor a
// doc-authored catalogue yet (tool -> reason). Empty since the surface-gap
// lane w4-catalog authored the 2026-10-21 wave: a new registry row without a
// catalogue must be listed here with its reason
// (TestEveryToolHasRowsOrHonestZero), naming the settings file a later lane
// would author (never a secret-bearing one).
var pendingTools = map[string]string{}

// noSurfaceTools have nothing local to edit (audit section 1).
var noSurfaceTools = map[string]string{
	"chatgpt-web":    "Browser chat: settings live in the vendor's web account.",
	"claude-web":     "Browser chat: settings live in the vendor's web account.",
	"perplexity-web": "Browser chat: settings live in the vendor's web account.",
	"gemini-web":     "Browser chat: settings live in the vendor's web account.",
	"copilot-web":    "Browser chat: settings live in the vendor's web account.",
	"grokbot":        "Grok Bot desktop: settings are server-side (vendor admin), nothing local to edit.",
}

// ToolCoverage is one registry tool's catalogue coverage.
type ToolCoverage struct {
	Tool            string         `json:"tool"`
	Status          CoverageStatus `json:"status"`
	Rows            int            `json:"rows"`
	Verified        int            `json:"verified"` // rows not marked unverified
	Writable        int            `json:"writable"`
	Secret          int            `json:"secret"`
	Dangerous       int            `json:"dangerous"`
	Deprecated      int            `json:"deprecated"`
	VerifiedAgainst string         `json:"verified_against,omitempty"`
	Note            string         `json:"note,omitempty"`
}

// Coverage reports every registry tool (integration.Tools()), sorted by
// tool id: rows, verified, writable, secret and dangerous counts.
func Coverage() []ToolCoverage {
	verifiedAgainst := map[string]string{}
	for _, tc := range toolCatalogs {
		verifiedAgainst[tc.Tool] = tc.VerifiedAgainst
	}
	counts := map[string]*ToolCoverage{}
	for _, r := range Catalog() {
		c := counts[r.Tool]
		if c == nil {
			c = &ToolCoverage{Tool: r.Tool}
			counts[r.Tool] = c
		}
		c.Rows++
		if r.Verified != VerifiedUnverified {
			c.Verified++
		}
		if r.Writable {
			c.Writable++
		}
		if r.Secret {
			c.Secret++
		}
		if r.Danger != DangerNone {
			c.Dangerous++
		}
		if r.Deprecated {
			c.Deprecated++
		}
	}
	var out []ToolCoverage
	for _, tool := range integration.Tools() {
		c := ToolCoverage{Tool: tool}
		if x := counts[tool]; x != nil {
			c = *x
		}
		switch {
		case generatedRows[tool] != nil:
			c.Status = CoverageGenerated
			c.VerifiedAgainst = verifiedAgainst[tool]
		case verifiedAgainst[tool] != "":
			c.Status = CoverageAuthored
			c.VerifiedAgainst = verifiedAgainst[tool]
		case noSurfaceTools[tool] != "":
			c.Status, c.Note = CoverageNoSurface, noSurfaceTools[tool]
		default:
			c.Status, c.Note = CoveragePending, pendingTools[tool]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}
