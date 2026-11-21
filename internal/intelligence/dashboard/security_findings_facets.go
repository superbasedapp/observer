//go:build !sbo_omit_security

package dashboard

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_findings_facets.go serves the Code security Findings tab's
// filter counts and grouped rows (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.4):
// GET /api/security/findings/facets and GET /api/security/findings/groups,
// both over the same filters as the list (securityFindingsFilter) and the
// store's one WHERE builder. Read-only. A group names a dependency
// finding's package (public), never any other category's evidence: the
// store reads the evidence of dependency findings only.

// securityFacetJS is one value of a facet and how many findings choosing
// it would show.
type securityFacetJS struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// securityFindingsFacetsJS is GET /api/security/findings/facets: the total
// the whole filter selects, and per facet each value's count with every
// filter but that facet's own applied. Every facet key is present, an
// empty array when nothing matches.
type securityFindingsFacetsJS struct {
	Total  int                          `json:"total"`
	Facets map[string][]securityFacetJS `json:"facets"`
}

// handleSecurityFindingsFacets serves GET
// /api/security/findings/facets?<the list's filters>.
func (s *Server) handleSecurityFindingsFacets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := securityFindingsFilter(r.URL.Query())
	st := store.New(s.db())
	total, err := st.CountSecFindings(ctx, filter)
	if err != nil {
		http.Error(w, "load facets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	facets, err := st.SecFindingFacets(ctx, filter)
	if err != nil {
		http.Error(w, "load facets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := securityFindingsFacetsJS{Total: total, Facets: map[string][]securityFacetJS{}}
	for _, name := range store.SecFacetNames() {
		vals := make([]securityFacetJS, 0, len(facets[name]))
		for _, v := range facets[name] {
			vals = append(vals, securityFacetJS{Value: v.Value, Count: v.Count})
		}
		resp.Facets[name] = vals
	}
	writeJSON(w, resp)
}

// securityFindingGroupJS is one row of GET /api/security/findings/groups.
// Only the key fields its grouping uses are set: an issue group its rule
// and either its package (a dependency finding) or its path, a package
// group its ecosystem and package, a rule group its rule, a project group
// its project.
type securityFindingGroupJS struct {
	Key             string `json:"key"`
	RuleID          string `json:"rule_id,omitempty"`
	Category        string `json:"category,omitempty"`
	Ecosystem       string `json:"ecosystem,omitempty"`
	Package         string `json:"package,omitempty"`
	RelPath         string `json:"rel_path,omitempty"`
	ProjectRootHash string `json:"project_root_hash,omitempty"`
	// Message is one representative message of the group's findings (the
	// smallest, so a reload shows the same one); absent on a project group.
	Message     string `json:"message,omitempty"`
	Count       int    `json:"count"`
	Projects    int    `json:"projects"`
	MaxSeverity string `json:"max_severity"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// securityFindingGroupsJS is GET /api/security/findings/groups. BySeverity
// counts every group the filter makes (not the page) by its worst
// severity.
type securityFindingGroupsJS struct {
	By         string                   `json:"by"`
	Groups     []securityFindingGroupJS `json:"groups"`
	Total      int                      `json:"total"`
	Page       int                      `json:"page"`
	Limit      int                      `json:"limit"`
	BySeverity map[string]int           `json:"by_severity"`
}

// handleSecurityFindingsGroups serves GET
// /api/security/findings/groups?by=<issue|package|rule|project, default
// issue>&<the list's filters>&page=<1-based>&limit=<n, default 50, at most
// 200>&sort=<severity|count|last_seen>&dir=<desc|asc>. The default order
// is the worst severity first, then the most findings, then the key. Any
// other grouping is a 400.
func (s *Server) handleSecurityFindingsGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	by := q.Get("by")
	if by == "" {
		by = store.SecGroupIssue
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = store.SecGroupDefaultLimit
	}
	if limit > store.SecGroupMaxLimit {
		limit = store.SecGroupMaxLimit
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	got, err := store.New(s.db()).SecFindingGroups(r.Context(), securityFindingsFilter(q), store.SecGroupQuery{
		By: by, Sort: q.Get("sort"), Desc: q.Get("dir") != "asc", Limit: limit, Offset: (page - 1) * limit,
	})
	if errors.Is(err, store.ErrSecGroupBy) {
		http.Error(w, "unknown grouping: by is one of issue, package, rule, project", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "load groups: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := securityFindingGroupsJS{
		By: by, Groups: make([]securityFindingGroupJS, 0, len(got.Groups)), Total: got.Total,
		Page: page, Limit: limit, BySeverity: got.BySeverity,
	}
	if resp.BySeverity == nil {
		resp.BySeverity = map[string]int{}
	}
	for _, g := range got.Groups {
		resp.Groups = append(resp.Groups, securityFindingGroupJSOf(by, g))
	}
	writeJSON(w, resp)
}

// securityGroupKeySep separates the parts of an issue group's key.
const securityGroupKeySep = "|"

// securityFindingGroupJSOf is one group as the page shows it.
func securityFindingGroupJSOf(by string, g store.SecFindingGroup) securityFindingGroupJS {
	js := securityFindingGroupJS{
		RuleID: g.RuleID, Category: g.Category, Message: g.Message, Count: g.Count, Projects: g.Projects,
		MaxSeverity: g.MaxSeverity, FirstSeen: g.FirstSeen.UTC().Format(time.RFC3339), LastSeen: g.LastSeen.UTC().Format(time.RFC3339),
	}
	if g.Dependency {
		// The evidence of a dependency group is its public package
		// coordinate; a coordinate that does not parse shows neither part.
		if pkg, ok := secdepdetail.ParsePackage(string(policy.FindingVulnerableDependency), g.Evidence); ok {
			js.Ecosystem, js.Package = pkg.Ecosystem, pkg.Name+"@"+pkg.Version
		}
	}
	switch by {
	case store.SecGroupIssue:
		if g.Dependency {
			js.Key = g.RuleID + securityGroupKeySep + "package" + securityGroupKeySep + g.Evidence
		} else {
			js.RelPath = g.RelPath
			js.Key = g.RuleID + securityGroupKeySep + "path" + securityGroupKeySep + g.RelPath
		}
	case store.SecGroupPackage:
		js.Key = g.Evidence
	case store.SecGroupRule:
		js.Key = g.RuleID
	case store.SecGroupProject:
		js.Key, js.ProjectRootHash = g.ProjectRootHash, g.ProjectRootHash
		js.Category, js.Message = "", ""
	}
	return js
}
