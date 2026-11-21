//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/seclang"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security.go serves the security pillar's Phase A routes (security pillar
// plan sections 4.2 and 4.10): the Code security page's posture summary and
// its findings list. A feature-owned file: with sbo_omit_security the
// routes answer 404 component_not_installed (security_omit.go), and while
// the module is inactive the component guard answers it for them.
// securityProjectRow is one project's posture on GET /api/security/status.
//
// A row names its project: ProjectID is the projects row (the Projects
// page's `?project=<id>` detail), Name and RootPath the same name and root
// GET /api/projects serves the same viewers. Before 2026-11-02 a row
// carried only the 64-hex root hash, and the page printed its first 12
// characters, which read as a git commit id: the regression this naming
// fixes (TestSecurityStatusNamesProjects).
type securityProjectRow struct {
	ProjectRootHash string `json:"project_root_hash"`
	ProjectID       int64  `json:"project_id,omitempty"`
	Name            string `json:"name"`
	RootPath        string `json:"root_path,omitempty"`
	LastSessionAt   string `json:"last_session_at,omitempty"`
	// Active is a project the posture writer signs (a session within
	// secsvc.DefaultActiveWithin); an idle project is listed while the
	// store still holds findings or scan runs for it.
	Active   bool              `json:"active"`
	State    string            `json:"state"`
	Reason   string            `json:"reason"`
	Blocking int               `json:"blocking"`
	Open     int               `json:"open"`
	Counts   []securityCountJS `json:"counts"`
	// LastScanAt is the newest working-tree scan run (any driver), Runs
	// each driver's newest run.
	LastScanAt string          `json:"last_scan_at,omitempty"`
	Runs       []securityRunJS `json:"runs"`
}

type securityCountJS struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	N        int    `json:"n"`
}

// securityRunJS is one driver's newest scan run on a project.
type securityRunJS struct {
	Driver     string `json:"driver"`
	Scope      string `json:"scope"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
	Findings   int    `json:"findings"`
	StartedAt  string `json:"started_at"`
	DurationMS int64  `json:"duration_ms"`
}

// securityStatusResponse is GET /api/security/status.
type securityStatusResponse struct {
	Module   string               `json:"module"`
	Projects []securityProjectRow `json:"projects"`
}

// securityProjectIndex maps a root hash to its projects row (every path
// root the store holds).
func securityProjectIndex(ctx context.Context, st *store.Store) (map[string]store.SecProjectRef, error) {
	refs, err := st.SecProjectRefs(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]store.SecProjectRef, len(refs))
	for _, r := range refs {
		out[secposture.ProjectRootHash(r.Root)] = r
	}
	return out, nil
}

// securityProjectName is the name a project row shows: the projects row's
// own name, else the root's last element.
func securityProjectName(r store.SecProjectRef) string {
	if r.Name != "" {
		return r.Name
	}
	return filepath.Base(filepath.Clean(r.Root))
}

// handleSecurityStatus serves GET /api/security/status: every active
// project's derived posture state (what the hook would read now), plus
// every idle project the store still holds findings or scan runs for, each
// with its open finding counts and its newest scan runs.
func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resolved, _ := config.ResolveGlobalPath(s.opts.ConfigPath)
	layout := secposture.LayoutFor(resolved)
	gp := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	module := secposture.ModuleSignalFrom(gp.State, gp.Posture)
	st := store.New(s.db())
	now := time.Now()
	// The projects the posture writer signs (secsvc.WriteAll).
	roots, err := st.SecActiveProjectRoots(ctx, now.Add(-secsvc.DefaultActiveWithin))
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	held, err := st.SecProjects(ctx)
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := st.SecLatestDriverRuns(ctx, "")
	if err != nil {
		http.Error(w, "load scan runs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	runsBy := map[string][]store.SecDriverRun{}
	for _, run := range runs {
		runsBy[run.ProjectRootHash] = append(runsBy[run.ProjectRootHash], run)
	}
	resp := securityStatusResponse{Module: moduleSignalName(module), Projects: []securityProjectRow{}}
	seen := map[string]bool{}
	add := func(hash, root string, active bool) error {
		if seen[hash] {
			return nil
		}
		seen[hash] = true
		row := securityProjectRow{ProjectRootHash: hash, Active: active, Counts: []securityCountJS{}, Runs: []securityRunJS{}}
		if ref, ok := index[hash]; ok {
			row.ProjectID, row.Name, row.RootPath = ref.ID, securityProjectName(ref), ref.Root
			if !ref.LastSessionAt.IsZero() {
				row.LastSessionAt = ref.LastSessionAt.UTC().Format(time.RFC3339)
			}
			if root == "" {
				root = ref.Root
			}
		}
		if root != "" {
			rd := secposture.Load(layout, root, module, now, secposture.Versions{})
			row.State, row.Reason, row.Blocking = string(rd.State.Posture), string(rd.State.Reason), rd.State.Blocking
		} else {
			// A hash no stored project names (its project row is gone):
			// its findings stay listed, its posture is unknown.
			row.State, row.Reason = string(policy.SecurityPostureUnknown), "project_not_found"
		}
		counts, err := st.SecOpenCounts(ctx, hash)
		if err != nil {
			return err
		}
		for _, c := range counts {
			row.Counts = append(row.Counts, securityCountJS{Category: string(c.Category), Severity: string(c.Severity), N: c.N})
			row.Open += c.N
		}
		var last time.Time
		for _, run := range runsBy[hash] {
			row.Runs = append(row.Runs, securityRunJS{
				Driver: run.Driver, Scope: run.Scope, Outcome: run.Outcome, Reason: run.Reason, Findings: run.Findings,
				StartedAt: run.StartedAt.UTC().Format(time.RFC3339), DurationMS: run.Duration.Milliseconds(),
			})
			if run.StartedAt.After(last) {
				last = run.StartedAt
			}
		}
		if !last.IsZero() {
			row.LastScanAt = last.UTC().Format(time.RFC3339)
		}
		resp.Projects = append(resp.Projects, row)
		return nil
	}
	for _, root := range roots {
		if err := add(secposture.ProjectRootHash(root), root, true); err != nil {
			http.Error(w, "load counts: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for _, hash := range held {
		if err := add(hash, "", false); err != nil {
			http.Error(w, "load counts: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	sort.SliceStable(resp.Projects, func(i, j int) bool {
		a, b := resp.Projects[i], resp.Projects[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.RootPath < b.RootPath
	})
	writeJSON(w, resp)
}

func moduleSignalName(m secposture.ModuleSignal) string {
	switch m {
	case secposture.ModuleActive:
		return "active"
	case secposture.ModuleInactive:
		return "inactive"
	case secposture.ModuleUnverified:
		return "unverified"
	default:
		return "no_daemon"
	}
}

// securityFindingJS is one finding on GET /api/security/findings: the
// templated message and ids only, never evidence. SessionID is the session
// the finding is attributed to (the page links it to its session detail).
// Package ("name@version") and Ecosystem are set for a dependency finding
// only (vulnerable_dependency: a public package coordinate); no other
// category's evidence is ever read for a row (store.SecDependencyEvidence).
type securityFindingJS struct {
	ID              string `json:"id"`
	ProjectRootHash string `json:"project_root_hash"`
	RuleID          string `json:"rule_id"`
	Driver          string `json:"driver"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	Confidence      string `json:"confidence"`
	Scope           string `json:"scope"`
	Baseline        string `json:"baseline"`
	Status          string `json:"status"`
	RelPath         string `json:"rel_path"`
	StartLine       int    `json:"start_line"`
	Message         string `json:"message"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	SessionID       string `json:"session_id,omitempty"`
	Tool            string `json:"tool,omitempty"`
	Package         string `json:"package,omitempty"`
	Ecosystem       string `json:"ecosystem,omitempty"`
	// Language is the seclang id of a non-dependency finding's file ("go",
	// "yaml", "dockerfile"); empty for a dependency finding (it has an
	// ecosystem) and for a file no seclang row names.
	Language string `json:"language,omitempty"`
	// Reach and Exploit are a dependency finding's view-time ranking
	// signals (security_signals.go): the import-level reachability tier and
	// the KEV and EPSS labels. Labels only; they change nothing else.
	Reach   *securityReachJS   `json:"reach,omitempty"`
	Exploit *securityExploitJS `json:"exploit,omitempty"`
}

func securityFindingJSOf(f secfinding.Finding) securityFindingJS {
	js := securityFindingJS{
		ID: f.ID, ProjectRootHash: f.Project.RootHash, RuleID: f.Rule.ID, Driver: f.Engine.Driver,
		Category: string(f.Category), Severity: string(f.Severity), Confidence: string(f.Confidence),
		Scope: string(f.Scope), Baseline: string(f.Baseline), Status: string(f.Status),
		RelPath: f.Location.RelPath, StartLine: f.Location.StartLine, Message: f.Message,
		FirstSeen: f.FirstSeen.UTC().Format(time.RFC3339), LastSeen: f.LastSeen.UTC().Format(time.RFC3339),
		SessionID: f.Lineage.SessionID, Tool: f.Lineage.Tool,
	}
	if f.Category != policy.FindingVulnerableDependency {
		js.Language = seclang.Language(f.Location.RelPath)
	}
	return js
}

// The findings list's paging defaults (GET /api/security/findings).
const (
	securityFindingsDefaultLimit = 50
	securityFindingsMaxLimit     = 1000 // the store's own cap; the CSV export asks for 1000
)

// securityFindingsSorts maps the list's sort parameter onto the store's
// whitelisted sorts; anything else is the default (severity). "rank" is
// the store's severity order, then the ranking rule (securityFindingsRank).
var securityFindingsSorts = map[string]string{
	"severity":           store.SecSortSeverity,
	"last_seen":          store.SecSortLastSeen,
	"first_seen":         store.SecSortFirstSeen,
	securityFindingsRank: store.SecSortSeverity,
}

// securityFindingsRank is the sort that ranks dependency findings (plan
// section 14.7): KEV-listed first, then the reachability tier, then EPSS,
// then the severity order, among the places dependency findings hold. It
// ranks the first securityFindingsMaxLimit findings of the severity order
// (the store's cap); a page past them is in plain severity order.
const securityFindingsRank = "rank"

// securityFindingsPage is GET /api/security/findings.
type securityFindingsPage struct {
	Findings []securityFindingJS `json:"findings"`
	Total    int                 `json:"total"`
	Page     int                 `json:"page"`
	Limit    int                 `json:"limit"`
	// ReachPending: some dependency row's reachability is still being
	// worked out in the background (securityReachPending), so the page asks
	// again shortly for the final labels and order.
	ReachPending bool `json:"reach_pending,omitempty"`
}

// securityListParam is a comma-separated query parameter as its values
// (trimmed, empty ones dropped). The store drops repeats and caps the list
// (store.SecFilterMaxValues).
func securityListParam(q url.Values, name string) []string {
	var out []string
	for _, v := range strings.Split(q.Get(name), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// securityFindingsFilter is the findings filter a query names, shared by
// the list, its facets and its groups: the comma lists severity, category,
// driver, ecosystem, language, project (one root hash still works) and
// baseline; the exact rule (rule id), package ("name@version" of a
// dependency finding), path (project-relative) and status (empty is every
// status); and q, free text over rule, message, path and a dependency
// finding's package. Every value is a bound parameter in the store; paging
// and order are the caller's.
func securityFindingsFilter(q url.Values) store.SecFindingFilter {
	return store.SecFindingFilter{
		ProjectRootHashes: securityListParam(q, "project"),
		Status:            secfinding.Status(q.Get("status")),
		Severities:        securityListParam(q, "severity"),
		Categories:        securityListParam(q, "category"),
		Drivers:           securityListParam(q, "driver"),
		Ecosystems:        securityListParam(q, "ecosystem"),
		Languages:         securityListParam(q, "language"),
		Baselines:         securityListParam(q, "baseline"),
		RuleID:            strings.TrimSpace(q.Get("rule")),
		Package:           strings.TrimSpace(q.Get("package")),
		RelPath:           q.Get("path"),
		Query:             q.Get("q"),
	}
}

// handleSecurityFindings serves GET /api/security/findings
// (?<filters>&page=<1-based>&limit=<n, default 50, at most
// 1000>&sort=<severity|last_seen|first_seen|rank>&dir=<desc|asc>, the
// filters those of securityFindingsFilter): one page of findings and the
// total the filter selects. The default order is severity descending
// (critical first), then last_seen DESC, id. sort=rank is
// securityFindingsRank (dir is ignored: most urgent first). Every
// dependency row carries its reach tier and exploit labels, every other row
// its language.
func (s *Server) handleSecurityFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = securityFindingsDefaultLimit
	}
	if limit > securityFindingsMaxLimit {
		limit = securityFindingsMaxLimit
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	sortBy, ok := securityFindingsSorts[q.Get("sort")]
	if !ok {
		sortBy = store.SecSortSeverity
	}
	filter := securityFindingsFilter(q)
	filter.Limit, filter.Offset, filter.Sort, filter.Desc = limit, (page-1)*limit, sortBy, q.Get("dir") != "asc"
	// The rank orders the whole ranked window (the first
	// securityFindingsMaxLimit of the severity order), then pages it. A page
	// that straddles the window's end stops at it (the page's own size, 50,
	// divides the window, so it never does there).
	ranked := q.Get("sort") == securityFindingsRank && filter.Offset < securityFindingsMaxLimit
	if q.Get("sort") == securityFindingsRank {
		filter.Desc = true
	}
	window := filter
	if ranked {
		window.Offset, window.Limit = 0, securityFindingsMaxLimit
	}
	ctx := r.Context()
	st := store.New(s.db())
	total, err := st.CountSecFindings(ctx, filter)
	if err != nil {
		http.Error(w, "load findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	got, err := st.ListSecFindings(ctx, window)
	if err != nil {
		http.Error(w, "load findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	evidence := s.securityDependencyEvidence(r, st, got)
	sigs := s.securityListSignals(ctx, st, got, evidence, securityRootsOf(ctx, st))
	resp := securityFindingsPage{Total: total, Page: page, Limit: limit}
	resp.ReachPending = securityReachPending(sigs)
	if ranked {
		got = rankSecurityFindings(got, sigs)
		lo := min(filter.Offset, len(got))
		got = got[lo:min(lo+limit, len(got))]
	}
	out := make([]securityFindingJS, 0, len(got))
	for _, f := range got {
		js := securityFindingJSOf(f)
		js.Package, js.Ecosystem = securityDependencyPackage(f, evidence[f.ID])
		out = append(out, js)
	}
	applySecuritySignals(out, sigs)
	resp.Findings = out
	writeJSON(w, resp)
}

// securityDependencyEvidence loads the dependency evidence of the listed
// dependency findings (none is read for any other category); a failed read
// leaves the rows without a package rather than failing the page.
func (s *Server) securityDependencyEvidence(r *http.Request, st *store.Store, fs []secfinding.Finding) map[string]string {
	var ids []string
	for _, f := range fs {
		if f.Category == policy.FindingVulnerableDependency {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	ev, err := st.SecDependencyEvidence(r.Context(), ids)
	if err != nil {
		return nil
	}
	return ev
}

// securityFindingDetail is GET /api/security/findings/{id}: one finding
// with the history the list leaves out. Still no evidence: the redacted
// excerpt stays with the explain flow. The one exception is a dependency
// finding's package coordinate ("<ecosystem> <name>@<version>", public),
// which Finding.Package and Dependency show.
type securityFindingDetail struct {
	Finding     securityFindingJS     `json:"finding"`
	RulePack    string                `json:"rule_pack,omitempty"`
	DriverVer   string                `json:"driver_version,omitempty"`
	FixHint     string                `json:"fix_hint,omitempty"`
	Model       string                `json:"model,omitempty"`
	Attribution string                `json:"attribution,omitempty"`
	ClosedAt    string                `json:"closed_at,omitempty"`
	ExceptionID string                `json:"exception_id,omitempty"`
	Project     *securityProjectRefJS `json:"project,omitempty"`
	// Dependency is the view-time package, lockfile and local-advisory
	// detail of a vulnerable_dependency finding (security_depdetail.go);
	// absent for every other category.
	Dependency *securityDependencyJS     `json:"dependency,omitempty"`
	Sightings  []string                  `json:"sightings"`
	Commits    []securityFindingCommitJS `json:"commits"`
	Events     []securityFindingEventJS  `json:"events"`
	Exceptions []securityExceptionJS     `json:"exceptions"`
}

// securityProjectRefJS names the project a finding belongs to.
type securityProjectRefJS struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	RootPath string `json:"root_path"`
}

type securityFindingCommitJS struct {
	SHA      string   `json:"sha"`
	LastSeen string   `json:"last_seen"`
	Remotes  []string `json:"remotes,omitempty"`
}

type securityFindingEventJS struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

// handleSecurityFinding serves GET /api/security/findings/{id}: the
// Findings tab's drawer.
func (s *Server) handleSecurityFinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	st := store.New(s.db())
	got, err := st.ListSecFindings(ctx, store.SecFindingFilter{ID: id, Limit: 1})
	if err != nil {
		http.Error(w, "load finding: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if id == "" || len(got) == 0 {
		http.Error(w, "unknown finding", http.StatusNotFound)
		return
	}
	f := got[0]
	out := securityFindingDetail{
		Finding: securityFindingJSOf(f), RulePack: f.Rule.Pack, DriverVer: f.Engine.DriverVersion, FixHint: f.FixHint,
		Model: f.Lineage.Model, Attribution: string(f.Attribution.Class), ExceptionID: f.ExceptionID,
		Sightings: []string{}, Commits: []securityFindingCommitJS{}, Events: []securityFindingEventJS{},
		Exceptions: []securityExceptionJS{},
	}
	if !f.ClosedAt.IsZero() {
		out.ClosedAt = f.ClosedAt.UTC().Format(time.RFC3339)
	}
	if index, err := securityProjectIndex(ctx, st); err == nil {
		if ref, ok := index[f.Project.RootHash]; ok {
			out.Project = &securityProjectRefJS{ID: ref.ID, Name: securityProjectName(ref), RootPath: ref.Root}
		}
	}
	if evidence := s.securityDependencyEvidence(r, st, got); evidence != nil {
		ev := evidence[f.ID]
		out.Finding.Package, out.Finding.Ecosystem = securityDependencyPackage(f, ev)
		root := ""
		if out.Project != nil {
			root = out.Project.RootPath
		}
		if dep := securityDependencyDetail(f, ev, root, s.securityOSVLookup()); dep != nil {
			out.Dependency = dep
			if dep.SuggestedVersion != "" {
				out.FixHint = securityDependencyFixHint(dep)
			}
		}
		rows := []securityFindingJS{out.Finding}
		applySecuritySignals(rows, s.securitySignals(ctx, st, got, evidence, map[string]string{f.Project.RootHash: root}))
		out.Finding = rows[0]
	}
	if paths, err := st.SecFindingSightings(ctx, f.ID); err == nil {
		out.Sightings = append(out.Sightings, paths...)
	}
	if commits, err := st.SecFindingCommits(ctx, f.ID); err == nil {
		for _, c := range commits {
			out.Commits = append(out.Commits, securityFindingCommitJS{SHA: c.SHA, LastSeen: c.LastSeen.UTC().Format(time.RFC3339), Remotes: c.Remotes})
		}
	}
	if events, err := st.SecFindingEvents(ctx, f.ID, 50); err == nil {
		for _, e := range events {
			out.Events = append(out.Events, securityFindingEventJS{Kind: e.Kind, Detail: e.Detail, At: e.At.UTC().Format(time.RFC3339)})
		}
	}
	if exc, err := st.ListSecExceptions(ctx, store.SecExceptionFilter{ProjectRootHash: f.Project.RootHash}); err == nil {
		for _, e := range exc {
			if e.FindingID == f.ID {
				out.Exceptions = append(out.Exceptions, securityExceptionJSOf(e))
			}
		}
	}
	writeJSON(w, out)
}
