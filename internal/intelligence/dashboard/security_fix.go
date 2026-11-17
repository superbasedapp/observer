//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfixstate"
	"github.com/marmutapp/superbased-observer/internal/secfixtask"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_fix.go serves the Code security page's "Fix with an agent"
// (docs/plans/fix-findings-with-agent-plan-2026-11-13.md section 5):
//
//	GET  /api/security/fix/plan      the selection's open findings by project,
//	                                 each project's task prompt, the tools'
//	                                 task seeds; mints the confirm token
//	POST /api/security/fix/launch    one project's task, started as a fresh
//	                                 terminal launch (startFreshTerminal)
//	GET  /api/security/fix/attempts  recent launches and their findings' state
//
// Owner-local. The selection is a finding id or the Findings list's own
// query parameters; the server re-reads every finding and builds the prompt
// from its own rows (internal/secfixtask), forcing status=open. The launch
// passes every gate a New terminal launch passes.

// securityFixAttemptsShown is how many attempts the attempts read returns.
const securityFixAttemptsShown = 20

// securityFixBodyMax caps the launch body.
const securityFixBodyMax = 16 << 10

type securityFixProjectJS struct {
	Hash     string `json:"project_root_hash"`
	Name     string `json:"name"`
	RootPath string `json:"root_path"`
	OnDisk   bool   `json:"on_disk"`
	Findings int    `json:"findings"`
	Listed   int    `json:"listed"`
	Prompt   string `json:"prompt"`
}

type securityFixPlanJS struct {
	ConfirmToken string                 `json:"confirm_token"`
	Total        int                    `json:"total"`
	Truncated    bool                   `json:"truncated"`
	Projects     []securityFixProjectJS `json:"projects"`
	Seeds        map[string]string      `json:"seeds"`
}

// securityFixLaunchRequest is the launch body: the selection, the project,
// and the New terminal dialog's own launch fields (project_root excluded:
// it is the project's).
type securityFixLaunchRequest struct {
	Query           string `json:"query"`
	Finding         string `json:"finding"`
	ProjectRootHash string `json:"project_root_hash"`
	terminalLaunchRequest
}

type securityFixLaunchJS struct {
	terminalLaunchResponse
	Seeded    bool   `json:"seeded"`
	Prompt    string `json:"prompt,omitempty"`
	AttemptID string `json:"attempt_id"`
}

type securityFixAttemptFindingJS struct {
	ID     string `json:"id"`
	RuleID string `json:"rule_id,omitempty"`
	Status string `json:"status"`
}

type securityFixAttemptJS struct {
	secfixstate.Attempt
	Total    int                           `json:"total"`
	Open     int                           `json:"open"`
	Cleared  bool                          `json:"cleared"`
	Findings []securityFixAttemptFindingJS `json:"findings"`
}

// securityFixProject is one project of a resolved selection.
type securityFixProject struct {
	ref      store.SecProjectRef
	hash     string
	findings []secfixtask.Finding
}

// securityFixSelection resolves q (finding=<id>, or the Findings list's
// filters) to its open findings grouped by project. total counts every open
// finding the selection matches; truncated says more than
// secfixtask.MaxSelect did.
func (s *Server) securityFixSelection(r *http.Request, st *store.Store, q url.Values) (projects []securityFixProject, total int, truncated bool, err error) {
	ctx := r.Context()
	filter := securityFindingsFilter(q)
	if id := strings.TrimSpace(q.Get("finding")); id != "" {
		if len(id) > 64 {
			return nil, 0, false, errors.New("bad finding id")
		}
		filter = store.SecFindingFilter{ID: id}
	}
	filter.Status = policy.FindingStatusOpen
	total, err = st.CountSecFindings(ctx, filter)
	if err != nil {
		return nil, 0, false, err
	}
	filter.Limit, filter.Sort, filter.Desc = secfixtask.MaxSelect, store.SecSortSeverity, true
	got, err := st.ListSecFindings(ctx, filter)
	if err != nil {
		return nil, 0, false, err
	}
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		return nil, 0, false, err
	}
	evidence := s.securityDependencyEvidence(r, st, got)
	lookup := s.securityOSVLookup()
	fixes := map[string]*securityDependencyJS{}
	var fs []secfixtask.Finding
	for _, f := range got {
		fs = append(fs, securityFixFindingOf(f, evidence[f.ID], lookup, fixes))
	}
	for _, g := range secfixtask.GroupByProject(fs) {
		ref, ok := index[g.ProjectKey]
		if !ok {
			// A finding whose project row is gone has no folder to work in.
			continue
		}
		projects = append(projects, securityFixProject{ref: ref, hash: g.ProjectKey, findings: g.Findings})
	}
	return projects, total, total > len(got), nil
}

// securityFixFindingOf is one store finding as the prompt builder's plain
// value. A dependency finding gets its package and the advisories' fixed
// versions (no lockfile read: the root is not passed); fixes memoizes the
// advisory lookup per evidence within one request.
func securityFixFindingOf(f secfinding.Finding, evidence string, lookup func(eco, id string) ([]byte, error), fixes map[string]*securityDependencyJS) secfixtask.Finding {
	out := secfixtask.Finding{
		ID: f.ID, ProjectKey: f.Project.RootHash, RuleID: f.Rule.ID, Category: string(f.Category),
		Severity: string(f.Severity), Driver: f.Engine.Driver, RelPath: f.Location.RelPath,
		StartLine: f.Location.StartLine, Message: f.Message, FixHint: f.FixHint, CWE: f.References.CWE,
	}
	if hint, ok := secassesssvc.FixContext(f.Rule.ID); ok {
		out.FixHint = hint
	}
	if f.Category != policy.FindingVulnerableDependency || evidence == "" {
		return out
	}
	out.Package, out.Ecosystem = securityDependencyPackage(f, evidence)
	dep, seen := fixes[evidence]
	if !seen {
		dep = securityDependencyDetail(f, evidence, "", lookup)
		fixes[evidence] = dep
	}
	if dep != nil {
		out.FixedVersions, out.SuggestedVersion = dep.FixedVersions, dep.SuggestedVersion
	}
	return out
}

// securityFixTotalIn counts the selection's open findings in one project
// (the prompt's "N more" line): the listed window when the selection was not
// truncated, else a count with the project filter added.
func securityFixTotalIn(ctx context.Context, st *store.Store, q url.Values, p securityFixProject, truncated bool) int {
	if !truncated {
		return len(p.findings)
	}
	filter := securityFindingsFilter(q)
	filter.Status = policy.FindingStatusOpen
	filter.ProjectRootHash = p.hash
	n, err := st.CountSecFindings(ctx, filter)
	if err != nil || n < len(p.findings) {
		return len(p.findings)
	}
	return n
}

// securityFixSeeds is every launchable tool's task seed on the wire.
func securityFixSeeds() map[string]string {
	out := map[string]string{}
	for _, t := range launchableTools() {
		out[t] = integration.TaskSeedFor(t).Wire()
	}
	return out
}

// securityFixOnDisk reports whether a project root is a directory here.
func securityFixOnDisk(root string) bool {
	if root == "" {
		return false
	}
	fi, err := os.Stat(root) //nolint:gosec // G703: a project root from the node's own project index, stat only
	return err == nil && fi.IsDir()
}

// handleSecurityFixPlan serves GET /api/security/fix/plan.
func (s *Server) handleSecurityFixPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	q := r.URL.Query()
	projects, total, truncated, err := s.securityFixSelection(r, st, q)
	if err != nil {
		writeErrStatus(w, err, http.StatusBadRequest)
		return
	}
	out := securityFixPlanJS{
		ConfirmToken: setConfirmCookie(w, r), Total: total, Truncated: truncated,
		Projects: []securityFixProjectJS{}, Seeds: securityFixSeeds(),
	}
	for _, p := range projects {
		name := securityProjectName(p.ref)
		task := secfixtask.Build(name, p.findings, securityFixTotalIn(ctx, st, q, p, truncated))
		out.Projects = append(out.Projects, securityFixProjectJS{
			Hash: p.hash, Name: name, RootPath: p.ref.Root, OnDisk: securityFixOnDisk(p.ref.Root),
			Findings: task.Listed + task.Omitted, Listed: task.Listed, Prompt: task.Prompt,
		})
	}
	writeJSON(w, out)
}

// handleSecurityFixLaunch serves POST /api/security/fix/launch.
func (s *Server) handleSecurityFixLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable - this dashboard runs without the embedded-terminal launcher (run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	var body securityFixLaunchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityFixBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// A fix task runs an agent in a terminal: never a GUI app, a plain shell
	// or a client-chosen folder.
	if k := strings.TrimSpace(body.Kind); k != "" && integration.LaunchKind(k) != integration.LaunchKindTerminal {
		http.Error(w, "a fix task starts a terminal agent", http.StatusBadRequest)
		return
	}
	if _, ok := launchSubcommand(body.Tool); !ok {
		http.Error(w, "tool "+body.Tool+" is not launchable in the embedded terminal", http.StatusBadRequest)
		return
	}
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(body.Sandbox); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	q, err := url.ParseQuery(body.Query)
	if err != nil {
		http.Error(w, "bad selection query", http.StatusBadRequest)
		return
	}
	if body.Finding != "" {
		q = url.Values{"finding": {body.Finding}}
	}
	ctx := r.Context()
	st := store.New(s.db())
	projects, _, truncated, err := s.securityFixSelection(r, st, q)
	if err != nil {
		writeErrStatus(w, err, http.StatusBadRequest)
		return
	}
	var project *securityFixProject
	for i := range projects {
		if projects[i].hash == body.ProjectRootHash {
			project = &projects[i]
			break
		}
	}
	if project == nil {
		http.Error(w, "the selection holds no open finding in that project", http.StatusConflict)
		return
	}
	name := securityProjectName(project.ref)
	task := secfixtask.Build(name, project.findings, securityFixTotalIn(ctx, st, q, *project, truncated))
	seeded := integration.TaskSeedFor(body.Tool).Seeds()
	prompt := ""
	if seeded {
		prompt = task.Prompt
	}
	launch := body.terminalLaunchRequest
	launch.Kind, launch.ProjectRoot = "", project.ref.Root
	resp, ok := s.startFreshTerminal(w, r, launch, prompt)
	if !ok {
		return
	}
	attempt, err := s.securityFixState().Record(secfixstate.Attempt{
		Tool: body.Tool, ProjectRootHash: project.hash, ProjectName: name,
		Handle: resp.Token, Seeded: seeded, FindingIDs: task.FindingIDs,
	}, time.Now())
	if err != nil && s.opts.Logger != nil {
		s.opts.Logger.Warn("security fix: attempt not recorded", "error", err)
	}
	out := securityFixLaunchJS{terminalLaunchResponse: resp, Seeded: seeded, AttemptID: attempt.ID}
	if !seeded {
		out.Prompt = task.Prompt
	}
	writeJSON(w, out)
	s.kickWatchRootsRefresh()
}

// handleSecurityFixAttempts serves GET /api/security/fix/attempts.
func (s *Server) handleSecurityFixAttempts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	out := []securityFixAttemptJS{}
	for _, a := range s.securityFixState().Recent(securityFixAttemptsShown) {
		js := securityFixAttemptJS{Attempt: a, Findings: []securityFixAttemptFindingJS{}}
		for _, id := range a.FindingIDs {
			fj := securityFixAttemptFindingJS{ID: id, Status: "missing"}
			if f, ok, err := st.SecFindingByID(ctx, id); err == nil && ok {
				fj.RuleID, fj.Status = f.Rule.ID, string(f.Status)
			}
			if fj.Status == string(policy.FindingStatusOpen) {
				js.Open++
			}
			js.Findings = append(js.Findings, fj)
		}
		js.Total = len(js.Findings)
		js.Cleared = js.Total > 0 && js.Open == 0
		out = append(out, js)
	}
	writeJSON(w, map[string]any{"attempts": out})
}

// securityFixState returns this server's one attempts store.
func (s *Server) securityFixState() *secfixstate.Store {
	s.secFixOnce.Do(func() {
		s.secFix = secfixstate.New(secfixstate.Path(s.opts.DBPath))
	})
	return s.secFix
}
