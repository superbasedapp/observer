//go:build !sbo_omit_security

package dashboard

import (
	"net/http"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
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
type securityProjectRow struct {
	ProjectRootHash string            `json:"project_root_hash"`
	State           string            `json:"state"`
	Reason          string            `json:"reason"`
	Blocking        int               `json:"blocking"`
	Counts          []securityCountJS `json:"counts"`
}

type securityCountJS struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	N        int    `json:"n"`
}

// securityStatusResponse is GET /api/security/status.
type securityStatusResponse struct {
	Module   string               `json:"module"`
	Projects []securityProjectRow `json:"projects"`
}

// handleSecurityStatus serves GET /api/security/status: every active project's
// derived posture state (what the hook would read now) and its open
// finding counts. Paths never appear, only project root hashes.
func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resolved, _ := config.ResolveGlobalPath(s.opts.ConfigPath)
	layout := secposture.LayoutFor(resolved)
	gp := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	module := secposture.ModuleSignalFrom(gp.State, gp.Posture)
	st := store.New(s.db())
	now := time.Now()
	// The projects the posture writer signs (secsvc.WriteAll); an idle
	// project has no posture file and is not listed.
	roots, err := st.SecActiveProjectRoots(ctx, now.Add(-secsvc.DefaultActiveWithin))
	if err != nil {
		http.Error(w, "load projects: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := securityStatusResponse{Module: moduleSignalName(module), Projects: []securityProjectRow{}}
	for _, root := range roots {
		rd := secposture.Load(layout, root, module, now, secposture.Versions{})
		row := securityProjectRow{
			ProjectRootHash: secposture.ProjectRootHash(root), State: string(rd.State.Posture),
			Reason: string(rd.State.Reason), Blocking: rd.State.Blocking, Counts: []securityCountJS{},
		}
		counts, err := st.SecOpenCounts(ctx, row.ProjectRootHash)
		if err != nil {
			http.Error(w, "load counts: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, c := range counts {
			row.Counts = append(row.Counts, securityCountJS{Category: string(c.Category), Severity: string(c.Severity), N: c.N})
		}
		resp.Projects = append(resp.Projects, row)
	}
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
// templated message and ids only, never evidence.
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
}

// handleSecurityFindings serves GET /api/security/findings
// (?project=<root hash>&status=<status>&limit=<n>).
func (s *Server) handleSecurityFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	got, err := store.New(s.db()).ListSecFindings(r.Context(), store.SecFindingFilter{
		ProjectRootHash: q.Get("project"), Status: secfinding.Status(q.Get("status")), Limit: limit,
	})
	if err != nil {
		http.Error(w, "load findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]securityFindingJS, 0, len(got))
	for _, f := range got {
		out = append(out, securityFindingJS{
			ID: f.ID, ProjectRootHash: f.Project.RootHash, RuleID: f.Rule.ID, Driver: f.Engine.Driver,
			Category: string(f.Category), Severity: string(f.Severity), Confidence: string(f.Confidence),
			Scope: string(f.Scope), Baseline: string(f.Baseline), Status: string(f.Status),
			RelPath: f.Location.RelPath, StartLine: f.Location.StartLine, Message: f.Message,
			FirstSeen: f.FirstSeen.UTC().Format(time.RFC3339), LastSeen: f.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, map[string]any{"findings": out})
}
