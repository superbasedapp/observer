//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_exceptions.go serves the Code security page's Exceptions and
// Baselines tabs (security pillar plan sections 4.5.2 and 6.3, lane
// sec-c3), the dashboard half of `observer security exception` and
// `observer security baseline`. Every route is owner-local: granting an
// exception or approving a baseline lifts a finding, so the writes also
// need the double-submit confirm token the GET mints, and R-165 denies an
// agent that posts to them under enforce. Pickers only: the reason and
// expiry are closed lists, the baseline commit is picked from the
// proposal. A feature-owned file; with sbo_omit_security the routes
// answer 404 component_not_installed (security_exceptions_omit.go).

type securityPickerJS struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type securityExceptionJS struct {
	ID              int64  `json:"id"`
	FindingID       string `json:"finding_id"`
	ProjectRootHash string `json:"project_root_hash"`
	RuleID          string `json:"rule_id"`
	RelPath         string `json:"rel_path"`
	Reason          string `json:"reason"`
	Expiry          string `json:"expiry"`
	ExpiresAt       string `json:"expires_at"`
	GrantedBy       string `json:"granted_by"`
	GrantedAt       string `json:"granted_at"`
	EndedAt         string `json:"ended_at,omitempty"`
	EndReason       string `json:"end_reason,omitempty"`
}

func securityExceptionJSOf(e store.SecException) securityExceptionJS {
	j := securityExceptionJS{
		ID: e.ID, FindingID: e.FindingID, ProjectRootHash: e.ProjectRootHash, RuleID: e.RuleID, RelPath: e.RelPath,
		Reason: e.Reason, Expiry: e.Expiry, ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339), GrantedBy: e.GrantedBy,
		GrantedAt: e.GrantedAt.UTC().Format(time.RFC3339), EndReason: e.EndReason,
	}
	if !e.EndedAt.IsZero() {
		j.EndedAt = e.EndedAt.UTC().Format(time.RFC3339)
	}
	return j
}

func (s *Server) securityExceptionDeps() secsvc.ExceptionDeps {
	st := store.New(s.db())
	return secsvc.ExceptionDeps{Store: st, HashFile: secsvc.HashProjectFile, RootFor: secsvc.RootsResolver(st.ProjectRoots), Now: s.now}
}

// securityPickers are the closed reason and expiry pickers, so the page
// renders exactly what the server accepts.
func securityPickers() (reasons, expiries []securityPickerJS) {
	for _, r := range secexcept.Reasons {
		reasons = append(reasons, securityPickerJS{ID: string(r.ID), Label: r.Label})
	}
	for _, e := range secexcept.Expiries {
		expiries = append(expiries, securityPickerJS{ID: string(e.ID), Label: e.Label})
	}
	return reasons, expiries
}

// writeSecurityRefusal answers a refused grant with 409 and the refusal.
func writeSecurityRefusal(w http.ResponseWriter, err error) {
	if r, ok := secexcept.AsRefusal(err); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(r.Refusal), "message": r.Message})
		return
	}
	writeErr(w, err)
}

// handleSecurityExceptions serves GET /api/security/exceptions
// (?project=<root hash>&all=1) and POST {finding_id, reason, expiry}.
func (s *Server) handleSecurityExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		got, err := store.New(s.db()).ListSecExceptions(r.Context(), store.SecExceptionFilter{ProjectRootHash: q.Get("project"), OpenOnly: q.Get("all") != "1"})
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]securityExceptionJS, 0, len(got))
		for _, e := range got {
			out = append(out, securityExceptionJSOf(e))
		}
		reasons, expiries := securityPickers()
		writeJSON(w, map[string]any{"exceptions": out, "reasons": reasons, "expiries": expiries, "confirm_token": setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req struct {
			FindingID string `json:"finding_id"`
			Reason    string `json:"reason"`
			Expiry    string `json:"expiry"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		ex, err := secsvc.GrantException(r.Context(), s.securityExceptionDeps(), secexcept.Request{
			FindingID: req.FindingID, Reason: req.Reason, Expiry: req.Expiry, Origin: secexcept.OriginDashboard,
		})
		if err != nil {
			writeSecurityRefusal(w, err)
			return
		}
		writeJSON(w, map[string]any{"exception": securityExceptionJSOf(ex)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecurityExceptionRevoke serves POST /api/security/exceptions/revoke
// {id}: the exception ends now and its finding is open again.
func (s *Server) handleSecurityExceptionRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := secsvc.RevokeException(r.Context(), s.securityExceptionDeps(), req.ID); err != nil {
		if errors.Is(err, store.ErrSecExceptionNotFound) {
			http.Error(w, "no such exception, or it already ended", http.StatusNotFound)
			return
		}
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"revoked": req.ID})
}

// handleSecurityBaseline serves GET /api/security/baseline?project=<root
// hash> (the current baseline and the commit picker) and POST {project,
// action: "approve" | "reset", commit}. The project is named by its root
// hash; the root itself never reaches the page.
func (s *Server) handleSecurityBaseline(w http.ResponseWriter, r *http.Request) {
	st := store.New(s.db())
	resolve := secsvc.RootsResolver(st.ProjectRoots)
	switch r.Method {
	case http.MethodGet:
		root, ok := resolve(r.Context(), r.URL.Query().Get("project"))
		if !ok {
			http.Error(w, "unknown project", http.StatusNotFound)
			return
		}
		v, err := secsvc.LoadBaselineView(r.Context(), gitview.RunReadOnlyTimeout, st, root)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"baseline": v, "confirm_token": setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req struct {
			Project string `json:"project"`
			Action  string `json:"action"`
			Commit  string `json:"commit"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		root, ok := resolve(r.Context(), req.Project)
		if !ok {
			http.Error(w, "unknown project", http.StatusNotFound)
			return
		}
		switch req.Action {
		case "approve":
			// The picker offers full commit ids; anything else is refused
			// here rather than resolved, and a full id is approved only
			// when the picker offers it (lane sec-gate2), so the page can
			// only approve a commit it showed.
			if err := secexcept.CheckBaselineCommit(req.Commit); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			b, err := secsvc.ApproveOfferedBaseline(r.Context(), gitview.RunReadOnlyTimeout, st, root, req.Commit, secexcept.OriginDashboard, secrules.PackVersion, s.now())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"approved": b.Ref})
		case "reset":
			if err := secsvc.ResetBaseline(r.Context(), st, root, secexcept.OriginDashboard, s.now()); err != nil {
				writeErr(w, err)
				return
			}
			writeJSON(w, map[string]any{"reset": true})
		default:
			http.Error(w, `action must be "approve" or "reset"`, http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecurityScanHistory serves POST /api/security/scan-history
// {project}: the bounded history scan (secsvc.ScanHistory) of one project,
// named by its root hash, with a 30-second deadline and the default commit
// cap. Owner-local with the confirm token: it runs git and writes findings.
func (s *Server) handleSecurityScanHistory(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		Project string `json:"project"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	st := store.New(s.db())
	root, ok := secsvc.RootsResolver(st.ProjectRoots)(r.Context(), req.Project)
	if !ok {
		http.Error(w, "unknown project", http.StatusNotFound)
		return
	}
	resolved, err := config.ResolveGlobalPath(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := secsvc.ScanHistory(r.Context(), secsvc.LocalHistoryDeps(resolved, secrules.PackVersion, st), root,
		secsvc.HistoryOptions{Deadline: 30 * time.Second})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"history": res, "complete": res.Complete()})
}

// securityGithooksActive reports whether the opt-in git hooks component is
// selected, through the daemon's one opt-in rule (Options.SecuritySelected,
// cmd/observer/security_optin.go; plans decision log P-025). With no
// component service or no rule wired it is not: installing writes into a
// repository, so this fails closed.
func (s *Server) securityGithooksActive(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	return ok && s.opts.SecuritySelected != nil && s.opts.SecuritySelected(snap, "security.githooks")
}

// handleSecurityGithooks serves GET /api/security/githooks?project=<root
// hash> (the hooks' state in that repository) and POST {project, action:
// "install" | "uninstall"} (component security.githooks; lane sec-c3).
// Installing is the developer's per-repository consent and needs the
// component active; uninstalling works while it is off, so a developer can
// always take the hooks out.
func (s *Server) handleSecurityGithooks(w http.ResponseWriter, r *http.Request) {
	st := store.New(s.db())
	resolve := secsvc.RootsResolver(st.ProjectRoots)
	project := r.URL.Query().Get("project")
	var req struct {
		Project string `json:"project"`
		Action  string `json:"action"`
	}
	if r.Method == http.MethodPost {
		if !requireConfirmToken(w, r) {
			return
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		project = req.Project
	} else if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	root, ok := resolve(r.Context(), project)
	if !ok {
		http.Error(w, "unknown project", http.StatusNotFound)
		return
	}
	t, err := secsvc.ResolveGithookTarget(r.Context(), gitview.RunReadOnlyTimeout, root)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	active := s.securityGithooksActive(r)
	if r.Method == http.MethodPost {
		switch req.Action {
		case "install":
			if !active {
				http.Error(w, "the Local git hooks component (security.githooks) is not active; turn it on in Settings > Components", http.StatusConflict)
				return
			}
			exe, err := os.Executable()
			if err == nil {
				err = secsvc.InstallGithooks(t, exe)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		case "uninstall":
			if _, err := secsvc.UninstallGithooks(t); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		default:
			http.Error(w, `action must be "install" or "uninstall"`, http.StatusBadRequest)
			return
		}
	}
	hooks, err := secsvc.GithooksStatus(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]any{"active": active, "refusal": t.Refusal, "hooks": hooks, "confirm_token": setConfirmCookie(w, r)})
}
