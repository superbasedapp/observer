//go:build !sbo_omit_security && !sbo_omit_security_dast

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_dast.go serves the Code security page's DAST card (component
// security.dast; security coverage gaps plan
// docs/plans/security-coverage-gaps-plan-2026-11-13.md section 2), through
// the injected seam (Options.SecurityDAST), so the dashboard never links
// the DAST lane:
//
//   - GET /api/security/dast[?project=<root hash>]: the selection, the
//     accept and its text, the confirm token, and for a named project its
//     dev-server candidates (from the project's own files; nothing dialed)
//     and its last run per origin.
//   - POST /api/security/dast/accept: records the developer's one accept
//     (surface dashboard).
//   - POST /api/security/dast/run {project, url, insecure_tls}: one run
//     against the URL in the body (loopback only), stored against the
//     project, one at a time.
//
// All owner-local with the confirm token on every POST; guard rule R-165
// denies an agent the prefix. 404 unless security.dast is selected.

// securityDASTBodyMax bounds a POST body.
const securityDASTBodyMax = 8 << 10

// securityDASTProjectJS is one project's part of the GET.
type securityDASTProjectJS struct {
	ProjectRootHash string                  `json:"project_root_hash"`
	Name            string                  `json:"name"`
	Candidates      []dashapi.DASTCandidate `json:"candidates"`
	LastRuns        []dashapi.DASTOriginRun `json:"last_runs"`
}

// securityDASTView is GET /api/security/dast.
type securityDASTView struct {
	State        dashapi.DASTState      `json:"state"`
	ConfirmToken string                 `json:"confirm_token"`
	Project      *securityDASTProjectJS `json:"project,omitempty"`
}

// securityDASTRunRequest is the run's body: the project by its root hash,
// the URL the developer chose or typed, and whether an untrusted
// certificate is accepted on an https dev server.
type securityDASTRunRequest struct {
	Project     string `json:"project"`
	URL         string `json:"url"`
	InsecureTLS bool   `json:"insecure_tls"`
}

// securityDASTSeam returns the seam and its state, or answers 404 itself
// (compiled out, or not selected).
func (s *Server) securityDASTSeam(w http.ResponseWriter, r *http.Request) (*dashapi.SecurityDAST, dashapi.DASTState, bool) {
	seam := s.opts.SecurityDAST
	if seam == nil || seam.State == nil {
		writeCompiledOut(w, "security.dast")
		return nil, dashapi.DASTState{}, false
	}
	st := seam.State(r.Context())
	if !st.Selected {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "the security.dast component is not selected: add it under [components]",
		})
		return nil, st, false
	}
	return seam, st, true
}

// securityDASTProjectRoot resolves a root hash through the dashboard's own
// project index; ok false for a hash no stored project names.
func (s *Server) securityDASTProjectRoot(ctx context.Context, hash string) (root, name string, ok bool, err error) {
	if hash == "" {
		return "", "", false, nil
	}
	index, err := securityProjectIndex(ctx, store.New(s.db()))
	if err != nil {
		return "", "", false, err
	}
	ref, found := index[hash]
	if !found || ref.Root == "" {
		return "", "", false, nil
	}
	return ref.Root, securityProjectName(ref), true, nil
}

func (s *Server) handleSecurityDAST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	seam, st, ok := s.securityDASTSeam(w, r)
	if !ok {
		return
	}
	view := securityDASTView{State: st, ConfirmToken: setConfirmCookie(w, r)}
	if hash := r.URL.Query().Get("project"); hash != "" {
		root, name, found, err := s.securityDASTProjectRoot(r.Context(), hash)
		if err != nil {
			writeErr(w, err)
			return
		}
		if !found {
			writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "unknown_project"})
			return
		}
		p := &securityDASTProjectJS{ProjectRootHash: hash, Name: name, Candidates: []dashapi.DASTCandidate{}, LastRuns: []dashapi.DASTOriginRun{}}
		if seam.Candidates != nil {
			if c := seam.Candidates(r.Context(), root); c != nil {
				p.Candidates = c
			}
		}
		if seam.LastRuns != nil {
			if l := seam.LastRuns(r.Context(), root); l != nil {
				p.LastRuns = l
			}
		}
		view.Project = p
	}
	writeJSON(w, view)
}

func (s *Server) handleSecurityDASTAccept(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	seam, _, ok := s.securityDASTSeam(w, r)
	if !ok {
		return
	}
	if seam.Accept == nil {
		writeCompiledOut(w, "security.dast")
		return
	}
	if err := seam.Accept(r.Context()); err != nil {
		writeSecurityDASTErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"state": seam.State(r.Context())})
}

func (s *Server) handleSecurityDASTRun(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	seam, st, ok := s.securityDASTSeam(w, r)
	if !ok {
		return
	}
	if seam.Run == nil {
		writeCompiledOut(w, "security.dast")
		return
	}
	var req securityDASTRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityDASTBodyMax)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_body", "detail": err.Error()})
		return
	}
	if !st.Accepted {
		writeSecurityDASTErr(w, dashapi.ErrDASTNotAccepted)
		return
	}
	// The URL is checked here too (the seam checks it again): a dev server
	// on this machine, with a port.
	if _, err := secdast.ParseTarget(req.URL); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_target", "detail": err.Error()})
		return
	}
	root, _, found, err := s.securityDASTProjectRoot(r.Context(), req.Project)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !found {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "unknown_project", "detail": "name a project this dashboard knows"})
		return
	}
	res, err := seam.Run(r.Context(), root, req.URL, req.InsecureTLS)
	if err != nil {
		writeSecurityDASTErr(w, err)
		return
	}
	writeJSON(w, res)
}

// securityDASTErrRows map the seam's refusals to their status, walked
// top-down; anything else is a 500.
var securityDASTErrRows = []struct {
	err    error
	status int
	code   string
}{
	{dashapi.ErrDASTNotSelected, http.StatusNotFound, "not_selected"},
	{dashapi.ErrDASTNotAccepted, http.StatusConflict, "not_accepted"},
	{dashapi.ErrDASTBadTarget, http.StatusBadRequest, "bad_target"},
	{dashapi.ErrDASTBusy, http.StatusConflict, "busy"},
}

func writeSecurityDASTErr(w http.ResponseWriter, err error) {
	for _, row := range securityDASTErrRows {
		if errors.Is(err, row.err) {
			writeJSONStatus(w, row.status, map[string]string{"error": row.code, "detail": err.Error()})
			return
		}
	}
	writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "failed", "detail": err.Error()})
}
