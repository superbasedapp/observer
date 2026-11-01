//go:build !sbo_omit_security && !sbo_omit_security_trust

package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/sectrustitem"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_trust.go serves /api/security/trust, the New Terminal dialog's
// repository trust chip and its review-and-accept panel (security pillar
// plan section 5.1, Phase B; component security.trust, whose route row
// makes the component guard answer 404 while it is inactive). The route is
// owner-local (L).
//
//   - GET ?dir=<path> runs the same read-only check the launch row runs, with
//     the developer's accepts, and returns the verdict and each reason: its
//     code, file, key, the short secret-masked excerpt the CLI prints, the
//     repository files a command runs and its digest. It records nothing and
//     mints the confirm token the POST needs.
//   - POST {dir, digests | all} (confirm token required) runs the check again
//     and accepts exactly the named digests the check reports, or every
//     pending one (refused over a truncated result), recording who (the
//     dashboard surface and the local account) and when, the same record
//     `observer security trust accept` writes. So the chip's "not accepted"
//     state is never a CLI-only dead end. Guard rule R-165 refuses an agent
//     that posts here.
//
// Both answer 404 unless the daemon's one opt-in rule
// (Options.SecuritySelected, cmd/observer/security_optin.go) selects
// security.trust, the same rule the launch row follows, so a [components]
// block that leaves the component out shows no chip (plans decision log
// P-031 finding 2; an install with no block has it, P-044). The GET says whether the dashboard accept
// would go through (accept_allowed): on a managed node whose governance hides
// or pins the Code security page the POST is refused, so the dialog hides
// Accept and says who can accept instead (P-031 finding 1).

// securityTrustReasonJS is one reason on the reply.
type securityTrustReasonJS struct {
	Code       string   `json:"code"`
	Level      string   `json:"level"`
	File       string   `json:"file"`
	Key        string   `json:"key,omitempty"`
	Excerpt    string   `json:"excerpt,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
	Files      []string `json:"files,omitempty"`
	Digest     string   `json:"digest,omitempty"`
	Local      bool     `json:"local,omitempty"`
	Accepted   bool     `json:"accepted,omitempty"`
}

// securityTrustResponse is GET /api/security/trust (and the POST's reply,
// after the accept).
type securityTrustResponse struct {
	Root         string                  `json:"root"`
	Verdict      string                  `json:"verdict"`
	Codes        []string                `json:"codes"`
	Pending      int                     `json:"pending"`
	Truncated    bool                    `json:"truncated,omitempty"`
	Reasons      []securityTrustReasonJS `json:"reasons"`
	Accepted     int                     `json:"accepted,omitempty"`
	ConfirmToken string                  `json:"confirm_token,omitempty"`
	// AcceptAllowed is false whenever the POST would be concealed or refused
	// here (governance, no database); AcceptNote then says who can accept.
	AcceptAllowed bool   `json:"accept_allowed"`
	AcceptNote    string `json:"accept_note,omitempty"`
}

// securityTrustPath is the route both methods serve.
const securityTrustPath = "/api/security/trust"

// securityTrustActive reports whether security.trust is selected under the
// daemon's one opt-in rule. With no component service or no rule wired it
// is not (fails closed, like the git hooks and scanners routes).
func (s *Server) securityTrustActive(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	return ok && s.opts.SecuritySelected != nil && s.opts.SecuritySelected(snap, "security.trust")
}

// securityTrustAcceptGate reports whether the dashboard accept for root
// would go through and, when it would not, the note naming who can accept.
// The governance answer comes from the guard's own route rules
// (governanceRouteRefusal) asked with the POST, so it cannot drift from what
// the POST meets.
func (s *Server) securityTrustAcceptGate(r *http.Request, root string) (bool, string) {
	cli := fmt.Sprintf("`observer security trust accept --all --dir %s`", quoteTrustArg(root))
	if s.db() == nil {
		return false, "This dashboard has no database to record an accept in. Accept in your own terminal with " + cli + "."
	}
	if s.opts.Governance == nil {
		return true, ""
	}
	eff := s.opts.Governance(r.Context())
	if !eff.VisibilityActive() {
		return true, ""
	}
	registered := SectionCodeSecurity
	if p := s.routeSections.Load(); p != nil {
		if sec, ok := (*p)[securityTrustPath]; ok {
			registered = sec
		}
	}
	post := r.Clone(r.Context())
	post.Method = http.MethodPost
	post.URL = &url.URL{Path: securityTrustPath}
	if ref := s.governanceRouteRefusal(post, registered, eff); ref.status == 0 {
		return true, ""
	}
	org := eff.Notice.OrgDisplayName
	if org == "" {
		org = eff.OrgName
	}
	if org == "" {
		org = "your organization"
	}
	return false, fmt.Sprintf("Accepting is not offered in this dashboard: %s manages the Code security page on this machine. "+
		"You can accept in your own terminal with %s (the accept is local to this machine), "+
		"or an organization admin can show the Code security page.", org, cli)
}

// quoteTrustArg quotes a directory for a command line when it holds a space
// or a quote (the CLI's quoteTrustDir).
func quoteTrustArg(dir string) string {
	if strings.ContainsAny(dir, " \t'\"") {
		return strconv.Quote(dir)
	}
	return dir
}

// securityTrustAcceptRequest is the POST body.
type securityTrustAcceptRequest struct {
	Dir     string   `json:"dir"`
	Digests []string `json:"digests"`
	All     bool     `json:"all"`
}

// securityTrustTarget is where a check runs: the repository root and the
// launch directory relative to it.
type securityTrustTarget struct {
	root, launch string
}

// resolveSecurityTrustDir validates an absolute directory and finds its
// repository root.
func resolveSecurityTrustDir(dir string) (securityTrustTarget, bool) {
	dir = strings.TrimSpace(dir)
	if dir == "" || !filepath.IsAbs(dir) {
		return securityTrustTarget{}, false
	}
	//nolint:gosec // G703: the caller names the directory on purpose; the route is owner-local (L) and reads only the trust check's fixed path table.
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return securityTrustTarget{}, false
	}
	abs := filepath.Clean(dir)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	root := abs
	// The checkout's own top level (a linked worktree's, not its main
	// checkout's, F0-14): the trust check reads that checkout's files.
	if gr, ok := git.FindCheckoutRoot(abs); ok {
		root = gr
	}
	launch := ""
	if rel, err := filepath.Rel(root, abs); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		launch = filepath.ToSlash(rel)
	}
	return securityTrustTarget{root: root, launch: launch}, true
}

// runSecurityTrust runs the check with the stored accepts.
func (s *Server) runSecurityTrust(ctx context.Context, t securityTrustTarget) (sectrust.Result, error) {
	accepted := map[string]bool{}
	if db := s.db(); db != nil {
		if a, err := store.New(db).AcceptedSecTrustDigests(ctx, guard.HashProjectRoot(t.root)); err == nil {
			accepted = a
		}
	}
	// The launch row's Observer-entry test (Options.RepoTrustOwn): at the
	// home directory Observer's own registered entries are left out, as the
	// launch leaves them out, so the chip never asks to accept them.
	var own func(sectrust.OwnItem) bool
	if s.opts.RepoTrustOwn != nil {
		if f := s.opts.RepoTrustOwn(t.root); f != nil {
			own = func(it sectrust.OwnItem) bool { return f(it.Code, it.File, it.Key, it.Content) }
		}
	}
	// The launch row's conditional rows (Options.RepoTrustPaths; N2's
	// initializeCommand row on every install), so the review lists, and
	// accepts, every row a launch warns or asks about.
	req := sectrust.Request{
		LaunchRel: t.launch,
		Accepted:  func(d string) bool { return accepted[d] },
		Own:       own,
	}
	if s.opts.RepoTrustPaths != nil {
		paths, parse := s.opts.RepoTrustPaths()
		req.Paths = paths
		if parse != nil {
			req.Devcontainer = parse
		}
	}
	res, err := sectrust.Check(ctx, sectrust.OSFS(t.root), req)
	if err != nil || own == nil {
		return res, err
	}
	return res.WithoutObserver(), nil
}

// securityTrustReply renders a result.
func securityTrustReply(t securityTrustTarget, res sectrust.Result) securityTrustResponse {
	resp := securityTrustResponse{
		Root: t.root, Verdict: string(res.Verdict), Codes: res.Codes(), Pending: len(res.Digests()),
		Truncated: res.Truncated, Reasons: []securityTrustReasonJS{},
	}
	if resp.Codes == nil {
		resp.Codes = []string{}
	}
	for _, x := range res.Reasons {
		resp.Reasons = append(resp.Reasons, securityTrustReasonJS{
			Code: x.Code, Level: x.Level.String(), File: x.File, Key: x.Key, Excerpt: x.Excerpt,
			Indicators: x.Indicators, Files: x.Files, Digest: x.Digest, Local: x.Local, Accepted: x.Accepted,
		})
	}
	return resp
}

// handleSecurityTrust serves GET and POST /api/security/trust.
func (s *Server) handleSecurityTrust(w http.ResponseWriter, r *http.Request) {
	if !s.securityTrustActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "repository trust (security.trust) is not selected: add it under [components]",
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		t, ok := resolveSecurityTrustDir(r.URL.Query().Get("dir"))
		if !ok {
			http.Error(w, "dir must be an absolute path to a directory", http.StatusBadRequest)
			return
		}
		res, err := s.runSecurityTrust(r.Context(), t)
		if err != nil {
			http.Error(w, "trust check: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp := securityTrustReply(t, res)
		resp.AcceptAllowed, resp.AcceptNote = s.securityTrustAcceptGate(r, t.root)
		if resp.AcceptAllowed {
			resp.ConfirmToken = setConfirmCookie(w, r)
		}
		writeJSON(w, resp)
	case http.MethodPost:
		s.handleSecurityTrustAccept(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecurityTrustAccept serves the POST: accept the named digests, or
// every pending one, after running the check again.
func (s *Server) handleSecurityTrustAccept(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	var req securityTrustAcceptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	if req.All == (len(req.Digests) > 0) {
		http.Error(w, "name the digests to accept, or set all (not both)", http.StatusBadRequest)
		return
	}
	t, ok := resolveSecurityTrustDir(req.Dir)
	if !ok {
		http.Error(w, "dir must be an absolute path to a directory", http.StatusBadRequest)
		return
	}
	db := s.db()
	if db == nil {
		http.Error(w, "no database", http.StatusServiceUnavailable)
		return
	}
	res, err := s.runSecurityTrust(r.Context(), t)
	if err != nil {
		http.Error(w, "trust check: "+err.Error(), http.StatusBadRequest)
		return
	}
	picked, err := res.Select(req.Digests, req.All)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	st := store.New(db)
	rootHash := guard.HashProjectRoot(t.root)
	items := sectrustitem.FromReasons(picked)
	n, err := st.AcceptSecTrustItems(r.Context(), rootHash, items, securityTrustAcceptor(), time.Now())
	if err != nil {
		http.Error(w, "accept: "+err.Error(), http.StatusInternalServerError)
		return
	}
	after, err := s.runSecurityTrust(r.Context(), t)
	if err != nil {
		http.Error(w, "trust check: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := securityTrustReply(t, after)
	resp.Accepted = n
	resp.AcceptAllowed = true
	writeJSON(w, resp)
}

// securityTrustAcceptor names who accepted from the dashboard: the surface
// and the local account the daemon runs as (the route is owner-local).
func securityTrustAcceptor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return "dashboard:" + name
}
