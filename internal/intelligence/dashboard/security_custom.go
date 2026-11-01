//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// security_custom.go serves /api/security/scanners/custom, the Code
// security page's custom scanner section (security pillar plan section
// 8.6, Phase D3; component security.scan.custom, whose route row makes the
// component guard answer 404 while it is inactive). Every route is
// owner-local: a scanner runs a program on this machine. Every write needs
// the confirm token the GET mints, and an agent reaching the accept route
// over HTTP is refused by guard rule R-165.
//
//	GET  /api/security/scanners/custom          the scanners, templates and every picker's closed set
//	POST /api/security/scanners/custom/preview  a manifest in full, with what discovery found and its digest
//	POST /api/security/scanners/custom/accept   accept exactly the shown digest, then self-test in the background
//	POST /api/security/scanners/custom/remove   remove one
//	POST /api/security/scanners/custom/selftest run a self-test now
//	POST /api/security/scanners/custom/run      scan a project now
//	GET  /api/security/scanners/custom/audit    the audit log

// customScanners is what the routes need of the service.
type customScanners interface {
	Layout() seccustomsvc.Layout
	Records(ctx context.Context) ([]seccustom.Record, map[string]string)
	Prepare(ctx context.Context, src seccustomsvc.Source, c seccustom.Choices) (seccustomsvc.Prepared, error)
	Accept(ctx context.Context, src seccustomsvc.Source, c seccustom.Choices, confirmed, via string) (seccustom.Record, error)
	Remove(ctx context.Context, id, via string) error
	SelfTest(ctx context.Context, id string) (seccustom.SelfTestState, error)
	Run(ctx context.Context, id, projectRoot string, scope secfinding.Scope) (seccustomsvc.RunReport, error)
	// RequiredMissingAmong takes the records Records returned, so a GET
	// checks each record once.
	RequiredMissingAmong(ctx context.Context, checked []seccustom.Record) []string
}

func (s *Server) customScanners() (customScanners, bool) {
	cs, ok := s.opts.CustomScanners.(customScanners)
	return cs, ok && cs != nil
}

// customTemplateJS is one template on the GET.
type customTemplateJS struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Note  string `json:"note"`
}

// customPickersJS are the closed sets every picker offers.
type customPickersJS struct {
	Limits       map[string][]int `json:"limits"`
	ChildrenUnit string           `json:"children_unit"`
	Inputs       []string         `json:"inputs"`
	Outputs      []string         `json:"outputs"`
	Caches       []string         `json:"caches"`
	Categories   []string         `json:"categories"`
	Severities   []string         `json:"severities"`
}

func customPickers() customPickersJS {
	p := customPickersJS{
		Limits:       map[string][]int{},
		ChildrenUnit: seccustom.ChildrenUnit(runtime.GOOS),
		Inputs:       []string{string(seccustom.InputStdin), string(seccustom.InputTargetsFile)},
		Outputs:      []string{string(seccustom.OutputSARIFFile), string(seccustom.OutputSARIFStdout)},
		Caches:       []string{string(seccustom.CacheNone), string(seccustom.CachePerDriver)},
	}
	for _, f := range seccustom.LimitFields() {
		p.Limits[string(f)] = seccustom.LimitSteps(f)
	}
	for _, c := range seccustom.Categories() {
		p.Categories = append(p.Categories, string(c))
	}
	for _, sv := range policy.FindingSeverities() {
		p.Severities = append(p.Severities, string(sv))
	}
	return p
}

// handleSecurityCustom serves GET /api/security/scanners/custom.
func (s *Server) handleSecurityCustom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cs, ok := s.customScanners()
	if !ok {
		writeCompiledOut(w, seccustom.ComponentID)
		return
	}
	recs, bad := cs.Records(r.Context())
	if recs == nil {
		recs = []seccustom.Record{}
	}
	var tpls []customTemplateJS
	for _, t := range seccustom.Templates() {
		tpls = append(tpls, customTemplateJS{ID: t.ID, Title: t.Title, Note: t.Note})
	}
	writeJSON(w, map[string]any{
		"scanners": recs, "unreadable": bad, "templates": tpls, "pickers": customPickers(),
		"org_required_missing": cs.RequiredMissingAmong(r.Context(), recs),
		"confirm_token":        setConfirmCookie(w, r),
	})
}

// customBody is a write's request.
type customBody struct {
	Template string            `json:"template,omitempty"`
	File     string            `json:"file,omitempty"`
	Choices  seccustom.Choices `json:"choices"`
	Confirm  string            `json:"manifest_sha256,omitempty"`
	ID       string            `json:"id,omitempty"`
	// Dir is the root of a known project, picked from /api/projects.
	Dir string `json:"dir,omitempty"`
}

func (b customBody) source() seccustomsvc.Source {
	if b.Template != "" {
		return seccustomsvc.Source{Template: b.Template}
	}
	if b.File == "" {
		return seccustomsvc.Source{}
	}
	return seccustomsvc.Source{File: []byte(b.File)}
}

// handleSecurityCustomSub serves the write routes and the audit log.
func (s *Server) handleSecurityCustomSub(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.customScanners()
	if !ok {
		writeCompiledOut(w, seccustom.ComponentID)
		return
	}
	verb := strings.TrimPrefix(r.URL.Path, "/api/security/scanners/custom/")
	if verb == "audit" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, map[string]any{"audit": cs.Layout().Audit(200)})
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	var b customBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*seccustom.MaxManifestBytes)).Decode(&b); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	switch verb {
	case "preview":
		p, err := cs.Prepare(ctx, b.source(), b.Choices)
		customReply(w, p, err)
	case "accept":
		rec, err := cs.Accept(ctx, b.source(), b.Choices, b.Confirm, "dashboard")
		if err == nil && rec.Manifest.SelfTest != nil {
			// The self-test runs off the request (it can take a minute
			// with a cold build cache); the list shows its state.
			go func(id string) { _, _ = cs.SelfTest(context.WithoutCancel(ctx), id) }(rec.ID)
		}
		customReply(w, rec, err)
	case "remove":
		err := cs.Remove(ctx, b.ID, "dashboard")
		customReply(w, map[string]string{"removed": b.ID}, err)
	case "selftest":
		st, err := cs.SelfTest(ctx, b.ID)
		customReply(w, st, err)
	case "run":
		root, err := s.customProjectRoot(ctx, b.Dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rep, err := cs.Run(ctx, b.ID, root, policy.FindingScopeManual)
		customReply(w, rep, err)
	default:
		http.NotFound(w, r)
	}
}

// customReply writes v, or the refusal as 422 with its plain sentence.
func customReply(w http.ResponseWriter, v any, err error) {
	switch {
	case errors.Is(err, seccustomsvc.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, v)
	}
}

// errUnknownProject refuses a run against a directory this machine has
// not seen as a project: the run takes a project picked from the known
// list (the pickers rule, D-571), never a typed path.
var errUnknownProject = errors.New("pick a project this machine knows (the projects list); a typed directory is not accepted")

// customProjectRoot returns dir when it is the root of a project the
// projects table knows, exactly as stored.
func (s *Server) customProjectRoot(ctx context.Context, dir string) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", errors.New("dir must be the absolute root of a known project")
	}
	d := s.db()
	if d == nil {
		return "", errUnknownProject
	}
	var root string
	err := d.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE root_path = ? LIMIT 1`, dir).Scan(&root)
	if err != nil || root == "" {
		return "", errUnknownProject
	}
	return root, nil
}
