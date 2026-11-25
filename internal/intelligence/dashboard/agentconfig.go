package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigorg"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The AI tool settings page (backlog items 2 and 7, phases P4 and P5;
// docs/plans/adapter-config-and-common-vocabulary-plan-2026-10-03.md
// sections 5 and 7). Every route is the nav section "agent-config", so a
// managed node's page visibility (D-185) governs it like any other page.
//
//	GET  /api/agent-config/coverage                V  catalogue coverage (no file reads)
//	GET  /api/agent-config/tools                   L  tool picker + confirm token
//	GET  /api/agent-config/tool                    L  one tool's files, settings, effective values
//	GET  /api/agent-config/file                    L  one file's text, secrets masked
//	GET  /api/agent-config/common                  L  the common vocabulary across tools
//	GET  /api/agent-config/instructions            L  instruction / skill / agent files
//	GET  /api/agent-config/instructions/new-path   L  the path a new skill / agent would take
//	GET  /api/agent-config/history                 L  saves (key names only)
//	POST /api/agent-config/preview                 L  hygiene pipeline, read-shaped (nothing written)
//	POST /api/agent-config/save                    L  confirm token; the whole pipeline
//	POST /api/agent-config/common/preview          L  L1 fan-out preview, read-shaped
//	POST /api/agent-config/common/save             L  confirm token; L1 fan-out write
//	GET  /api/agent-config/org                     L  the org AI tool policy and what this node did with it
//	POST /api/agent-config/org/apply               L  confirm token; apply the org policy now (managed only)
//
// The reads are Local, not View: they read the developer's own vendor
// files (secrets masked, but env blocks and command strings are personal).

const agentConfigMaxBody = 4 << 20

// agentConfigService builds the editor boundary for this request.
func (s *Server) agentConfigService() *agentconfigsvc.Service {
	return s.agentConfigServiceFor("dashboard")
}

// agentConfigServiceFor builds the boundary with a history origin ("org"
// for the org policy apply).
func (s *Server) agentConfigServiceFor(origin string) *agentconfigsvc.Service {
	var st agentconfigsvc.LayerStore
	if s.db() != nil {
		st = store.New(s.db())
	}
	port := s.opts.ProxyPort
	return agentconfigsvc.New(agentconfigsvc.Options{
		Store: st,
		Lock:  hook.LockSettingsFile,
		ProxyAddrs: []string{
			"127.0.0.1:" + strconv.Itoa(port), "localhost:" + strconv.Itoa(port), "[::1]:" + strconv.Itoa(port),
		},
		Captured:   s.agentConfigCaptured,
		Access:     s.agentConfigAccess,
		EditGrants: s.agentConfigEditGrants,
		Origin:     origin,
	})
}

// agentConfigAccess is the node's write posture for the editor
// (agentconfigorg.NodeAccess): a managed node is read-only until its
// organization's AI tool policy arrives (D-102), then follows it (enforced
// settings locked, grants, the org's secrets posture); an organization's
// read-only choice for the page applies on any node that granted it
// (D-130). An individual node edits freely.
func (s *Server) agentConfigAccess(ctx context.Context) agentconfig.Access {
	if s.opts.Governance == nil {
		return agentconfig.Access{SecretsPosture: agentconfig.SecretsWarn}
	}
	eff := s.opts.Governance(ctx)
	lvl, src := eff.NavVisibility(string(SectionAgentConfig))
	in := agentconfigorg.NodeAccessInput{
		Managed:         eff.ManagedDefaultsApply(),
		PageReadOnly:    lvl == nodegov.VisibilityReadOnly,
		PageFromDefault: src == govern.VisibilitySourceDefault,
	}
	if in.Managed && s.db() != nil {
		if body, _, ok := store.New(s.db()).OrgAgentConfigBody(ctx); ok {
			in.Body = &body
		}
		in.EditGrants = s.agentConfigEditGrants(ctx, time.Now())
	}
	return agentconfigorg.NodeAccess(in)
}

// agentConfigEditGrants reads the honoured AI tool setting edit grants
// (T-436) from the verified grant cache; any failure opens nothing.
func (s *Server) agentConfigEditGrants(ctx context.Context, now time.Time) []string {
	if s.db() == nil {
		return nil
	}
	got, err := orgclient.ConfigEditGrants(ctx, store.New(s.db()), now)
	if err != nil {
		return nil
	}
	return got
}

// agentConfigPolicyHeld reports a verified org AI tool policy cached here
// (pageDefaultSupersedes).
func (s *Server) agentConfigPolicyHeld(ctx context.Context) bool {
	if s.db() == nil {
		return false
	}
	_, _, ok := store.New(s.db()).OrgAgentConfigBody(ctx)
	// An AI tool setting edit grant (T-436) is the organization's
	// permission too, so it supersedes the default read-only page as well.
	return ok || len(s.agentConfigEditGrants(ctx, time.Now())) > 0
}

// agentConfigCaptured reports a tool whose adapter this node runs, so a
// setting that would switch off its capture is refused while integrated.
func (s *Server) agentConfigCaptured(tool string) bool {
	if s.opts.ConfigPath == "" {
		return false
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		// Unknown posture: treat the tool as captured (the refusal is the
		// safe direction; the developer can still edit by hand).
		return true
	}
	for _, a := range cfg.Observer.Watch.EnabledAdapters {
		if a == tool {
			return true
		}
	}
	return false
}

// agentConfigProject validates the optional project root against the
// projects Observer knows (a write can never be aimed at an arbitrary
// directory). "" is valid (no project).
func (s *Server) agentConfigProject(ctx context.Context, root string) (string, bool) {
	if strings.TrimSpace(root) == "" {
		return "", true
	}
	want := filepath.Clean(root)
	if s.db() == nil {
		return "", false
	}
	roots, err := store.New(s.db()).ProjectRoots(ctx)
	if err != nil {
		return "", false
	}
	for _, r := range roots {
		if filepath.Clean(r) == want {
			return want, true
		}
	}
	return "", false
}

func (s *Server) agentConfigQueryProject(w http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := s.agentConfigProject(r.Context(), r.URL.Query().Get("project"))
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "unknown_project", "message": "That project is not one Observer has captured activity for."})
	}
	return p, ok
}

// writeAgentConfigErr maps the service's errors onto statuses.
func writeAgentConfigErr(w http.ResponseWriter, err error) {
	var se *agentconfigsvc.SaveError
	var ce *agentconfigsvc.CommonSaveError
	var preview any
	switch {
	case errors.As(err, &se):
		preview = se.Preview
	case errors.As(err, &ce):
		preview = ce.Preview
	}
	body := map[string]any{"error": "", "message": err.Error()}
	if preview != nil {
		body["preview"] = preview
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, agentconfigsvc.ErrUnknownTool), errors.Is(err, agentconfigsvc.ErrUnknownFile):
		status, body["error"] = http.StatusNotFound, "unknown"
	case errors.Is(err, agentconfigsvc.ErrBadTarget), errors.Is(err, agentconfig.ErrUnknownCommonKey), errors.Is(err, agentconfig.ErrBadValue):
		status, body["error"] = http.StatusBadRequest, "bad_request"
	case errors.Is(err, agentconfigsvc.ErrNotEditable):
		status, body["error"] = http.StatusConflict, "not_editable"
	case errors.Is(err, agentconfigsvc.ErrBlocked):
		status, body["error"] = http.StatusUnprocessableEntity, "hygiene_refused"
		body["message"] = "The sanity check refused this save; see the findings."
	case errors.Is(err, agentconfigsvc.ErrStale):
		status, body["error"] = http.StatusConflict, "stale"
		body["message"] = "The file changed since the preview (or the preview was not run). Review the new preview, then save again."
	case errors.Is(err, agentconfigsvc.ErrConfirm):
		status, body["error"] = http.StatusPreconditionRequired, "confirm_required"
		body["message"] = "This save changes a setting that can loosen the tool's safety. Confirm it to save."
	case errors.Is(err, agentconfigsvc.ErrReadBackFailed):
		body["error"] = "read_back_failed"
	default:
		body["error"] = "internal"
	}
	writeJSONStatus(w, status, body)
}

func (s *Server) handleAgentConfigCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"coverage":    agentconfig.Coverage(),
		"common_keys": agentconfig.CommonSpecs(),
		"schemas":     agentconfig.SchemaPins(),
	})
}

func (s *Server) handleAgentConfigTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	svc := s.agentConfigService()
	writeJSON(w, map[string]any{
		"tools":         svc.Tools(r.Context()),
		"access":        s.agentConfigAccess(r.Context()),
		"confirm_token": setConfirmCookie(w, r),
	})
}

func (s *Server) handleAgentConfigTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	project, ok := s.agentConfigQueryProject(w, r)
	if !ok {
		return
	}
	v, err := s.agentConfigService().Inspect(r.Context(), r.URL.Query().Get("tool"), project)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) handleAgentConfigFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	project, ok := s.agentConfigQueryProject(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	rv, err := s.agentConfigService().Raw(r.Context(), agentconfigsvc.Target{
		Tool: q.Get("tool"), FileID: q.Get("file_id"), Project: project, Path: q.Get("path"),
	})
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, rv)
}

func (s *Server) handleAgentConfigCommon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	project, ok := s.agentConfigQueryProject(w, r)
	if !ok {
		return
	}
	keys, err := s.agentConfigService().CommonView(r.Context(), project)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"keys": keys, "access": s.agentConfigAccess(r.Context())})
}

func (s *Server) handleAgentConfigInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	project, ok := s.agentConfigQueryProject(w, r)
	if !ok {
		return
	}
	files, err := s.agentConfigService().Instructions(r.Context(), r.URL.Query().Get("tool"), project)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	if files == nil {
		files = []agentconfigsvc.InstructionFile{}
	}
	writeJSON(w, map[string]any{"files": files})
}

func (s *Server) handleAgentConfigNewPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	project, ok := s.agentConfigQueryProject(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	p, err := s.agentConfigService().NewInstructionPath(agentconfigsvc.Target{Tool: q.Get("tool"), FileID: q.Get("file_id"), Project: project}, q.Get("name"))
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"path": p})
}

func (s *Server) handleAgentConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.agentConfigService().History(r.Context(), r.URL.Query().Get("tool"), intArg(r, "limit", 50, 1, 500))
	if err != nil {
		writeErr(w, err)
		return
	}
	type row struct {
		ID          int64    `json:"id"`
		At          string   `json:"at"`
		Tool        string   `json:"tool"`
		FileID      string   `json:"file_id"`
		Path        string   `json:"path"`
		Layer       string   `json:"layer"`
		CommonKey   string   `json:"common_key,omitempty"`
		Origin      string   `json:"origin"`
		Mode        string   `json:"mode"`
		ChangedKeys []string `json:"changed_keys"`
		BackupPath  string   `json:"backup_path,omitempty"`
		Created     bool     `json:"created,omitempty"`
		Warnings    int      `json:"warnings"`
	}
	out := make([]row, 0, len(rows))
	for _, h := range rows {
		out = append(out, row{
			ID: h.ID, At: h.At.UTC().Format("2006-01-02T15:04:05Z"), Tool: h.Tool, FileID: h.FileID, Path: h.FilePath,
			Layer: h.Layer, CommonKey: h.CommonKey, Origin: h.Origin, Mode: h.Mode, ChangedKeys: h.ChangedKeys,
			BackupPath: h.BackupPath, Created: h.Created, Warnings: h.Warnings,
		})
	}
	writeJSON(w, map[string]any{"rows": out})
}

// decodeAgentConfigBody decodes a JSON body and validates its project.
func (s *Server) decodeAgentConfigBody(w http.ResponseWriter, r *http.Request, v any, project *string) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, agentConfigMaxBody))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	if project != nil {
		p, ok := s.agentConfigProject(r.Context(), *project)
		if !ok {
			writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "unknown_project", "message": "That project is not one Observer has captured activity for."})
			return false
		}
		*project = p
	}
	return true
}

func (s *Server) handleAgentConfigPreview(w http.ResponseWriter, r *http.Request) {
	var req agentconfigsvc.SaveRequest
	if !s.decodeAgentConfigBody(w, r, &req, &req.Project) {
		return
	}
	for i := range req.Edits {
		req.Edits[i].Value = cfgfmt.NativeNumbers(req.Edits[i].Value)
	}
	p, err := s.agentConfigService().Preview(r.Context(), req)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) handleAgentConfigSave(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req agentconfigsvc.SaveRequest
	if !s.decodeAgentConfigBody(w, r, &req, &req.Project) {
		return
	}
	for i := range req.Edits {
		req.Edits[i].Value = cfgfmt.NativeNumbers(req.Edits[i].Value)
	}
	out, err := s.agentConfigService().Save(r.Context(), req)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	if out.Saved {
		s.recordManageAudit(r, "agent_config_save", fmt.Sprintf("tool=%s file=%s changes=%d", req.Tool, out.FileID, len(out.Changes)))
	}
	writeJSON(w, out)
}

func (s *Server) handleAgentConfigCommonPreview(w http.ResponseWriter, r *http.Request) {
	var req agentconfigsvc.CommonRequest
	if !s.decodeAgentConfigBody(w, r, &req, &req.Project) {
		return
	}
	req.Value = cfgfmt.NativeNumbers(req.Value)
	p, err := s.agentConfigService().CommonPreview(r.Context(), req)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) handleAgentConfigCommonSave(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req agentconfigsvc.CommonRequest
	if !s.decodeAgentConfigBody(w, r, &req, &req.Project) {
		return
	}
	req.Value = cfgfmt.NativeNumbers(req.Value)
	if a := s.agentConfigAccess(r.Context()); a.ReadOnly {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "not_editable", "message": a.Reason})
		return
	}
	out, err := s.agentConfigService().CommonSave(r.Context(), req)
	if err != nil {
		writeAgentConfigErr(w, err)
		return
	}
	if out.Saved {
		scope := "user"
		if req.Project != "" {
			scope = "project"
		}
		s.recordManageAudit(r, "agent_config_common_save", fmt.Sprintf("key=%s scope=%s files=%d", req.Key, scope, len(out.Written)))
	}
	writeJSON(w, out)
}
