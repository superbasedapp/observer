package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/guardrecipesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Guard recipes (plan docs/plans/profile-guard-recipes-repo-grouping-plan-
// 2026-11-07.md section 3): the Security > Rules > Recipes card. A recipe is
// a strictness level plus function packs, applied to this machine or to one
// project as a managed file the guard folds in before the person's own
// policy file. internal/guardrecipesvc owns every read and write; these
// handlers resolve the request, take the config locks and answer.
//
//	GET  /api/guard/recipes              L  catalog, what is applied where, level drift, the confirm token
//	GET  /api/guard/recipes/show         V  one recipe and its raw file (?name=); one of the person's own recipes is shown on this machine only
//	GET  /api/guard/recipes/preview      V  what an apply or remove would change (?level=&packs=&scope=&project_root=[&remove=1]); a remote viewer gets no file paths and no compiled file
//	POST /api/guard/recipes/apply        L  apply {level, packs, scope, project_root}
//	POST /api/guard/recipes/remove       L  remove {scope, project_root}
//	POST /api/guard/recipes/user         L  save one of the person's recipes {name, toml}
//	POST /api/guard/recipes/user/delete  L  delete one of the person's recipes {name}
//	GET  /api/guard/simulate?recipe=1&…  V  the 7/30-day replay before and after (handleGuardSimulate)
//
// A recipe is a person's choice, never an agent's: the write routes are
// whole-route Local, carry the owner-local confirm token the catalog GET
// mints, and guard rule R-165 denies an agent's request to any of them
// (internal/policy/rules_selfapproval.go). Writes hold remoteManageMu and
// then, inside FileConfigWriter, configWriteMu (config.WriteLock), the
// order every whole-config read-modify-write takes.

// maxGuardRecipeBody bounds a recipe request body (a user recipe is at most
// 128 KiB, guardrecipe's own bound, plus the JSON around it).
const maxGuardRecipeBody = 256 << 10

// guardRecipeEnv builds the service env from the ON-DISK config and the
// project roots the daemon has seen, as every guard surface here does.
func (s *Server) guardRecipeEnv(ctx context.Context) (guardrecipesvc.Env, error) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return guardrecipesvc.Env{}, fmt.Errorf("load config: %w", err)
	}
	home, _ := os.UserHomeDir()
	roots, _ := store.New(s.db()).ProjectRoots(ctx)
	return guardrecipesvc.Env{
		Config: cfg, Home: home, KnownProjectRoots: roots, Now: s.now,
		GovernancePins: governancePinsInForce(s.opts.ConfigPath),
	}, nil
}

// governancePinsInForce is the governance overlay's pins in force for the
// config at path (nil without a config, a sidecar or on a load error), so a
// recipe preview shows the mode a pin holds (sweep finding CFG-9).
func governancePinsInForce(path string) map[string]any {
	gov, ok := governanceOutcome(path)
	if !ok {
		return nil
	}
	return gov.PinsInForce
}

// governanceApplied reports whether the governance overlay set key for the
// config at path (false without a config, a sidecar or on a load error).
func governanceApplied(path, key string) bool {
	gov, ok := governanceOutcome(path)
	return ok && slices.Contains(gov.Applied, key)
}

// governanceOutcome is what the governance overlay did for the config at
// path; ok is false without a config or on a load error.
func governanceOutcome(path string) (config.GovernanceOutcome, bool) {
	if path == "" {
		return config.GovernanceOutcome{}, false
	}
	if _, err := os.Stat(path); err != nil {
		return config.GovernanceOutcome{}, false
	}
	_, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return config.GovernanceOutcome{}, false
	}
	return gov, true
}

// guardRecipeScope parses a scope and checks a project root is one the
// daemon knows. The error status is the caller's answer.
func (s *Server) guardRecipeScope(r *http.Request, scope, root string) (guardrecipe.Scope, string, int, error) {
	sc := guardrecipe.Scope(strings.TrimSpace(scope))
	if sc == "" {
		sc = guardrecipe.ScopeGlobal
	}
	if !guardrecipe.ValidScope(sc) {
		return "", "", http.StatusBadRequest, fmt.Errorf("scope %q not in {global, project}", scope)
	}
	if sc == guardrecipe.ScopeGlobal {
		return sc, "", 0, nil
	}
	if !s.guardKnownProjectRoot(r, root) {
		return "", "", http.StatusConflict, errors.New("unknown project root: pick a project Observer has seen a session in")
	}
	return sc, root, 0, nil
}

// splitRecipePacks parses packs=a,b into a de-duplicated list.
func splitRecipePacks(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// handleGuardRecipes serves GET /api/guard/recipes.
func (s *Server) handleGuardRecipes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		writeErr(w, err)
		return
	}
	global, projects, issues := guardrecipesvc.ListApplied(env, set)
	if projects == nil {
		projects = []guardrecipesvc.Applied{}
	}
	all := append(append([]string{}, set.Issues...), issues...)
	resp := map[string]any{
		"catalog":       guardrecipesvc.CatalogViews(set),
		"issues":        all,
		"enabled":       env.Config.Guard.Enabled,
		"level":         env.Config.Guard.Level,
		"mode":          env.Config.Guard.Mode,
		"prompt_mode":   env.Config.Guard.Prompt.Mode,
		"global":        global,
		"projects":      projects,
		"level_drift":   guardrecipesvc.LevelDrift(env, global),
		"trusted_layer": guard.TrustedProjectPolicyPath(env.Config.Guard, env.Home, "/") != "",
		"user_layer":    guard.UserPolicyPath(env.Config.Guard, env.Home) != "",
		"recipe_dir":    guard.RecipeDir(env.Config.Guard, env.Home),
		"confirm_token": setConfirmCookie(w, r),
	}
	// ?project_root= names the project the card has picked, so it gets that
	// project's applied recipe even before the list refetches.
	if root := r.URL.Query().Get("project_root"); root != "" && s.guardKnownProjectRoot(r, root) {
		if a, err := guardrecipesvc.ReadApplied(env, set, guardrecipe.ScopeProject, root); err == nil {
			// ReadApplied alone carries no drift; the list's entry does.
			if a != nil {
				for _, p := range projects {
					if p.ProjectRoot == a.ProjectRoot {
						a.Drift = p.Drift
					}
				}
			}
			resp["project"] = a
		}
	}
	writeJSON(w, resp)
}

// handleGuardRecipeShow serves GET /api/guard/recipes/show?name=.
func (s *Server) handleGuardRecipeShow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		writeErr(w, err)
		return
	}
	rec, ok := set.Get(r.URL.Query().Get("name"))
	if !ok {
		http.Error(w, "no such recipe", http.StatusNotFound)
		return
	}
	// Sweep finding UI-7a: a built-in recipe is the same file on every
	// install, so it stays a View read; one of the person's own recipes is
	// their file, comments and notes included (a host name, a project's
	// name), so it is shown on this machine only, as a Local route would.
	if rec.Source == guardrecipe.SourceUser && remoteExposedFromContext(r.Context()) {
		http.Error(w, "your own recipes are shown on this machine only", http.StatusForbidden)
		return
	}
	writeJSON(w, map[string]any{"recipe": guardrecipesvc.ViewOf(rec), "toml": string(rec.Raw)})
}

// redactPreviewForRemote strips what a preview names of this machine's
// files for a remote viewer (sweep finding UI-7a): the recipe file's path
// and the compiled file (a user recipe's rows and notes), the replaced
// recipe's path, and the home directory wherever a problem or an issue
// names it. What changes (the rules, the modes, the level) stays.
func redactPreviewForRemote(pv *guardrecipesvc.Preview, home string) *guardrecipesvc.Preview {
	if pv == nil {
		return nil
	}
	out := *pv
	out.Path, out.Text = "", ""
	if pv.Replaces != nil {
		rep := *pv.Replaces
		rep.Path = ""
		out.Replaces = &rep
	}
	var dirs []string
	for _, d := range []string{pv.Path, home} {
		if d == pv.Path && d != "" {
			d = filepath.Dir(d)
		}
		if d != "" && d != "." && d != string(filepath.Separator) && d != "/" {
			dirs = append(dirs, d, filepath.ToSlash(d), filepath.FromSlash(d))
		}
	}
	scrub := func(list []string) []string {
		if len(list) == 0 {
			return list
		}
		next := make([]string, len(list))
		for i, s := range list {
			for _, d := range dirs {
				if d != "" {
					s = strings.ReplaceAll(s, d, "~")
				}
			}
			next[i] = s
		}
		return next
	}
	out.Problems, out.Issues = scrub(pv.Problems), scrub(pv.Issues)
	return &out
}

// writePreview answers a preview, redacted for a remote viewer.
func (s *Server) writePreview(w http.ResponseWriter, r *http.Request, env guardrecipesvc.Env, pv *guardrecipesvc.Preview) {
	if remoteExposedFromContext(r.Context()) {
		pv = redactPreviewForRemote(pv, env.Home)
	}
	writeJSON(w, pv)
}

// guardRecipeQuery is the selection a preview or a replay names in the
// query string.
type guardRecipeQuery struct {
	remove bool
	req    guardrecipesvc.Request
}

// parseGuardRecipeQuery reads level, packs, scope, project_root and remove.
func (s *Server) parseGuardRecipeQuery(r *http.Request) (guardRecipeQuery, int, error) {
	q := r.URL.Query()
	scope, root, status, err := s.guardRecipeScope(r, q.Get("scope"), q.Get("project_root"))
	if err != nil {
		return guardRecipeQuery{}, status, err
	}
	out := guardRecipeQuery{
		remove: q.Get("remove") == "1" || strings.EqualFold(q.Get("remove"), "true"),
		req: guardrecipesvc.Request{
			Level: strings.TrimSpace(q.Get("level")), Packs: splitRecipePacks(q.Get("packs")),
			Scope: scope, ProjectRoot: root, Via: "dashboard",
		},
	}
	if !out.remove && out.req.Level == "" && len(out.req.Packs) == 0 {
		return guardRecipeQuery{}, http.StatusBadRequest, errors.New("pick a level or at least one pack")
	}
	return out, 0, nil
}

// handleGuardRecipePreview serves GET /api/guard/recipes/preview.
func (s *Server) handleGuardRecipePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	sel, status, err := s.parseGuardRecipeQuery(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		writeErr(w, err)
		return
	}
	if sel.remove {
		pv, ok, err := guardrecipesvc.PreviewRemove(env, set, sel.req.Scope, sel.req.ProjectRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			http.Error(w, "no recipe is applied there", http.StatusNotFound)
			return
		}
		s.writePreview(w, r, env, pv)
		return
	}
	pv, err := guardrecipesvc.PreviewApply(env, set, sel.req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.writePreview(w, r, env, pv)
}

// guardRecipeReplay runs the simulate route's recipe=1 comparison: the same
// captured actions under the policy as it is and as the selection leaves it.
// The selection was parsed (and its project root checked) by the request that
// started the run; ctx is the run's own context, not a request's, because one
// run serves every identical request (guard_simulate_job.go). rfs and eval are
// the run's shared filesystem memo and its progress-counting evaluator.
func (s *Server) guardRecipeReplay(ctx context.Context, sel guardRecipeQuery, inputs []guard.ActionInput, rfs *guard.ReplayFS, eval func(*guard.Guard, []guard.ActionInput) []guard.ActionVerdict) (*guardrecipesvc.Replay, int, error) {
	env, err := s.guardRecipeEnv(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	env.ReplayFS, env.Evaluate = rfs, eval
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if sel.remove {
		rep, _, ok, err := guardrecipesvc.ReplayRemove(env, set, sel.req.Scope, sel.req.ProjectRoot, inputs)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if !ok {
			return nil, http.StatusNotFound, errors.New("no recipe is applied there")
		}
		return rep, 0, nil
	}
	rep, _, err := guardrecipesvc.ReplayApply(env, set, sel.req, inputs)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return rep, 0, nil
}

// decodeGuardRecipeBody decodes a write route's JSON body strictly.
func decodeGuardRecipeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGuardRecipeBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// handleGuardRecipeApply serves POST /api/guard/recipes/apply.
func (s *Server) handleGuardRecipeApply(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		Level       string   `json:"level"`
		Packs       []string `json:"packs"`
		Scope       string   `json:"scope"`
		ProjectRoot string   `json:"project_root"`
	}
	if !decodeGuardRecipeBody(w, r, &body) {
		return
	}
	scope, root, status, err := s.guardRecipeScope(r, body.Scope, body.ProjectRoot)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	req := guardrecipesvc.Request{
		Level: strings.TrimSpace(body.Level), Packs: splitRecipePacks(strings.Join(body.Packs, ",")),
		Scope: scope, ProjectRoot: root, Via: "dashboard",
	}
	if req.Level == "" && len(req.Packs) == 0 {
		http.Error(w, "pick a level or at least one pack", http.StatusBadRequest)
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		writeErr(w, err)
		return
	}
	pv, err := guardrecipesvc.PreviewApply(env, set, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(pv.Problems) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"applied": false, "problems": pv.Problems})
		return
	}
	res, err := guardrecipesvc.Apply(env, set, req, guardrecipesvc.FileConfigWriter(s.opts.ConfigPath))
	if err != nil {
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "guard_recipe_apply", fmt.Sprintf("scope=%s level=%s packs=%s changes=%d config_changed=%t",
		req.Scope, req.Level, strings.Join(req.Packs, ","), len(res.Preview.Changes), res.ConfigChanged))
	// Hook processes read config and policy per invocation, so the apply is
	// in force for new agent commands at once; the daemon binds policy and
	// the guard mode at start, so restart_required covers the proxy and
	// watcher paths only (the Recipes card's toast says the same, UI-5).
	writeJSON(w, map[string]any{"applied": true, "result": res, "restart_required": true})
}

// handleGuardRecipeRemove serves POST /api/guard/recipes/remove.
func (s *Server) handleGuardRecipeRemove(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		Scope       string `json:"scope"`
		ProjectRoot string `json:"project_root"`
	}
	if !decodeGuardRecipeBody(w, r, &body) {
		return
	}
	scope, root, status, err := s.guardRecipeScope(r, body.Scope, body.ProjectRoot)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		writeErr(w, err)
		return
	}
	// A remove the service would refuse (it would lower a rule or drop a
	// policy layer) answers 422 with every problem, like the apply route.
	if pv, ok, err := guardrecipesvc.PreviewRemove(env, set, scope, root); err != nil {
		writeErr(w, err)
		return
	} else if ok && len(pv.Problems) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"removed": false, "problems": pv.Problems})
		return
	}
	res, removed, err := guardrecipesvc.Remove(env, set, scope, root, guardrecipesvc.FileConfigWriter(s.opts.ConfigPath))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !removed {
		writeJSON(w, map[string]any{"removed": false, "restart_required": false})
		return
	}
	s.recordManageAudit(r, "guard_recipe_remove", fmt.Sprintf("scope=%s changes=%d config_changed=%t", scope, len(res.Preview.Changes), res.ConfigChanged))
	writeJSON(w, map[string]any{"removed": true, "result": res, "restart_required": true})
}

// handleGuardRecipeUser serves POST /api/guard/recipes/user: save one of the
// person's own recipes. It changes no policy until the recipe is applied.
func (s *Server) handleGuardRecipeUser(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		Name string `json:"name"`
		TOML string `json:"toml"`
	}
	if !decodeGuardRecipeBody(w, r, &body) {
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	rec, err := guardrecipesvc.SaveUserRecipe(env, strings.TrimSpace(body.Name), []byte(body.TOML))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.recordManageAudit(r, "guard_recipe_save", fmt.Sprintf("name=%s kind=%s version=%d", rec.Name, rec.Kind, rec.Version))
	writeJSON(w, map[string]any{"saved": true, "recipe": guardrecipesvc.ViewOf(rec)})
}

// handleGuardRecipeUserDelete serves POST /api/guard/recipes/user/delete.
func (s *Server) handleGuardRecipeUserDelete(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeGuardRecipeBody(w, r, &body) {
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	env, err := s.guardRecipeEnv(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := guardrecipesvc.DeleteUserRecipe(env, strings.TrimSpace(body.Name)); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.recordManageAudit(r, "guard_recipe_delete", "name="+strings.TrimSpace(body.Name))
	writeJSON(w, map[string]any{"deleted": true})
}
