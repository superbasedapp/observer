package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Guard policy-editor endpoints (G2.2, operator checkpoint Q3 FULL):
// the dashboard's read/edit surface over the §4.6 policy layers.
//
// Two write owners, both operator-surface (not the agent): the PUT on
// handleGuardPolicy writes the USER guard-policy.toml, and the PUT on
// handleGuardProjectPolicy writes the dashboard-authored TRUSTED
// per-project file under ~/.observer/guard-project-policies/ (R-160
// protects that dir, so the agent cannot). The IN-REPO project file
// belongs to its repo (the least-trusted layer — the agent can edit it,
// which R-161 flags) and the org bundle arrives signed from the org
// server; both stay read-only views. Every save is gated by the same
// strict parse `observer guard lint` runs (guard.Lint for the user
// layer; guard.LintTrustedProject — org-floor-aware — for the trusted
// layer) — a malformed body, or a trusted relaxation below the org
// floor, is refused 422 with the problems listed and the on-disk file
// untouched. Saves keep a .bak of the prior file; the backup endpoint
// mirrors handleConfigBackup's swap-restore (a second restore undoes
// the first) and accepts a {layer, project_root} target.

// guardPolicyLayerJSON is one layers-card row: a policy source in
// effect (or configured but absent), with counts where the file is a
// local TOML we can structurally parse. Org bundles are JSON
// envelopes — counts_known=false rather than a misleading zero.
type guardPolicyLayerJSON struct {
	Layer       string   `json:"layer"` // org | user | project | trusted_project
	Path        string   `json:"path"`
	Exists      bool     `json:"exists"`
	Editable    bool     `json:"editable"` // true for the user + trusted_project layers
	Version     string   `json:"version,omitempty"`
	ContentHash string   `json:"content_hash,omitempty"`
	CountsKnown bool     `json:"counts_known"`
	Rules       int      `json:"rules"`
	Overrides   int      `json:"overrides"`
	Disabled    int      `json:"disabled"`          // top-level `disable = [...]` count (trusted_project)
	Content     string   `json:"content,omitempty"` // carried inline for editable trusted_project rows
	Problems    []string `json:"problems,omitempty"`
	// Notes are NON-FATAL parse notes for a layer that IS loaded and in
	// force — today the org-bundle keys this binary does not understand
	// and ignored (a newer server published them). Deliberately NOT
	// folded into Problems: a note is not a load issue, and rendering
	// it as one would read as "your org policy is broken" when the org
	// floor is fully armed.
	Notes       []string `json:"notes,omitempty"`
	ProjectRoot string   `json:"project_root,omitempty"`
}

// handleGuardPolicy serves /api/guard/policy:
//
//   - GET → the layers card (org/user/project sources with paths,
//     lint problems, rule/override counts, construction load issues)
//     plus the user-layer editor payload (raw content + backup state).
//   - PUT {content} → save the USER policy file. Lint gates the save
//     (422 on any problem); the prior file is kept at <path>.bak; the
//     write is atomic (temp + rename). Restart-honest: the daemon
//     binds policy at start (hook processes read config per
//     invocation and follow immediately).
func (s *Server) handleGuardPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.serveGuardPolicyView(w, r)
	case http.MethodPut:
		s.saveGuardUserPolicy(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) serveGuardPolicyView(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	home, _ := os.UserHomeDir()
	st := store.New(s.opts.DB)
	roots, _ := st.ProjectRoots(r.Context())

	// Fresh construction from the ON-DISK config (the G1.5 idiom): the
	// same layers the daemon binds at start, so load issues here are
	// what the next restart would report. Construction failure
	// degrades to an empty issue list — the layers still render from
	// the file probes below (fail-open, like every guard surface).
	var loadIssues []string
	stateHash := map[string]string{} // layer → content hash
	orgState := guard.PolicyState{}
	if g, gerr := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots}); gerr == nil {
		loadIssues = g.LoadIssues()
		for _, ps := range g.PolicyStates() {
			stateHash[ps.Layer] = ps.ContentHash
			if ps.Layer == "org" {
				orgState = ps
			}
		}
	}
	if loadIssues == nil {
		loadIssues = []string{}
	}

	layers := make([]guardPolicyLayerJSON, 0, 2+len(roots))

	// Org bundle: signed, read-only; a JSON envelope, not a TOML we
	// can count rules out of structurally.
	if orgPath := guard.OrgBundlePath(cfg.Guard, home); orgPath != "" {
		row := guardPolicyLayerJSON{Layer: "org", Path: orgPath}
		if _, statErr := os.Stat(orgPath); statErr == nil {
			row.Exists = true
		}
		row.Version = orgState.Version
		row.ContentHash = stateHash["org"]
		row.Notes = orgState.Notes
		layers = append(layers, row)
	}

	// User layer: the editable one.
	userPath := guard.UserPolicyPath(cfg.Guard, home)
	userRow := guardPolicyLayerJSON{Layer: "user", Path: userPath, Editable: userPath != ""}
	var userContent string
	if userPath != "" {
		if raw, readErr := os.ReadFile(userPath); readErr == nil {
			userRow.Exists = true
			userContent = string(raw)
			userRow.CountsKnown = true
			ov, decl, dis, _ := guard.PolicyRuleRefs(raw)
			userRow.Rules, userRow.Overrides, userRow.Disabled = len(decl), len(ov), len(dis)
			userRow.Problems = guard.Lint(raw, "user")
			userRow.ContentHash = stateHash["user"]
		}
	}
	layers = append(layers, userRow)

	// Project layers: for every known project root emit the in-repo file
	// as a READ-ONLY row (it belongs to the repo, escalate-only) AND the
	// trusted daemon-local file as an EDITABLE row (dashboard-authored,
	// R-160-protected, weaken/disable-allowed). The trusted row is always
	// present so the UI can create one for a root that has none yet.
	for _, root := range roots {
		// In-repo project file (read-only).
		if p := guard.ProjectPolicyPath(cfg.Guard, root); p != "" {
			if raw, readErr := os.ReadFile(p); readErr == nil {
				ov, decl, dis, _ := guard.PolicyRuleRefs(raw)
				layers = append(layers, guardPolicyLayerJSON{
					Layer: "project", Path: p, Exists: true,
					CountsKnown: true, Rules: len(decl), Overrides: len(ov), Disabled: len(dis),
					Problems:    guard.Lint(raw, "project"),
					ProjectRoot: root,
				})
			}
		}
		// Trusted daemon-local project file (editable).
		if tp := guard.TrustedProjectPolicyPath(cfg.Guard, home, root); tp != "" {
			trow := guardPolicyLayerJSON{
				Layer: "trusted_project", Path: tp, Editable: true, ProjectRoot: root,
			}
			if raw, readErr := os.ReadFile(tp); readErr == nil {
				trow.Exists = true
				trow.Content = string(raw)
				trow.CountsKnown = true
				ov, decl, dis, _ := guard.PolicyRuleRefs(raw)
				trow.Rules, trow.Overrides, trow.Disabled = len(decl), len(ov), len(dis)
				trow.Problems = guard.LintTrustedProject(cfg.Guard, home, raw)
			}
			layers = append(layers, trow)
		}
	}

	backupExists := false
	backupPath := ""
	if userPath != "" {
		backupPath = userPath + ".bak"
		if _, statErr := os.Stat(backupPath); statErr == nil {
			backupExists = true
		}
	}
	writeJSON(w, map[string]any{
		"layers":      layers,
		"load_issues": loadIssues,
		"user": map[string]any{
			"path":          userPath,
			"exists":        userRow.Exists,
			"content":       userContent,
			"writable":      userPath != "",
			"backup_exists": backupExists,
			"backup_path":   backupPath,
		},
		"project_policy_relpath": cfg.Guard.Rules.ProjectPolicy,
	})
}

func (s *Server) saveGuardUserPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	path, err := s.guardUserPolicyPath()
	if err != nil {
		writeErr(w, err)
		return
	}
	if path == "" {
		http.Error(w, "no user policy path configured ([guard.rules] user_policy is empty)", http.StatusConflict)
		return
	}
	// The save gate: the exact strict parse `observer guard lint`
	// runs. A file that passes here is a file the guard loads with
	// zero issues at the next start.
	if problems := guard.Lint([]byte(req.Content), "user"); len(problems) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"saved": false, "problems": problems})
		return
	}
	if err := writeGuardPolicyFile(path, []byte(req.Content)); err != nil {
		writeErr(w, err)
		return
	}
	ov, decl, _, _ := guard.PolicyRuleRefs([]byte(req.Content))
	writeJSON(w, map[string]any{
		"saved":            true,
		"path":             path,
		"backup_path":      path + ".bak",
		"rules":            len(decl),
		"overrides":        len(ov),
		"restart_required": true,
	})
}

// handleGuardProjectPolicy serves /api/guard/policy/project (PUT only):
// the trusted per-project file writer.
func (s *Server) handleGuardProjectPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}
	s.saveGuardProjectPolicy(w, r)
}

// saveGuardProjectPolicy serves PUT /api/guard/policy/project — the ONLY
// dashboard path that writes the dashboard-authored TRUSTED per-project
// file (~/.observer/guard-project-policies/<hash>.toml). It mirrors
// saveGuardUserPolicy exactly, with two differences: the target path is
// resolved from {project_root} via guard.TrustedProjectPolicyPath (409
// when the trusted dir is unconfigured or the root is unknown), and the
// save gate is guard.LintTrustedProject (org-floor-aware — a relaxation
// below the org floor is refused 422, the file untouched). Local-only
// (L), SectionPolicies.
func (s *Server) saveGuardProjectPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectRoot string `json:"project_root"`
		Content     string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	home, _ := os.UserHomeDir()
	if !s.guardKnownProjectRoot(r, req.ProjectRoot) {
		http.Error(w, "unknown project root", http.StatusConflict)
		return
	}
	path := guard.TrustedProjectPolicyPath(cfg.Guard, home, req.ProjectRoot)
	if path == "" {
		http.Error(w, "no trusted project dir configured ([guard.rules] trusted_project_dir is empty) or empty project root", http.StatusConflict)
		return
	}
	// The save gate: the trusted-project parse+compile pass PLUS the real
	// org-floor check. A file that passes here loads with zero issues.
	if problems := guard.LintTrustedProject(cfg.Guard, home, []byte(req.Content)); len(problems) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"saved": false, "problems": problems})
		return
	}
	if err := writeGuardPolicyFile(path, []byte(req.Content)); err != nil {
		writeErr(w, err)
		return
	}
	ov, decl, dis, _ := guard.PolicyRuleRefs([]byte(req.Content))
	writeJSON(w, map[string]any{
		"saved":            true,
		"path":             path,
		"backup_path":      path + ".bak",
		"rules":            len(decl),
		"overrides":        len(ov),
		"disabled":         len(dis),
		"restart_required": true,
		"project_root":     req.ProjectRoot,
	})
}

// guardKnownProjectRoot reports whether root matches a project root the
// daemon has observed (path-normalized). A trusted per-project file may
// only be authored for a known root — an unknown root is a 409, not a
// silent write of an orphan file. Distinct from the guidance handler's
// knownProjectRoot, which reads the ?root= query param; here the root
// arrives in the request body / project_root query param.
func (s *Server) guardKnownProjectRoot(r *http.Request, root string) bool {
	if root == "" {
		return false
	}
	want := filepath.Clean(root)
	roots, _ := store.New(s.db()).ProjectRoots(r.Context())
	for _, have := range roots {
		if filepath.Clean(have) == want {
			return true
		}
	}
	return false
}

// handleGuardPolicyLint serves POST /api/guard/policy/lint — the
// editor's validate button and the PUT's save gate share the same
// check (guard.Lint, the parser `observer guard lint` runs). Always
// 200 with the findings; the refusal-on-malformed (422) lives on the
// PUT, where a write is actually at stake.
func (s *Server) handleGuardPolicyLint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Content string `json:"content"`
		Layer   string `json:"layer"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	layer := req.Layer
	if layer == "" {
		layer = "user"
	}
	if layer != "user" && layer != "project" && layer != "org" && layer != "trusted_project" {
		http.Error(w, `layer must be one of "user", "project", "trusted_project", "org"`, http.StatusBadRequest)
		return
	}
	var problems []string
	if layer == "trusted_project" {
		// Org-floor-aware lint (the same gate the trusted-project save
		// uses) so a relaxation below the org floor lints dirty here too.
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, fmt.Errorf("load config: %w", err))
			return
		}
		home, _ := os.UserHomeDir()
		problems = guard.LintTrustedProject(cfg.Guard, home, []byte(req.Content))
	} else {
		problems = guard.Lint([]byte(req.Content), layer)
	}
	if problems == nil {
		problems = []string{}
	}
	ov, decl, dis, _ := guard.PolicyRuleRefs([]byte(req.Content))
	writeJSON(w, map[string]any{
		"ok":        len(problems) == 0,
		"problems":  problems,
		"rules":     len(decl),
		"overrides": len(ov),
		"disabled":  len(dis),
	})
}

// handleGuardPolicyBackup serves /api/guard/policy/backup — the
// swap-undo over <policy>.bak, mirroring handleConfigBackup's contract:
// GET views the backup, POST swaps current and backup (so a second
// restore undoes the first). The backup must lint clean before it is
// restored — restoring a malformed policy would trade a bad save for a
// bad load. The target defaults to the user layer; ?layer=trusted_project
// &project_root=<root> selects a trusted per-project file instead (its
// restore lints through the org-floor-aware gate).
func (s *Server) handleGuardPolicyBackup(w http.ResponseWriter, r *http.Request) {
	path, lintFn, err := s.guardBackupTarget(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if path == "" {
		http.Error(w, "no policy path configured for the requested layer (user_policy / trusted_project_dir empty, or unknown project root)", http.StatusConflict)
		return
	}
	bakPath := path + ".bak"
	switch r.Method {
	case http.MethodGet:
		body, readErr := os.ReadFile(bakPath)
		if errors.Is(readErr, os.ErrNotExist) {
			writeJSON(w, map[string]any{"exists": false, "backup_path": bakPath})
			return
		}
		if readErr != nil {
			writeErr(w, readErr)
			return
		}
		var modifiedAt string
		if fi, statErr := os.Stat(bakPath); statErr == nil {
			modifiedAt = fi.ModTime().UTC().Format(time.RFC3339)
		}
		writeJSON(w, map[string]any{
			"exists":      true,
			"backup_path": bakPath,
			"modified_at": modifiedAt,
			"content":     string(body),
		})
	case http.MethodPost:
		bak, readErr := os.ReadFile(bakPath)
		if errors.Is(readErr, os.ErrNotExist) {
			http.Error(w, "no backup exists yet — backups are created on the first editor save over an existing file", http.StatusNotFound)
			return
		}
		if readErr != nil {
			writeErr(w, readErr)
			return
		}
		if problems := lintFn(bak); len(problems) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"restored": false,
				"problems": append([]string{"backup does not lint clean; not restoring"}, problems...),
			})
			return
		}
		cur, readErr := os.ReadFile(path)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			writeErr(w, readErr)
			return
		}
		if err := writeFileAtomic(path, bak); err != nil {
			writeErr(w, err)
			return
		}
		if len(cur) > 0 {
			if err := os.WriteFile(bakPath, cur, 0o644); err != nil { //nolint:gosec // G306: backup of the non-secret guard-policy.toml; mirrors the config-backup precedent.
				// Non-fatal: the restore landed; only the undo-of-undo is
				// degraded. Report it honestly.
				writeJSON(w, map[string]any{
					"restored":         true,
					"swap_incomplete":  true,
					"restart_required": true,
				})
				return
			}
		}
		writeJSON(w, map[string]any{
			"restored":         true,
			"restart_required": true,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// guardBackupTarget resolves the backup endpoint's target file and the
// layer-appropriate lint function from the request's ?layer / ?project_root
// query params. It defaults to the USER layer (path + guard.Lint(_,"user"))
// so an existing bare POST keeps working; ?layer=trusted_project&project_root
// =<root> selects the trusted per-project file (path + the org-floor-aware
// guard.LintTrustedProject). An unknown project root or an unconfigured
// trusted dir resolves to an empty path (the caller returns 409).
func (s *Server) guardBackupTarget(r *http.Request) (path string, lintFn func([]byte) []string, err error) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return "", nil, fmt.Errorf("load config: %w", err)
	}
	home, _ := os.UserHomeDir()
	if r.URL.Query().Get("layer") == "trusted_project" {
		root := r.URL.Query().Get("project_root")
		if !s.guardKnownProjectRoot(r, root) {
			return "", nil, nil
		}
		lintFn = func(b []byte) []string { return guard.LintTrustedProject(cfg.Guard, home, b) }
		return guard.TrustedProjectPolicyPath(cfg.Guard, home, root), lintFn, nil
	}
	lintFn = func(b []byte) []string { return guard.Lint(b, "user") }
	return guard.UserPolicyPath(cfg.Guard, home), lintFn, nil
}

// guardUserPolicyPath resolves the user policy file from the ON-DISK
// config — the same file guard.New loads at the next daemon start.
func (s *Server) guardUserPolicyPath() (string, error) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	home, _ := os.UserHomeDir()
	return guard.UserPolicyPath(cfg.Guard, home), nil
}

// writeGuardPolicyFile is the policy editor's write mechanics: keep
// the prior file at .bak, then atomic temp + rename — the same shape
// as config.WriteToml, inlined here because the payload is raw bytes
// rather than a marshalable struct.
func writeGuardPolicyFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ensure policy dir: %w", err)
	}
	if existing, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", existing, 0o644); err != nil { //nolint:gosec // G306: backup of the non-secret guard-policy.toml; mirrors the config-backup precedent.
			return fmt.Errorf("write .bak: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read current policy: %w", err)
	}
	return writeFileAtomic(path, content)
}

// writeFileAtomic writes content via a same-dir temp file + rename.
func writeFileAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guard-policy-*.toml")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpName, path, err)
	}
	return nil
}
