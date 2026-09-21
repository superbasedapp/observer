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
// One write owner: handleGuardPolicy's PUT is the ONLY dashboard path
// that touches the user guard-policy.toml — and only the USER layer
// is writable here. Project files belong to their repos (the least-
// trusted layer — the agent can edit them, which R-161 itself flags),
// and the org bundle arrives signed from the org server; both stay
// read-only views. Every save is gated by the same strict parse
// `observer guard lint` runs (guard.Lint) — a malformed body is
// refused 422 with the problems listed and the on-disk file is
// untouched. Saves keep a .bak of the prior file; the backup endpoint
// mirrors handleConfigBackup's swap-restore (a second restore undoes
// the first).

// guardPolicyLayerJSON is one layers-card row: a policy source in
// effect (or configured but absent), with counts where the file is a
// local TOML we can structurally parse. Org bundles are JSON
// envelopes — counts_known=false rather than a misleading zero.
type guardPolicyLayerJSON struct {
	Layer       string   `json:"layer"` // org | user | project
	Path        string   `json:"path"`
	Exists      bool     `json:"exists"`
	Editable    bool     `json:"editable"` // true only for the user layer
	Version     string   `json:"version,omitempty"`
	ContentHash string   `json:"content_hash,omitempty"`
	CountsKnown bool     `json:"counts_known"`
	Rules       int      `json:"rules"`
	Overrides   int      `json:"overrides"`
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
			ov, decl, _ := guard.PolicyRuleRefs(raw)
			userRow.Rules, userRow.Overrides = len(decl), len(ov)
			userRow.Problems = guard.Lint(raw, "user")
			userRow.ContentHash = stateHash["user"]
		}
	}
	layers = append(layers, userRow)

	// Project layers: probe every known project root for the
	// configured relative path. Read-only views — these files belong
	// to their repos.
	for _, root := range roots {
		p := guard.ProjectPolicyPath(cfg.Guard, root)
		if p == "" {
			continue
		}
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			continue
		}
		ov, decl, _ := guard.PolicyRuleRefs(raw)
		layers = append(layers, guardPolicyLayerJSON{
			Layer: "project", Path: p, Exists: true,
			CountsKnown: true, Rules: len(decl), Overrides: len(ov),
			Problems:    guard.Lint(raw, "project"),
			ProjectRoot: root,
		})
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
	ov, decl, _ := guard.PolicyRuleRefs([]byte(req.Content))
	writeJSON(w, map[string]any{
		"saved":            true,
		"path":             path,
		"backup_path":      path + ".bak",
		"rules":            len(decl),
		"overrides":        len(ov),
		"restart_required": true,
	})
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
	if layer != "user" && layer != "project" && layer != "org" {
		http.Error(w, `layer must be one of "user", "project", "org"`, http.StatusBadRequest)
		return
	}
	problems := guard.Lint([]byte(req.Content), layer)
	if problems == nil {
		problems = []string{}
	}
	ov, decl, _ := guard.PolicyRuleRefs([]byte(req.Content))
	writeJSON(w, map[string]any{
		"ok":        len(problems) == 0,
		"problems":  problems,
		"rules":     len(decl),
		"overrides": len(ov),
	})
}

// handleGuardPolicyBackup serves /api/guard/policy/backup — the
// swap-undo over <user-policy>.bak, mirroring handleConfigBackup's
// contract: GET views the backup, POST swaps current and backup (so a
// second restore undoes the first). The backup must lint clean before
// it is restored — restoring a malformed policy would trade a bad
// save for a bad load.
func (s *Server) handleGuardPolicyBackup(w http.ResponseWriter, r *http.Request) {
	path, err := s.guardUserPolicyPath()
	if err != nil {
		writeErr(w, err)
		return
	}
	if path == "" {
		http.Error(w, "no user policy path configured ([guard.rules] user_policy is empty)", http.StatusConflict)
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
		if problems := guard.Lint(bak, "user"); len(problems) > 0 {
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
