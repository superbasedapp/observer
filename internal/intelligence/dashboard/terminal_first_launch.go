package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_first_launch.go is the first-launch consent of the local
// dashboard's launchpad (door A, docs/plans/local-dashboard-first-run-
// options-2026-11-18.md section 8, step 3). On a fresh machine starting an
// agent from New terminal needs three [terminal.launch] opt-ins at once: the
// tool on allowed_tools, allow_fresh_agent on, and the folder on
// allowed_project_roots. The dialog shows them as ONE previewed step, and
// this route applies exactly that step.
//
// Why a route and not PUT /api/terminal/policy: the PUT canonicalizes every
// root through the filesystem, so a folder that does not exist yet cannot be
// previewed, and the first-launch folder on a machine with no history is a
// NEW ~/observer-playground that must be created only on consent. This route
// previews without creating it and, on the real save, creates it and writes
// the three changes in the one save pipeline (commitConfigEdit: dry run, the
// masked diff, the save at the previewed etag, read back, audited).
//
// It applies exactly the previewed changes and refuses anything else:
//   - the body names the tool, the folder and the change list the person
//     saw; unknown fields are refused;
//   - the route computes the change list itself from the loaded config
//     (firstLaunchPlan, a rule table) and refuses with 409 plan_changed
//     when it differs from the one the person saw;
//   - it never removes or rewrites anything: a tool and a root are appended,
//     allow_fresh_agent only ever goes on, every other key is untouched;
//   - the only folder it creates is the playground path it computes itself.
//
// The route is whole-route Local (owner-loopback only) like the policy
// editor, the POST needs the double-submit confirm token, and the guard's
// self-approval rule (internal/policy rules_selfapproval.go) denies it to an
// agent the same way it denies PUT /api/terminal/policy.

// firstLaunchPlaygroundName is the folder created under the home directory
// for a first launch on a machine with no project history.
const firstLaunchPlaygroundName = "observer-playground"

// firstLaunchHome resolves the home directory (a seam so tests can point it
// at a temporary directory).
var firstLaunchHome = os.UserHomeDir

// firstLaunchChange is one change the consent can make, in the order the
// dialog lists them.
type firstLaunchChange string

const (
	// changeAllowTool appends the tool to [terminal.launch].allowed_tools.
	changeAllowTool firstLaunchChange = "allow_tool"
	// changeAllowFresh turns [terminal.launch].allow_fresh_agent on.
	changeAllowFresh firstLaunchChange = "allow_fresh"
	// changeAllowFolder appends the folder to allowed_project_roots.
	changeAllowFolder firstLaunchChange = "allow_folder"
	// changeCreateFolder creates the playground folder (no config key).
	changeCreateFolder firstLaunchChange = "create_folder"
)

// firstLaunchState is what the plan reads: the loaded policy and the asked
// tool and folder, already resolved.
type firstLaunchState struct {
	allowedTools []string
	freshOn      bool
	allowedRoots []string
	tool         string
	// folder is the canonical folder ("" = the agent's default directory,
	// which needs no allow-list entry).
	folder string
	// folderMissing is true only for the playground folder that does not
	// exist yet.
	folderMissing bool
}

// firstLaunchRules is the ordered rule table firstLaunchPlan walks: each row
// is one change and the condition that makes it needed. One test case per row
// (terminal_first_launch_test.go).
var firstLaunchRules = []struct {
	change firstLaunchChange
	needed func(s firstLaunchState) bool
}{
	{changeAllowTool, func(s firstLaunchState) bool { return !containsString(s.allowedTools, s.tool) }},
	{changeAllowFresh, func(s firstLaunchState) bool { return !s.freshOn }},
	{changeAllowFolder, func(s firstLaunchState) bool { return s.folder != "" && !rootCovered(s.folder, s.allowedRoots) }},
	{changeCreateFolder, func(s firstLaunchState) bool { return s.folder != "" && s.folderMissing }},
}

// firstLaunchPlan returns the changes a first launch of s.tool in s.folder
// still needs, in table order. Empty means it can launch as configured.
func firstLaunchPlan(s firstLaunchState) []firstLaunchChange {
	out := []firstLaunchChange{}
	for _, r := range firstLaunchRules {
		if r.needed(s) {
			out = append(out, r.change)
		}
	}
	return out
}

// rootCovered reports whether the canonical folder equals or sits under one
// of the canonical allowed roots (the same containment the spawn path uses).
func rootCovered(folder string, roots []string) bool {
	f := filepath.Clean(folder)
	for _, r := range roots {
		rc := filepath.Clean(r)
		if f == rc {
			return true
		}
		rel, err := filepath.Rel(rc, f)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

// sameChanges reports whether two change lists hold the same changes (order
// does not matter; the person saw a list, not an ordering).
func sameChanges(a []firstLaunchChange, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	want := make([]string, len(a))
	for i, c := range a {
		want[i] = string(c)
	}
	got := append([]string(nil), b...)
	sort.Strings(want)
	sort.Strings(got)
	for i := range want {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// playgroundPaths returns the playground folder as the person reads it
// (home joined with the name) and its canonical form (the home directory's
// symlinks resolved, the spelling the allow-list stores once it exists).
func playgroundPaths() (display, canonical string, err error) {
	home, err := firstLaunchHome()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", "", fmt.Errorf("no home directory to create %s in", firstLaunchPlaygroundName)
	}
	display = filepath.Join(home, firstLaunchPlaygroundName)
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", "", fmt.Errorf("resolve home directory: %w", err)
	}
	return display, filepath.Join(realHome, firstLaunchPlaygroundName), nil
}

// firstLaunchBody is the POST body: what the person saw in the consent.
type firstLaunchBody struct {
	Tool    string   `json:"tool"`
	Folder  string   `json:"folder"`
	Changes []string `json:"changes"`
}

// handleTerminalFirstLaunch serves GET and POST /api/terminal/first-launch.
func (s *Server) handleTerminalFirstLaunch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTerminalFirstLaunchGet(w, r)
	case http.MethodPost:
		s.handleTerminalFirstLaunchPost(w, r)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// handleTerminalFirstLaunchGet names the playground folder (where a first
// launch goes on a machine with no project history) and whether it exists,
// and mints the confirm token the POST echoes.
func (s *Server) handleTerminalFirstLaunchGet(w http.ResponseWriter, r *http.Request) {
	confirmTok := setConfirmCookie(w, r)
	resp := map[string]any{
		"confirm_token":     confirmTok,
		"config_writable":   s.opts.ConfigPath != "",
		"playground_path":   "",
		"playground_exists": false,
	}
	if display, _, err := playgroundPaths(); err == nil {
		resp["playground_path"] = display
		if st, err := os.Stat(display); err == nil && st.IsDir() {
			resp["playground_exists"] = true
		}
	}
	writeJSON(w, resp)
}

// resolveFirstLaunchFolder turns the asked folder into its canonical form.
// The playground path (in either spelling) resolves without existing and
// reports missing when it does not exist; every other folder must already
// exist and pass the same canonicalization as the policy editor.
func resolveFirstLaunchFolder(raw string) (canonical string, missing, playground bool, err error) {
	folder := strings.TrimSpace(raw)
	if folder == "" {
		return "", false, false, nil
	}
	display, pgCanonical, pgErr := playgroundPaths()
	if pgErr == nil {
		c := filepath.Clean(folder)
		if c == display || c == pgCanonical {
			st, statErr := os.Stat(pgCanonical)
			switch {
			case statErr == nil && st.IsDir():
				return pgCanonical, false, true, nil
			case statErr == nil:
				return "", false, true, fmt.Errorf("%s exists and is not a folder", display)
			case errors.Is(statErr, os.ErrNotExist):
				return pgCanonical, true, true, nil
			default:
				return "", false, true, fmt.Errorf("check %s: %w", display, statErr)
			}
		}
	}
	roots, err := canonicalizeProjectRoots([]string{folder})
	if err != nil {
		return "", false, false, err
	}
	if len(roots) != 1 {
		return "", false, false, fmt.Errorf("project root %q rejected", folder)
	}
	return roots[0], false, false, nil
}

// handleTerminalFirstLaunchPost previews (?dry_run=1) or applies
// (?base_etag=) the first-launch consent through the one save pipeline.
func (s *Server) handleTerminalFirstLaunchPost(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	var body firstLaunchBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "decode first-launch consent: "+err.Error(), http.StatusBadRequest)
		return
	}
	tools, err := validateLaunchableTools([]string{body.Tool})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(tools) != 1 {
		http.Error(w, "first-launch consent: a tool is required", http.StatusBadRequest)
		return
	}
	tool := tools[0]
	folder, missing, playground, err := resolveFirstLaunchFolder(body.Folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"

	var plan []firstLaunchChange
	created := false
	// The folder is created inside the save's locks, after the plan matched,
	// and removed again (only if still empty) when the save does not land, so
	// a refused or failed write leaves no folder behind.
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.commitConfigEdit(rec, r, configEdit{
		section:       "terminal.launch",
		keysOnNewFile: true,
		edit: func(cfg *config.Config) (any, error) {
			plan = firstLaunchPlan(firstLaunchState{
				allowedTools:  cfg.Terminal.Launch.AllowedTools,
				freshOn:       cfg.Terminal.Launch.AllowFreshAgent,
				allowedRoots:  cfg.Terminal.Launch.AllowedProjectRoots,
				tool:          tool,
				folder:        folder,
				folderMissing: missing,
			})
			if !sameChanges(plan, body.Changes) {
				return nil, configEditRefusal{
					status: http.StatusConflict,
					msg:    fmt.Sprintf("plan_changed: the launch settings changed since the preview; this launch now needs %s - review it again", changeList(plan)),
				}
			}
			for _, c := range plan {
				switch c {
				case changeAllowTool:
					cfg.Terminal.Launch.AllowedTools = appendSorted(cfg.Terminal.Launch.AllowedTools, tool)
				case changeAllowFresh:
					cfg.Terminal.Launch.AllowFreshAgent = true
				case changeAllowFolder:
					cfg.Terminal.Launch.AllowedProjectRoots = appendSorted(cfg.Terminal.Launch.AllowedProjectRoots, folder)
				case changeCreateFolder:
					if dryRun {
						continue
					}
					if !playground {
						return nil, configEditRefusal{status: http.StatusBadRequest, msg: "only the playground folder can be created"}
					}
					if err := os.Mkdir(folder, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
						return nil, fmt.Errorf("create %s: %w", folder, err)
					}
					created = true
				}
			}
			return nil, nil
		},
		auditAction: "terminal_first_launch",
		auditDetailFor: func(config.Config) string {
			return fmt.Sprintf("tool=%s changes=%s", tool, changeList(plan))
		},
		extra: func(cfg config.Config) map[string]any {
			names := make([]string, len(plan))
			for i, c := range plan {
				names[i] = string(c)
			}
			return map[string]any{
				"tool":             tool,
				"folder":           folder,
				"changes":          names,
				"folder_created":   created,
				"restart_required": s.launchPolicyRestartRequired(),
			}
		},
	})
	if created && rec.status >= 400 {
		_ = os.Remove(folder) // only succeeds while it is still empty
	}
}

// changeList renders a plan for a message ("nothing" when empty).
func changeList(plan []firstLaunchChange) string {
	if len(plan) == 0 {
		return "nothing"
	}
	names := make([]string, len(plan))
	for i, c := range plan {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

// appendSorted appends v once and keeps the persisted order stable (the
// policy editor stores both lists sorted).
func appendSorted(list []string, v string) []string {
	if containsString(list, v) {
		return list
	}
	out := append(append([]string(nil), list...), v)
	sort.Strings(out)
	return out
}

// statusRecorder remembers the status a handler wrote, so the route can undo
// its own folder creation when the save answered an error.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status and passes it on.
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
