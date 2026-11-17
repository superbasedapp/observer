package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The "Launch binary paths" card on Settings > Session attach (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md, section 9). Before it the
// New Terminal preflight said "[launch.tools.<tool>].path is set, but nothing
// is there" with no dashboard control: launch.tools is a compound table the
// generic settings editor cannot write.
//
//	GET /api/launch/tool-paths  L  the overrides as a sorted list {tool, path, exists},
//	                               the confirm token, the config etag
//	PUT /api/launch/tool-paths  L  {"tool": "<id>", "path": "<abs>" | null}; null removes the
//	                               tool's entry; ?dry_run=1 previews the diff and writes nothing,
//	                               ?base_etag= refuses a config file that moved since the preview
//
// The write goes through the one config save pipeline (commitConfigEdit). A
// launch binary path decides which program a launch executes, so the real save
// carries the owner-local confirm token the GET mints (the pipeline's
// sensitive-tier rule cannot see this compound table, so the route demands it
// itself, like /api/update/auto-apply). The file is never executed here.

// launchToolPathMaxBytes bounds a stored path.
const launchToolPathMaxBytes = 4096

// launchToolPathRow is one [launch.tools.<tool>].path override.
type launchToolPathRow struct {
	Tool string `json:"tool"`
	Path string `json:"path"`
	// Exists reports a regular file at Path on this daemon's host.
	Exists bool `json:"exists"`
}

// launchToolPathsView is GET /api/launch/tool-paths.
type launchToolPathsView struct {
	Paths        []launchToolPathRow `json:"paths"`
	ConfirmToken string              `json:"confirm_token,omitempty"`
	ConfigEtag   string              `json:"config_etag,omitempty"`
}

// launchToolPathRequest is a PUT body. Remove is set by UnmarshalJSON when
// path is an explicit null, so removing differs from a missing field.
type launchToolPathRequest struct {
	Tool   string
	Path   string
	Remove bool
}

// UnmarshalJSON accepts exactly {"tool": "<id>", "path": "<abs>" | null}.
func (req *launchToolPathRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k := range raw {
		if k != "tool" && k != "path" {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	t, ok := raw["tool"]
	if !ok {
		return fmt.Errorf("tool is required")
	}
	if err := json.Unmarshal(t, &req.Tool); err != nil {
		return fmt.Errorf("tool must be a string")
	}
	p, ok := raw["path"]
	if !ok {
		return fmt.Errorf("path is required (a path, or null to remove)")
	}
	var ptr *string
	if err := json.Unmarshal(p, &ptr); err != nil {
		return fmt.Errorf("path must be a string or null")
	}
	if ptr == nil {
		req.Remove = true
		return nil
	}
	req.Path = *ptr
	return nil
}

// launchToolPathRule is one ordered validation row; a non-empty return is the
// refusal, in plain words.
type launchToolPathRule struct {
	name  string
	check func(tool, path string, mustExist bool) string
}

// launchToolPathRules is walked top-down; the first refusal wins. A removal only
// needs a named tool.
var launchToolPathRules = []launchToolPathRule{
	{"known tool", func(tool, _ string, _ bool) string {
		if strings.TrimSpace(tool) == "" {
			return "Choose a tool."
		}
		if _, ok := integration.For(tool); !ok {
			return fmt.Sprintf("%q is not a tool Observer knows.", tool)
		}
		return ""
	}},
	{"not empty", func(_, path string, _ bool) string {
		if strings.TrimSpace(path) == "" {
			return "Enter the full path to the program, or remove the override."
		}
		return ""
	}},
	{"length", func(_, path string, _ bool) string {
		if len(path) > launchToolPathMaxBytes {
			return fmt.Sprintf("That path is longer than %d bytes.", launchToolPathMaxBytes)
		}
		return ""
	}},
	{"no control characters", func(_, path string, _ bool) string {
		for _, r := range path {
			if r < 0x20 || r == 0x7f {
				return "That path contains a control character."
			}
		}
		return ""
	}},
	{"absolute", func(_, path string, _ bool) string {
		if !filepath.IsAbs(path) {
			return "The path must be absolute (start at the drive or at /), not relative."
		}
		return ""
	}},
	{"file exists", func(_, path string, mustExist bool) string {
		if mustExist && !launchToolPathIsFile(path) {
			return "Nothing is there: no program file exists at that path on this machine."
		}
		return ""
	}},
}

// validateLaunchToolPath walks the rule table.
func validateLaunchToolPath(tool, path string, mustExist bool) string {
	for _, r := range launchToolPathRules {
		if msg := r.check(tool, path, mustExist); msg != "" {
			return msg
		}
	}
	return ""
}

// launchToolPathIsFile reports a regular file at path (never executes it).
func launchToolPathIsFile(path string) bool {
	st, err := os.Stat(path) //nolint:gosec // G703: false positive; the owner's own launch binary path from the confirmed dashboard edit or their config.toml, only stat'd, never opened or run
	return err == nil && st.Mode().IsRegular()
}

// launchToolPathRows lists the overrides sorted by tool.
func launchToolPathRows(cfg config.Config) []launchToolPathRow {
	rows := make([]launchToolPathRow, 0, len(cfg.Launch.Tools))
	for tool, tc := range cfg.Launch.Tools {
		if strings.TrimSpace(tc.Path) == "" {
			continue
		}
		rows = append(rows, launchToolPathRow{Tool: tool, Path: tc.Path, Exists: launchToolPathIsFile(tc.Path)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Tool < rows[j].Tool })
	return rows
}

// handleLaunchToolPaths serves /api/launch/tool-paths.
func (s *Server) handleLaunchToolPaths(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, err)
			return
		}
		v := launchToolPathsView{Paths: launchToolPathRows(cfg)}
		v.ConfirmToken = setConfirmCookie(w, r)
		if s.opts.ConfigPath != "" {
			v.ConfigEtag, _ = configEtag(s.opts.ConfigPath)
		}
		writeJSON(w, v)
	case http.MethodPut:
		s.launchToolPathsSave(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// launchToolPathsSave writes [launch.tools.<tool>].path through the save pipeline.
func (s *Server) launchToolPathsSave(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"
	if !dryRun && !requireJSONConfirm(w, r) {
		return
	}
	var req launchToolPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Removing needs only a named tool (an override left for a tool Observer
	// no longer knows must stay removable); setting runs the whole table.
	if req.Remove {
		if strings.TrimSpace(req.Tool) == "" {
			http.Error(w, "Choose a tool.", http.StatusBadRequest)
			return
		}
	} else if msg := validateLaunchToolPath(req.Tool, req.Path, !dryRun); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	s.commitConfigEdit(w, r, configEdit{
		section: "launch",
		apply: func(cfg *config.Config) {
			tools := make(map[string]config.LaunchToolConfig, len(cfg.Launch.Tools)+1)
			for k, v := range cfg.Launch.Tools {
				tools[k] = v
			}
			if req.Remove {
				delete(tools, req.Tool)
			} else {
				tc := tools[req.Tool]
				tc.Path = req.Path
				tools[req.Tool] = tc
			}
			if len(tools) == 0 {
				tools = nil
			}
			cfg.Launch.Tools = tools
		},
		auditAction: "launch_tool_path",
		auditDetailFor: func(cfg config.Config) string {
			if req.Remove {
				return "tool=" + req.Tool + " path=removed"
			}
			return "tool=" + req.Tool + " path=set"
		},
		extra: func(cfg config.Config) map[string]any {
			exists := false
			if !req.Remove {
				exists = launchToolPathIsFile(req.Path)
			}
			return map[string]any{
				"tool":          req.Tool,
				"exists":        exists,
				"needs_confirm": true,
				"paths":         launchToolPathRows(cfg),
			}
		},
	})
}
