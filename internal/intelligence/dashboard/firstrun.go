package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/captureprogress"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The first-run capture view (T-922): on the first dashboard visit after a
// fresh install, a dialog shows which AI coding tools were found on this
// machine, how each one is captured, and how far the watcher has got reading
// their existing history. Everything it reports already exists elsewhere:
// the tool rows are the Connected-tools builder (toolStatusRows), the
// progress is the watcher's own initial-scan model (Options.CaptureProgress,
// internal/captureprogress), and the counts are plain reads of sessions and
// projects. Nothing here walks the filesystem or re-parses a file.
//
// Node-local: the routes are owner-local (L), the seen flag lives in a file
// beside the database (internal/firstrunstate), and nothing here is
// reachable from the org push seam.

// firstRunProjectLimit bounds the "projects found" list.
const firstRunProjectLimit = 8

// firstRunHistory is one tool's history-capture state.
type firstRunHistory struct {
	// State: scanning | done | failed | stopped | waiting | off | not_running.
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
	FilesFound     int    `json:"files_found"`
	FilesProcessed int    `json:"files_processed"`
	FilesFailed    int    `json:"files_failed"`
}

// firstRunTool is one detected tool in the first-run view.
type firstRunTool struct {
	Tool string `json:"tool"`
	Name string `json:"name"`
	// Detected: the tool's session folder exists on this machine
	// (DetectedPath names it).
	Detected     bool   `json:"detected"`
	DetectedPath string `json:"detected_path,omitempty"`
	// Enabled: capture for the tool is on in [observer.watch]
	// enabled_adapters.
	Enabled bool `json:"enabled"`
	// WatcherActive: this process's watcher reads the tool's session files.
	WatcherActive bool            `json:"watcher_active"`
	Hooks         *toolProbe      `json:"hooks,omitempty"`
	Proxy         *toolProbe      `json:"proxy,omitempty"`
	History       firstRunHistory `json:"history"`
	Sessions      int64           `json:"sessions"`
	Projects      int64           `json:"projects"`
	LastSeenAt    string          `json:"last_seen_at,omitempty"`
	// The fields below are additive for the Tools page coverage view (T-935,
	// ?all=1); the first-run dialog ignores them.
	//
	// MCP is the Connected-tools MCP probe (nil: the tool has no MCP format
	// Observer writes).
	MCP *toolProbe `json:"mcp,omitempty"`
	// Wiring is the Connected-tools setup action set (nil: none offered).
	Wiring *toolWiring `json:"wiring,omitempty"`
	// Launchable: the New terminal picker offers this tool (and so its
	// guided install), integration.TerminalLaunchable on its registry row.
	Launchable bool `json:"launchable,omitempty"`
}

// firstRunCapture is the overall history-capture state.
type firstRunCapture struct {
	// State: idle | scanning | done | stopped | not_running.
	State          string `json:"state"`
	StartedAt      string `json:"started_at,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
	FilesFound     int    `json:"files_found"`
	FilesProcessed int    `json:"files_processed"`
	FilesFailed    int    `json:"files_failed"`
}

// firstRunProject is one captured project.
type firstRunProject struct {
	Name          string   `json:"name"`
	Root          string   `json:"root"`
	Sessions      int64    `json:"sessions"`
	Tools         []string `json:"tools"`
	LastSessionAt string   `json:"last_session_at,omitempty"`
}

// firstRunResponse is GET /api/firstrun.
type firstRunResponse struct {
	// AutoOpen: the dashboard should open the view by itself (a fresh
	// install the owner has not closed it on).
	AutoOpen bool `json:"auto_open"`
	Seen     bool `json:"seen"`
	// Install: fresh | existing | unknown.
	Install        string          `json:"install"`
	WatcherRunning bool            `json:"watcher_running"`
	Capture        firstRunCapture `json:"capture"`
	Tools          []firstRunTool  `json:"tools"`
	// SupportedNotFound counts the supported tools not found here.
	SupportedNotFound int `json:"supported_not_found"`
	// Supported counts the supported tools (the adapter catalog); 0 on a
	// brief read. Additive (T-935).
	Supported    int               `json:"supported"`
	Sessions     int64             `json:"sessions"`
	ProjectCount int64             `json:"project_count"`
	Projects     []firstRunProject `json:"projects"`
	GeneratedAt  string            `json:"generated_at"`
	// ConfirmToken is the owner-local double-submit token the seen POST
	// echoes (the T-530 discipline every dashboard write follows).
	ConfirmToken string `json:"confirm_token"`
	// Dismissed lists the dashboard notices the owner dismissed for good
	// (uiDismissKeys), kept on the daemon (WINNODE2 16b).
	Dismissed []string `json:"dismissed,omitempty"`
}

// uiDismissKeys is the closed set of notices POST /api/firstrun/seen
// {"dismiss": key} records: the first-visit product tour and the "Review
// components" setup card. Anything else is refused.
var uiDismissKeys = map[string]bool{"tour": true, "components_setup": true}

// firstRunState returns this server's one seen-state store.
func (s *Server) firstRunState() *firstrunstate.Store {
	s.firstRunOnce.Do(func() {
		s.firstRun = firstrunstate.New(firstrunstate.Path(s.opts.DBPath))
	})
	return s.firstRun
}

func (s *Server) handleFirstRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	// brief=1 is the every-page-load read the dashboard takes the auto-open
	// decision from: the state, the capture totals and the counts, without
	// the per-tool integration probes or the project list.
	brief := r.URL.Query().Get("brief") == "1"
	// all=1 is the Tools page coverage read (T-935): every supported tool is
	// listed, the ones not found here included, instead of only being
	// counted in supported_not_found.
	all := r.URL.Query().Get("all") == "1"
	st := s.firstRunState().Load()
	counts, totals, err := s.firstRunCounts(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}
	snap := captureprogress.Snapshot{State: captureprogress.ScanIdle}
	watcherRunning := s.opts.CaptureProgress != nil
	if watcherRunning {
		snap = s.opts.CaptureProgress()
	}
	projects := []firstRunProject{}
	tools := []firstRunTool{}
	notFound := 0
	supported := 0
	if !brief {
		if projects, err = s.firstRunProjects(ctx); err != nil {
			writeErr(w, err)
			return
		}
		rows, configLoaded := s.toolStatusRows(ctx)
		tools, notFound = firstRunTools(rows, configLoaded, watcherRunning, snap, counts, all)
		supported = len(s.opts.ToolCatalog)
	}

	install := string(st.Install)
	if install == "" {
		install = "unknown"
	}
	writeJSON(w, firstRunResponse{
		AutoOpen:          firstRunAutoOpen(st, totals.sessions),
		Seen:              st.Seen(),
		Install:           install,
		WatcherRunning:    watcherRunning,
		Capture:           firstRunCaptureOf(snap, watcherRunning),
		Tools:             tools,
		SupportedNotFound: notFound,
		Supported:         supported,
		Sessions:          totals.sessions,
		ProjectCount:      totals.projects,
		Projects:          projects,
		GeneratedAt:       s.now().UTC().Format(time.RFC3339),
		ConfirmToken:      setConfirmCookie(w, r),
		Dismissed:         st.DismissedKeys(),
	})
}

// handleFirstRunSeen records that the owner closed the view for good
// ({"seen": true}) or asks for it back ({"seen": false}). Owner-local write:
// POST, JSON, the confirm token, and one metadata-only audit row.
func (s *Server) handleFirstRunSeen(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		Seen    *bool  `json:"seen"`
		Dismiss string `json:"dismiss"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Dismiss != "" {
		// {"dismiss": key}: a dashboard notice dismissed for good
		// (WINNODE2 16b).
		if !uiDismissKeys[req.Dismiss] {
			http.Error(w, "unknown notice "+strconv.Quote(req.Dismiss), http.StatusBadRequest)
			return
		}
		st, err := s.firstRunState().Dismiss(req.Dismiss, s.now())
		if err != nil {
			writeErr(w, err)
			return
		}
		s.recordManageAudit(r, "ui_notice_dismissed", "notice="+req.Dismiss)
		writeJSON(w, map[string]any{"ok": true, "dismissed": st.DismissedKeys()})
		return
	}
	if req.Seen == nil {
		http.Error(w, `body must be {"seen": true} or {"seen": false}`, http.StatusBadRequest)
		return
	}
	st, err := s.firstRunState().SetSeen(*req.Seen, s.now())
	if err != nil {
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "firstrun_seen", fmt.Sprintf("seen=%t", *req.Seen))
	writeJSON(w, map[string]any{"ok": true, "seen": st.Seen()})
}

// firstRunAutoOpen decides whether the view opens by itself. A recorded
// install decides; with nothing recorded (a dashboard that runs without the
// daemon's start-up record, such as a standalone `observer dashboard`), an
// empty database counts as fresh.
func firstRunAutoOpen(st firstrunstate.State, sessions int64) bool {
	if st.Install == firstrunstate.InstallUnknown && !st.Seen() {
		return sessions == 0
	}
	return firstrunstate.AutoOpen(st)
}

type firstRunToolCount struct{ sessions, projects int64 }

type firstRunTotals struct{ sessions, projects int64 }

// firstRunCounts reads captured sessions and projects, per tool and in
// total, from the real database (never the demo one: this describes the
// machine).
func (s *Server) firstRunCounts(ctx context.Context) (map[string]firstRunToolCount, firstRunTotals, error) {
	out := map[string]firstRunToolCount{}
	var totals firstRunTotals
	if s.opts.DB == nil {
		return out, totals, nil
	}
	rows, err := s.opts.DB.QueryContext(ctx,
		`SELECT tool, COUNT(*), COUNT(DISTINCT project_id) FROM sessions GROUP BY tool`)
	if err != nil {
		return nil, totals, fmt.Errorf("dashboard.firstRunCounts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tool string
		var c firstRunToolCount
		if err := rows.Scan(&tool, &c.sessions, &c.projects); err != nil {
			return nil, totals, fmt.Errorf("dashboard.firstRunCounts: %w", err)
		}
		out[tool] = c
	}
	if err := rows.Err(); err != nil {
		return nil, totals, fmt.Errorf("dashboard.firstRunCounts: %w", err)
	}
	if err := s.opts.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(DISTINCT project_id) FROM sessions`).Scan(&totals.sessions, &totals.projects); err != nil {
		return nil, totals, fmt.Errorf("dashboard.firstRunCounts: %w", err)
	}
	return out, totals, nil
}

// firstRunProjects lists the most recently active captured projects.
func (s *Server) firstRunProjects(ctx context.Context) ([]firstRunProject, error) {
	out := []firstRunProject{}
	if s.opts.DB == nil {
		return out, nil
	}
	rows, err := s.opts.DB.QueryContext(ctx, `
		SELECT COALESCE(p.name, ''), p.root_path, COUNT(s.id),
		       COALESCE(GROUP_CONCAT(DISTINCT s.tool), ''), COALESCE(MAX(s.started_at), '')
		FROM sessions s JOIN projects p ON p.id = s.project_id
		GROUP BY p.id
		ORDER BY MAX(s.started_at) DESC
		LIMIT ?`, firstRunProjectLimit)
	if err != nil {
		return nil, fmt.Errorf("dashboard.firstRunProjects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p firstRunProject
		var tools string
		if err := rows.Scan(&p.Name, &p.Root, &p.Sessions, &tools, &p.LastSessionAt); err != nil {
			return nil, fmt.Errorf("dashboard.firstRunProjects: %w", err)
		}
		if strings.TrimSpace(p.Name) == "" {
			p.Name = projectBaseName(p.Root)
		}
		p.Tools = []string{}
		for _, t := range strings.Split(tools, ",") {
			if t = strings.TrimSpace(t); t != "" {
				p.Tools = append(p.Tools, t)
			}
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dashboard.firstRunProjects: %w", err)
	}
	return out, nil
}

// projectBaseName is the last element of a root path written with either
// separator.
func projectBaseName(root string) string {
	r := strings.TrimRight(strings.ReplaceAll(root, `\`, "/"), "/")
	if r == "" {
		return root
	}
	return path.Base(r)
}

// firstRunTools turns the Connected-tools rows into the view's rows: a tool
// is listed when its session folder exists here, when it already has
// captured sessions, or when the watcher reported progress for it. The rest
// are counted (notFound) and, when all is set (the coverage read), listed
// too.
func firstRunTools(rows []toolStatusRow, configLoaded, watcherRunning bool, snap captureprogress.Snapshot, counts map[string]firstRunToolCount, all bool) (tools []firstRunTool, notFound int) {
	tools = []firstRunTool{}
	for _, row := range rows {
		prog, hasProg := snap.Tool(row.Tool)
		c := counts[row.Tool]
		if !row.Detected && c.sessions == 0 && !hasProg {
			notFound++
			if !all {
				continue
			}
		}
		enabled := row.Enabled || !configLoaded
		t := firstRunTool{
			Tool:          row.Tool,
			Name:          integration.DisplayName(row.Tool),
			Detected:      row.Detected,
			DetectedPath:  row.DetectedPath,
			Enabled:       enabled,
			WatcherActive: watcherRunning && enabled && (row.Detected || hasProg),
			Hooks:         row.Hooks,
			Proxy:         row.Proxy,
			Sessions:      c.sessions,
			Projects:      c.projects,
			LastSeenAt:    row.LastSeenAt,
			MCP:           row.MCP,
			Wiring:        row.Wiring,
		}
		if capRow, ok := integration.For(row.Tool); ok {
			t.Launchable = integration.TerminalLaunchable(capRow)
		}
		t.History = firstRunHistoryOf(historyFacts{
			hasProgress: hasProg, progress: prog,
			watcherRunning: watcherRunning, enabled: enabled,
			captureState: snap.State,
		})
		tools = append(tools, t)
	}
	return tools, notFound
}

// historyFacts is what the per-tool history rules read.
type historyFacts struct {
	hasProgress    bool
	progress       captureprogress.ToolProgress
	watcherRunning bool
	enabled        bool
	captureState   captureprogress.ScanState
}

// historyRules is the ordered decision table for a tool's history state
// (CLAUDE.md #5): the watcher's own report wins; otherwise the row says why
// there is none. The first row whose when holds decides.
var historyRules = []struct {
	name   string
	when   func(f historyFacts) bool
	state  string
	reason string
}{
	{
		name: "the watcher reported this tool",
		when: func(f historyFacts) bool { return f.hasProgress },
	},
	{
		name:   "no watcher in this process",
		when:   func(f historyFacts) bool { return !f.watcherRunning },
		state:  "not_running",
		reason: "The background watcher is not running in this process. Run observer start to capture history.",
	},
	{
		name:   "capture turned off",
		when:   func(f historyFacts) bool { return !f.enabled },
		state:  "off",
		reason: "Capture for this tool is turned off in your settings.",
	},
	{
		name:   "first pass not started yet",
		when:   func(f historyFacts) bool { return f.captureState == captureprogress.ScanIdle },
		state:  "waiting",
		reason: "Waiting for the first pass to start.",
	},
	{
		name:   "nothing to read yet",
		when:   func(historyFacts) bool { return true },
		state:  "waiting",
		reason: "No session files to read yet. New sessions are picked up as they happen.",
	},
}

func firstRunHistoryOf(f historyFacts) firstRunHistory {
	for _, r := range historyRules {
		if !r.when(f) {
			continue
		}
		if r.state == "" {
			p := f.progress
			return firstRunHistory{
				State: string(p.State), Reason: p.Reason,
				FilesFound: p.FilesFound, FilesProcessed: p.FilesProcessed, FilesFailed: p.FilesFailed,
			}
		}
		return firstRunHistory{State: r.state, Reason: r.reason}
	}
	return firstRunHistory{State: "waiting"}
}

// firstRunCaptureOf maps the watcher's snapshot to the wire shape.
func firstRunCaptureOf(snap captureprogress.Snapshot, watcherRunning bool) firstRunCapture {
	out := firstRunCapture{
		State:          string(snap.State),
		FilesFound:     snap.FilesFound,
		FilesProcessed: snap.FilesProcessed,
		FilesFailed:    snap.FilesFailed,
	}
	if !watcherRunning {
		out.State = "not_running"
	}
	if !snap.StartedAt.IsZero() {
		out.StartedAt = snap.StartedAt.UTC().Format(time.RFC3339)
	}
	if !snap.FinishedAt.IsZero() {
		out.FinishedAt = snap.FinishedAt.UTC().Format(time.RFC3339)
	}
	return out
}
