package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// taskreport.go wires the Phase-2 session-level task-tracking report
// (internal/taskreport — a standalone leaf package, not this one, so
// the MCP get_session_tasks tool can build on the exact same
// LoadSessionTaskReport/LoadTaskRollup functions without an import
// cycle: this package already imports internal/diag, which imports
// internal/mcp) into the two dashboard HTTP routes.

// taskflowOptions builds the taskflow.Options every LoadSessionTaskReport/
// LoadTaskRollup call needs from s.opts.Tasks (the [tasks] config this
// Server was constructed with) — NOT from store.New(db).TasksOptions(),
// which every handler here builds a fresh store instance for per
// request and which therefore never had SetTasksOptions called on it
// (the bug taskreport.LoadSessionTaskReport's doc comment describes).
func (s *Server) taskflowOptions() taskflow.Options {
	return taskflow.Options{
		MatchMode:             s.opts.Tasks.MatchMode,
		ConcurrentAttribution: s.opts.Tasks.ConcurrentAttribution,
		IncludeSidechains:     s.opts.Tasks.IncludeSidechains,
	}
}

// handleSessionTasks serves GET /api/session/<id>/tasks — a View
// sub-route under handleSessionDetail, mirroring handleSessionPredict's
// shape exactly (predict.go).
func (s *Server) handleSessionTasks(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	st := store.New(s.opts.DB)
	rep, err := taskreport.LoadSessionTaskReport(r.Context(), st, s.opts.CostEngine, sessionID, s.taskflowOptions())
	if err != nil {
		http.Error(w, fmt.Sprintf("load task report: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}

// handleTaskRollup serves GET /api/tasks?days=&project_id=&project=&tool=
// — the project/tool/window rollup for the dashboard's Tasks page and
// the Analysis page's task-tracking section. `project` is the same
// root-path string every other Analysis endpoint accepts
// (analysisScopeClause) — the dashboard's global project filter never
// resolves to a numeric id, so `project_id` stays for API compatibility
// (a caller that already knows the numeric id, e.g. a saved link) while
// `project`/`tool` are what the frontend's global filters actually send.
func (s *Server) handleTaskRollup(w http.ResponseWriter, r *http.Request) {
	since, until := windowRange(r, 0, 0, 36500)
	projectID := int64(intArg(r, "project_id", 0, 0, 1<<31-1))
	projectRoot := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")

	st := store.New(s.opts.DB)
	rollup, err := taskreport.LoadTaskRollup(r.Context(), st, s.opts.CostEngine, since, until, projectID, projectRoot, tool, s.taskflowOptions())
	if err != nil {
		http.Error(w, fmt.Sprintf("load task rollup: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rollup)
}
