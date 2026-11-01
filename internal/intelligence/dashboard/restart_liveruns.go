package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// restart_liveruns.go is the restart route's live sandboxed run question
// (sandbox plan v2 section 5.5, ledger SBX-UPD-1). With no seam wired, or
// with no live sandboxed run, the route answers exactly as before; with one,
// a plain restart is refused 409 live_sandboxed_runs naming the runs, and
// the body's live_runs answer decides: end them and restart, restart when
// they finish, cancel a pending answer, end them only, or apply a deferred
// update when they finish. No answer ends a run silently.

// restartBodyLimit bounds the restart POST body (one small JSON object).
const restartBodyLimit = 4 << 10

// restartRequest is the optional POST body.
type restartRequest struct {
	LiveRuns string `json:"live_runs"`
}

// readRestartRequest reads the optional body; an empty body is the plain
// restart of before. A body that is not JSON is refused 400 by the caller.
func readRestartRequest(r *http.Request) (restartRequest, error) {
	var req restartRequest
	if r.Body == nil {
		return req, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, restartBodyLimit))
	if err != nil {
		return req, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return req, nil
	}
	err = json.Unmarshal(raw, &req)
	return req, err
}

// liveRunsJSON renders the runs for a response (never null).
func liveRunsJSON(runs []dashapi.LiveSandboxRun) []dashapi.LiveSandboxRun {
	if runs == nil {
		return []dashapi.LiveSandboxRun{}
	}
	return runs
}

// setLiveRunsHeader stamps the live count header (LiveRunsHeader) so the CLI
// can tell a daemon with no live sandboxed run from one that predates the
// question.
func setLiveRunsHeader(w http.ResponseWriter, n int) {
	w.Header().Set(dashapi.LiveRunsHeader, strconv.Itoa(n))
}

// addLiveRunsStatus adds the live-run fields to the GET report. With no
// live run and nothing pending it adds nothing, so the report is the one of
// before.
func addLiveRunsStatus(resp map[string]any, st dashapi.LiveSandboxRunsState) {
	if len(st.Runs) > 0 {
		resp["live_sandboxed_runs"] = liveRunsJSON(st.Runs)
		resp["live_run_update_policy"] = st.Policy
	}
	if st.RestartPending {
		resp["restart_pending"] = true
		resp["restart_pending_since"] = st.RestartPendingSince.UTC().Format(time.RFC3339)
	}
	if st.UpdateDeferred && len(st.Runs) > 0 {
		resp["update_deferred_live_sandbox"] = true
		// ask_immediately opens the question at once; defer shows it in the
		// banner (live_run_update_policy).
		resp["update_question"] = st.Policy == "ask_immediately"
	}
	if st.UpdatePending {
		resp["update_pending"] = true
	}
}

// handleRestartLiveRuns runs the live-run half of POST /api/admin/restart.
// It returns true when it answered; false means the plain restart of before
// runs (no seam, or no live run and no answer that needs one).
func (s *Server) handleRestartLiveRuns(w http.ResponseWriter, r *http.Request, req restartRequest) bool {
	seam := s.opts.LiveSandboxRuns
	if seam == nil {
		return false
	}
	st := seam.State()
	setLiveRunsHeader(w, len(st.Runs))
	switch req.LiveRuns {
	case dashapi.LiveRunsCancel:
		writeJSON(w, map[string]any{"pending_cancelled": seam.CancelPending()})
		return true
	case dashapi.LiveRunsEndOnly:
		n, err := seam.EndRuns(r.Context())
		if err != nil {
			writeErr(w, err)
			return true
		}
		writeJSON(w, map[string]any{"ended_sandboxed_runs": n})
		return true
	case dashapi.LiveRunsApplyWhenFinished:
		if err := seam.ApplyUpdateWhenFinished(); err != nil {
			writeErrStatus(w, err, http.StatusConflict)
			return true
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"update_pending": true, "live_sandboxed_runs": len(st.Runs)})
		return true
	}
	if len(st.Runs) == 0 {
		return false
	}
	switch req.LiveRuns {
	case dashapi.LiveRunsEnd:
		return false // the caller ends the runs after its own checks, then restarts
	case dashapi.LiveRunsWhenFinished:
		if err := seam.RestartWhenFinished(); err != nil {
			writeErr(w, err)
			return true
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"restart_pending": true, "live_sandboxed_runs": len(st.Runs)})
		return true
	case "":
		n := len(st.Runs)
		msg := strconv.Itoa(n) + " sandboxed run is live; a restart ends it."
		if n != 1 {
			msg = strconv.Itoa(n) + " sandboxed runs are live; a restart ends them."
		}
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error":   dashapi.LiveRunsErrorCode,
			"message": msg + " End them and restart, or restart when they finish.",
			"runs":    liveRunsJSON(st.Runs),
		})
		return true
	}
	writeErrStatus(w, errUnknownLiveRunsAnswer, http.StatusBadRequest)
	return true
}

// errUnknownLiveRunsAnswer refuses a live_runs value the route does not
// know.
var errUnknownLiveRunsAnswer = liveRunsError("unknown live_runs answer (want end, when_finished, cancel, end_only or apply_when_finished)")

type liveRunsError string

func (e liveRunsError) Error() string { return string(e) }

// liveRunsEnd is the "end the runs and restart" answer, read by
// handleAdminRestart.
const liveRunsEnd = dashapi.LiveRunsEnd
