package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// sandbox_setup.go serves the sandbox setup routes (sandbox installation
// lifecycle plan section 3.6) over Options.SandboxSetup:
//
//	GET  /api/terminal/sandbox/setup                   the offered rows on this host
//	GET  /api/terminal/sandbox/setup/{backend}         one row's plan (passive facts)
//	POST /api/terminal/sandbox/setup/{backend}/check   the active check (confirm token)
//	POST /api/terminal/sandbox/setup/{backend}/run     one step (confirm token)
//	POST /api/terminal/sandbox/setup/{backend}/apply   read [terminal.sandbox] again now (confirm token)
//	GET  /api/terminal/sandbox/setup/op/{id}           an in-process op's progress
//
// Every route is Local. The prefix belongs to the terminals.sandbox
// component, so the component guard answers 404 component_not_installed
// while the module is off; a nil seam answers 501 not_in_build. Errors are
// JSON {"error", "code"} with a code from dashapi.SandboxSetupCodes. A run
// body names a step, an action, the plan fingerprint, the consent echo, a
// local path and (hosted_connect only) a key: never an argv or a command,
// and decoding refuses any field it does not know. The key is never logged
// or echoed.

// sandboxSetupMaxBody caps a setup request body.
const sandboxSetupMaxBody = 64 << 10

// sandboxSetupIDPattern is a backend id or an op id in a setup path.
var sandboxSetupIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// sandboxSetupCoder is how a seam refusal names its status and code (the
// cmd-side error implements it; the dashboard names no cmd type).
type sandboxSetupCoder interface {
	SandboxSetupCode() string
	HTTPStatus() int
}

// sandboxSetupPlanCarrier is a refusal that carries the fresh plan
// (plan_changed).
type sandboxSetupPlanCarrier interface {
	FreshPlan() *dashapi.SandboxSetupPlan
}

// writeSandboxSetupErr writes a seam error as DI-05 JSON.
func writeSandboxSetupErr(w http.ResponseWriter, err error) {
	if errors.Is(err, dashapi.ErrSandboxSetupNotInBuild) {
		writeSandboxSetupCode(w, http.StatusNotImplemented, dashapi.SandboxSetupCodeNotInBuild, err.Error(), nil)
		return
	}
	var coder sandboxSetupCoder
	if errors.As(err, &coder) {
		var plan *dashapi.SandboxSetupPlan
		var pc sandboxSetupPlanCarrier
		if errors.As(err, &pc) {
			plan = pc.FreshPlan()
		}
		writeSandboxSetupCode(w, coder.HTTPStatus(), coder.SandboxSetupCode(), err.Error(), plan)
		return
	}
	writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

// sandboxSetupCodePlaces maps the setup codes whose fix is a setting to the
// place that changes it (internal/settingslink). A code without a row is not
// fixed by a setting and carries no link.
var sandboxSetupCodePlaces = map[string]settingslink.Place{
	dashapi.SandboxSetupCodeInstallDisabled:   settingslink.TerminalLaunchPolicy,
	dashapi.SandboxSetupCodeElevationDisabled: settingslink.TerminalSandbox,
}

// writeSandboxSetupCode writes one refusal. A code whose fix is a setting
// also carries the deep link fields ("settings", "settings_label").
func writeSandboxSetupCode(w http.ResponseWriter, status int, code, msg string, plan *dashapi.SandboxSetupPlan) {
	body := map[string]any{"error": msg, "code": code}
	if plan != nil {
		body["plan"] = plan
	}
	if p, ok := sandboxSetupCodePlaces[code]; ok {
		if l, ok := settingslink.For(p); ok {
			body["message"] = msg
			body["settings"] = l.Href
			body["settings_label"] = l.Label
		}
	}
	writeJSONStatus(w, status, body)
}

// sandboxSetupSeam returns the seam, or writes 501 and returns nil.
func (s *Server) sandboxSetupSeam(w http.ResponseWriter) dashapi.SandboxSetup {
	if s.opts.SandboxSetup == nil {
		writeSandboxSetupCode(w, http.StatusNotImplemented, dashapi.SandboxSetupCodeNotInBuild, "sandbox setup is not in this build", nil)
		return nil
	}
	return s.opts.SandboxSetup
}

// decodeSandboxSetupBody strictly decodes one JSON object into v: unknown
// fields, a second value and an oversized body are refused.
func decodeSandboxSetupBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, sandboxSetupMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// The decoder's message may quote the body (a key): never echo it.
		writeSandboxSetupCode(w, http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep, "the request body is not a sandbox setup request (an unknown field, or not JSON)", nil)
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeSandboxSetupCode(w, http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep, "the request body holds more than one object", nil)
		return false
	}
	return true
}

// handleSandboxSetupSummary serves GET /api/terminal/sandbox/setup.
func (s *Server) handleSandboxSetupSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	rows, err := seam.Summary(r.Context())
	if err != nil {
		writeSandboxSetupErr(w, err)
		return
	}
	if rows == nil {
		rows = []dashapi.SandboxSetupSummary{}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"backends": rows})
}

// handleSandboxSetup serves the per-backend and op routes under
// /api/terminal/sandbox/setup/.
func (s *Server) handleSandboxSetup(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/terminal/sandbox/setup/"), "/")
	parts := strings.Split(rest, "/")
	for _, p := range parts {
		if !sandboxSetupIDPattern.MatchString(p) {
			http.NotFound(w, r)
			return
		}
	}
	switch {
	case len(parts) == 2 && parts[0] == "op":
		s.handleSandboxSetupOp(w, r, parts[1])
	case len(parts) == 1:
		s.handleSandboxSetupPlan(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "check":
		s.handleSandboxSetupCheck(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "run":
		s.handleSandboxSetupRun(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "apply":
		s.handleSandboxSetupApply(w, r, parts[0])
	default:
		http.NotFound(w, r)
	}
}

// handleSandboxSetupPlan serves GET .../setup/{backend}: the plan from
// passive facts (no exec, no dial).
func (s *Server) handleSandboxSetupPlan(w http.ResponseWriter, r *http.Request, backend string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	plan, err := seam.Plan(r.Context(), backend)
	if err != nil {
		writeSandboxSetupErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, plan)
}

// handleSandboxSetupCheck serves POST .../setup/{backend}/check: the active
// check, on the person's click (confirm token), body {}.
func (s *Server) handleSandboxSetupCheck(w http.ResponseWriter, r *http.Request, backend string) {
	if !requireConfirmToken(w, r) {
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	var body struct{}
	if !decodeSandboxSetupBody(w, r, &body) {
		return
	}
	plan, err := seam.Check(r.Context(), backend)
	if err != nil {
		writeSandboxSetupErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, plan)
}

// handleSandboxSetupRun serves POST .../setup/{backend}/run: one step, with
// every argv derived server-side.
func (s *Server) handleSandboxSetupRun(w http.ResponseWriter, r *http.Request, backend string) {
	if !requireConfirmToken(w, r) {
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	var req dashapi.SandboxSetupRunRequest
	if !decodeSandboxSetupBody(w, r, &req) {
		return
	}
	started, err := seam.Run(r.Context(), backend, req, "dashboard")
	if err != nil {
		writeSandboxSetupErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, started)
}

// handleSandboxSetupApply serves POST .../setup/{backend}/apply, body {}:
// the daemon's sandbox seams read [terminal.sandbox] again now, so a change a
// CLI wrote binds on the next launch without a restart. It changes no value
// itself. {"applied": false} when the seam cannot apply (not a daemon). The
// daemon logs each apply it serves (R4 (a)): the CLI that asked prints
// nothing of its own logger, so this line is the only record of it.
func (s *Server) handleSandboxSetupApply(w http.ResponseWriter, r *http.Request, backend string) {
	if !requireConfirmToken(w, r) {
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	var body struct{}
	if !decodeSandboxSetupBody(w, r, &body) {
		return
	}
	applied := s.applySandboxLive(r)
	s.opts.Logger.Info("sandbox setup: live apply", "backend", backend, "source", "route apply", "applied", applied)
	writeJSONStatus(w, http.StatusOK, map[string]bool{"applied": applied})
}

// applySandboxLive asks the setup seam to apply [terminal.sandbox] now and
// reports whether it could (the one seam a sandbox config write goes
// through, sandbox_live_apply.go on the cmd side).
func (s *Server) applySandboxLive(r *http.Request) bool {
	a, ok := s.opts.SandboxSetup.(dashapi.SandboxSetupLiveApplier)
	if !ok {
		return false
	}
	a.ApplyLive(r.Context())
	return true
}

// handleSandboxSetupOp serves GET .../setup/op/{id}.
func (s *Server) handleSandboxSetupOp(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seam := s.sandboxSetupSeam(w)
	if seam == nil {
		return
	}
	op, ok := seam.Op(r.Context(), id)
	if !ok {
		writeSandboxSetupCode(w, http.StatusNotFound, dashapi.SandboxSetupCodeUnknownStep, "no such setup operation", nil)
		return
	}
	writeJSONStatus(w, http.StatusOK, op)
}
