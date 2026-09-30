package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/repricesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// repriceSettingsSection is the Settings section that owns pricing. The pin
// on it is enforced by repricesvc.Service.Apply (the one place the CLI and
// this card share, PRICE-REPRICE-1 review finding 5); this handler only
// renders the service's *GovernanceRefusedError as the governance refusal
// every pinned Settings write answers with. A revert is never refused.
const repriceSettingsSection = repricesvc.SettingsSection

// repriceActor is the actor recorded on a run the dashboard started. The
// dashboard's write routes are owner-local (CapabilityLocal), so the actor is
// this machine's owner by construction.
const repriceActor = "dashboard"

// RepriceService is the dashboard's seam onto opt-in retroactive re-pricing
// (gap PRICE-REPRICE-1): cmd wires an *repricesvc.Service, the ONE owner of
// the plan / apply / revert flow shared with `observer reprice`. Nil = not
// wired (the routes answer 501).
type RepriceService interface {
	Pricing(ctx context.Context) repricesvc.PricingInfo
	Plan(ctx context.Context, f repricesvc.Filter) (repricesvc.Plan, error)
	Apply(ctx context.Context, req repricesvc.Request) (store.RepriceRun, error)
	Revert(ctx context.Context, runID int64, actor string) (store.RepriceRun, error)
	Runs(ctx context.Context, limit int) ([]store.RepriceRun, error)
}

// repriceFilterBody is the FilterBody of the node dashboard contract.
type repriceFilterBody struct {
	Since string `json:"since"`
	Until string `json:"until"`
	Model string `json:"model"`
}

func (b repriceFilterBody) filter() repricesvc.Filter {
	return repricesvc.Filter{Since: b.Since, Until: b.Until, Model: b.Model}
}

// repriceApplyBody is POST /api/reprice/apply's body.
type repriceApplyBody struct {
	repriceFilterBody
	Digest string `json:"digest"`
}

// repriceRevertBody is POST /api/reprice/revert's body.
type repriceRevertBody struct {
	RunID int64 `json:"run_id"`
}

const repriceNotWired = "re-pricing is not wired on this dashboard"

// handleRepriceStatus serves GET /api/reprice/status: the price table a run
// would price under, the last 20 runs, and the confirm token the write
// routes require.
func (s *Server) handleRepriceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.Reprice == nil {
		http.Error(w, repriceNotWired, http.StatusNotImplemented)
		return
	}
	tok := setConfirmCookie(w, r)
	runs, err := s.opts.Reprice.Runs(r.Context(), 20)
	if err != nil {
		writeErr(w, fmt.Errorf("reprice status: %w", err))
		return
	}
	writeJSON(w, map[string]any{
		"confirm_token": tok,
		"pricing":       s.opts.Reprice.Pricing(r.Context()),
		"runs":          repricesvc.ViewRuns(runs),
	})
}

// handleRepricePlan serves POST /api/reprice/plan: the dry run. It never
// writes, so it needs no confirm token; POST + JSON only.
func (s *Server) handleRepricePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		http.Error(w, "unsupported media type: application/json required", http.StatusUnsupportedMediaType)
		return
	}
	if s.opts.Reprice == nil {
		http.Error(w, repriceNotWired, http.StatusNotImplemented)
		return
	}
	var body repriceFilterBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeErrStatus(w, fmt.Errorf("decode reprice plan: %w", err), http.StatusBadRequest)
		return
	}
	plan, err := s.opts.Reprice.Plan(r.Context(), body.filter())
	if err != nil {
		writeErrStatus(w, err, repriceErrStatus(err))
		return
	}
	writeJSON(w, plan.View())
}

// handleRepriceApply serves POST /api/reprice/apply: re-plan and apply when
// the fresh plan's digest equals the approved one; otherwise 409
// {"error":"plan_changed","plan":PlanView} and nothing is written.
func (s *Server) handleRepriceApply(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.Reprice == nil {
		http.Error(w, repriceNotWired, http.StatusNotImplemented)
		return
	}
	var body repriceApplyBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeErrStatus(w, fmt.Errorf("decode reprice apply: %w", err), http.StatusBadRequest)
		return
	}
	run, err := s.opts.Reprice.Apply(r.Context(), repricesvc.Request{Filter: body.filter(), Actor: repriceActor, Digest: body.Digest})
	var changed *repricesvc.PlanChangedError
	if errors.As(err, &changed) {
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "plan_changed", "plan": changed.Plan.View()})
		return
	}
	var pinned *repricesvc.GovernanceRefusedError
	if errors.As(err, &pinned) {
		writeGovernanceRefusal(w, http.StatusConflict, "governance_read_only", pinned.Section, pinned.Effective,
			"Pricing is pinned by your organization, so stored costs cannot be re-priced here.")
		return
	}
	if err != nil {
		if run.ID != 0 {
			// A partial run: the committed batches are real and revertable.
			s.recordManageAudit(r, "reprice_apply", repriceAuditDetail(run))
			writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "run": repricesvc.ViewRun(run)})
			return
		}
		writeErrStatus(w, err, repriceErrStatus(err))
		return
	}
	s.recordManageAudit(r, "reprice_apply", repriceAuditDetail(run))
	writeJSON(w, repricesvc.ViewRun(run))
}

// handleRepriceRevert serves POST /api/reprice/revert: undo one apply run.
// Never refused by governance. 409 {"error"} for an unknown run, a run
// already reverted, a revert run, a run still running, another run in
// progress, or a run a LATER run supersedes (the error names the run to
// revert first).
func (s *Server) handleRepriceRevert(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.Reprice == nil {
		http.Error(w, repriceNotWired, http.StatusNotImplemented)
		return
	}
	var body repriceRevertBody
	if err := decodeJSONBody(r, &body); err != nil || body.RunID <= 0 {
		writeErrStatus(w, errors.New("decode reprice revert: a positive run_id is required"), http.StatusBadRequest)
		return
	}
	run, err := s.opts.Reprice.Revert(r.Context(), body.RunID, repriceActor)
	if err != nil {
		if repricesvc.IsRefusal(err) {
			writeErrStatus(w, err, http.StatusConflict)
			return
		}
		if run.ID != 0 {
			s.recordManageAudit(r, "reprice_revert", repriceAuditDetail(run))
			writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "run": repricesvc.ViewRun(run)})
			return
		}
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "reprice_revert", repriceAuditDetail(run))
	writeJSON(w, repricesvc.ViewRun(run))
}

// repriceErrStatus maps a plan/apply error to a status: a bad filter is the
// caller's (400), a refusal (another run in progress) a conflict (409),
// anything else ours (500).
func repriceErrStatus(err error) int {
	switch {
	case errors.Is(err, repricesvc.ErrBadFilter):
		return http.StatusBadRequest
	case repricesvc.IsRefusal(err):
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// repriceAuditDetail is the content-free audit detail of a run.
func repriceAuditDetail(run store.RepriceRun) string {
	d := fmt.Sprintf("run=%d kind=%s status=%s changed=%d delta_usd=%.6f pricing=%s/v%d",
		run.ID, run.Kind, run.Status, run.Changed, run.DeltaUSD, run.PricingSource, run.PricingVersion)
	if run.RevertsRun != 0 {
		d += fmt.Sprintf(" reverts=%d", run.RevertsRun)
	}
	if run.Since != "" || run.Until != "" {
		d += fmt.Sprintf(" window=%s..%s", run.Since, run.Until)
	}
	if run.Model != "" {
		d += " model=" + run.Model
	}
	return d
}
