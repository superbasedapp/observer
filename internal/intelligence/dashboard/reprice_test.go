package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/repricesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeReprice records calls; it never touches a row.
type fakeReprice struct {
	plans    []repricesvc.Filter
	applied  []repricesvc.Request
	reverted []int64
	digest   string
	// applyErr, when set, is what Apply answers (the service's refusals).
	applyErr error
}

func (f *fakeReprice) Pricing(context.Context) repricesvc.PricingInfo {
	return repricesvc.PricingInfo{Source: "seed", Description: "the built-in rate table"}
}

func (f *fakeReprice) Plan(_ context.Context, flt repricesvc.Filter) (repricesvc.Plan, error) {
	f.plans = append(f.plans, flt)
	return repricesvc.Plan{Since: flt.Since, Digest: f.digest, Pricing: f.Pricing(context.Background())}, nil
}

func (f *fakeReprice) Apply(_ context.Context, req repricesvc.Request) (store.RepriceRun, error) {
	f.applied = append(f.applied, req)
	if f.applyErr != nil {
		return store.RepriceRun{}, f.applyErr
	}
	if req.Digest != f.digest {
		return store.RepriceRun{}, &repricesvc.PlanChangedError{Plan: repricesvc.Plan{Digest: f.digest}}
	}
	return store.RepriceRun{ID: 7, Kind: "apply", Status: "applied", Changed: 3, DeltaUSD: 1.5}, nil
}

func (f *fakeReprice) Revert(_ context.Context, id int64, _ string) (store.RepriceRun, error) {
	f.reverted = append(f.reverted, id)
	if id == 5 {
		return store.RepriceRun{}, fmt.Errorf("repricesvc.Revert: %w", &store.RepriceSupersededError{RunID: 5, LaterRunID: 7})
	}
	if id != 7 {
		return store.RepriceRun{}, fmt.Errorf("wrapped: %w", store.ErrRepriceRunNotFound)
	}
	return store.RepriceRun{ID: 8, Kind: "revert", RevertsRun: 7, Status: "applied"}, nil
}

func (f *fakeReprice) Runs(context.Context, int) ([]store.RepriceRun, error) {
	return []store.RepriceRun{{ID: 7, Kind: "apply", Status: "applied"}}, nil
}

func repriceServer(t *testing.T, svc RepriceService) *Server {
	t.Helper()
	dir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	opts := Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml")}
	if svc != nil {
		opts.Reprice = svc
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func repriceToken(t *testing.T, s *Server) (string, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/reprice/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Token   string                 `json:"confirm_token"`
		Pricing repricesvc.PricingInfo `json:"pricing"`
		Runs    []repricesvc.RunView   `json:"runs"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" || body.Pricing.Source != "seed" || len(body.Runs) != 1 || body.Runs[0].ID != 7 {
		t.Fatalf("status body %+v", body)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			return body.Token, c
		}
	}
	t.Fatal("no confirm cookie")
	return "", nil
}

func TestRepriceRoutes(t *testing.T) {
	fake := &fakeReprice{digest: "abc"}
	s := repriceServer(t, fake)
	tok, ck := repriceToken(t, s)

	// The dry run needs no token.
	rr := shellWrapPost(s, "/api/reprice/plan", `{"since":"2026-09-01"}`, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("plan: %d %s", rr.Code, rr.Body.String())
	}
	var pv repricesvc.PlanView
	if err := json.Unmarshal(rr.Body.Bytes(), &pv); err != nil || pv.Digest != "abc" || pv.Since != "2026-09-01" {
		t.Fatalf("plan view %+v %v", pv, err)
	}

	// Apply without the confirm token is refused before the service.
	if rr := shellWrapPost(s, "/api/reprice/apply", `{"digest":"abc"}`, "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("apply without the confirm token: %d", rr.Code)
	}
	if len(fake.applied) != 0 {
		t.Fatal("a refused request reached the service")
	}

	// A stale digest: 409 plan_changed with the fresh plan.
	rr = shellWrapPost(s, "/api/reprice/apply", `{"since":"2026-09-01","digest":"stale"}`, tok, ck)
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale apply: %d %s", rr.Code, rr.Body.String())
	}
	var conflict struct {
		Error string              `json:"error"`
		Plan  repricesvc.PlanView `json:"plan"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &conflict); err != nil || conflict.Error != "plan_changed" || conflict.Plan.Digest != "abc" {
		t.Fatalf("conflict body %s %v", rr.Body.String(), err)
	}

	// The approved digest applies.
	rr = shellWrapPost(s, "/api/reprice/apply", `{"since":"2026-09-01","digest":"abc"}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rr.Code, rr.Body.String())
	}
	var run repricesvc.RunView
	if err := json.Unmarshal(rr.Body.Bytes(), &run); err != nil || run.ID != 7 || run.Changed != 3 {
		t.Fatalf("run view %+v %v", run, err)
	}
	if got := fake.applied[len(fake.applied)-1]; got.Actor != repriceActor || got.Filter.Since != "2026-09-01" {
		t.Fatalf("service saw %+v", got)
	}

	// Revert: ok, then a refusal maps to 409.
	rr = shellWrapPost(s, "/api/reprice/revert", `{"run_id":7}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rr.Code, rr.Body.String())
	}
	rr = shellWrapPost(s, "/api/reprice/revert", `{"run_id":99}`, tok, ck)
	if rr.Code != http.StatusConflict {
		t.Fatalf("revert unknown: %d %s", rr.Code, rr.Body.String())
	}
	// Out of order: 409 naming the later run to revert first.
	rr = shellWrapPost(s, "/api/reprice/revert", `{"run_id":5}`, tok, ck)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "revert run 7 first") {
		t.Fatalf("revert superseded: %d %s", rr.Code, rr.Body.String())
	}
	if rr := shellWrapPost(s, "/api/reprice/revert", `{}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("revert without run_id: %d", rr.Code)
	}

	// The two writes left manage audit rows.
	var n int
	if err := s.opts.DB.QueryRow(`SELECT COUNT(*) FROM remote_audit WHERE detail LIKE 'reprice_%'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit rows %d %v", n, err)
	}
}

func TestRepriceRoutesNotWired(t *testing.T) {
	s := repriceServer(t, nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/reprice/status", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status got %d", rr.Code)
	}
	if rr := shellWrapPost(s, "/api/reprice/plan", `{}`, "", nil); rr.Code != http.StatusNotImplemented {
		t.Fatalf("plan got %d", rr.Code)
	}
}

// TestRepriceApplyRefusedWhenPricingPinned: the service refuses an APPLY
// under the org's pricing pin (repricesvc owns the check, so the CLI is
// refused too - review finding 5); the card renders the refusal as the
// governance refusal every pinned Settings write answers with (409
// governance_read_only). A revert is never refused.
func TestRepriceApplyRefusedWhenPricingPinned(t *testing.T) {
	fake := &fakeReprice{digest: "abc", applyErr: fmt.Errorf("wrapped: %w", &repricesvc.GovernanceRefusedError{
		Section:   repriceSettingsSection,
		Effective: govern.Effective{Active: true, OrgName: "Acme", ReadOnlySettings: []string{repriceSettingsSection}},
	})}
	s := repriceServer(t, fake)
	tok, ck := repriceToken(t, s)
	rr := shellWrapPost(s, "/api/reprice/apply", `{"digest":"abc"}`, tok, ck)
	if rr.Code != http.StatusConflict {
		t.Fatalf("pinned apply: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error   string `json:"error"`
		Section string `json:"section"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error != "governance_read_only" || body.Section != "pricing" {
		t.Fatalf("refusal body %s", rr.Body.String())
	}
	if rr := shellWrapPost(s, "/api/reprice/revert", `{"run_id":7}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("revert under the pin: %d %s", rr.Code, rr.Body.String())
	}
}

// TestRepriceApplyBusyIsConflict: another run holding the claim is a 409
// naming the running run, not a 500.
func TestRepriceApplyBusyIsConflict(t *testing.T) {
	fake := &fakeReprice{digest: "abc", applyErr: fmt.Errorf("repricesvc.Apply: %w", &store.RepriceBusyError{RunningRunID: 11})}
	s := repriceServer(t, fake)
	tok, ck := repriceToken(t, s)
	rr := shellWrapPost(s, "/api/reprice/apply", `{"digest":"abc"}`, tok, ck)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "run 11") {
		t.Fatalf("busy apply: %d %s", rr.Code, rr.Body.String())
	}
}
