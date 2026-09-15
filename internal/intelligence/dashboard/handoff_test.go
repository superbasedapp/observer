package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
)

// TestHandoffTargetsLaunchGating pins the contract a PTY-unsupported daemon
// (a native-Windows install) relies on: when cmd leaves the launch seam
// unwired, handoffTargets(false) reports EVERY target launchable=false so the
// "Launch here" button hides — but the target list itself is intact, so the
// platform-independent "Write handover doc" migration still works for every
// tool. Enabling the launcher flips launchable per capability without
// dropping a target.
func TestHandoffTargetsLaunchGating(t *testing.T) {
	off := handoffTargets(false)
	if len(off) == 0 {
		t.Fatal("handoffTargets(false) returned no targets — the migration picker would be empty")
	}
	for _, tg := range off {
		if tg.Launchable {
			t.Errorf("launcher disabled: target %q launchable=true, want false", tg.Tool)
		}
	}
	on := handoffTargets(true)
	if len(on) != len(off) {
		t.Fatalf("target count changed with launch gating: on=%d off=%d (gating must flip a flag, never drop a target)", len(on), len(off))
	}
	var sawLaunchable bool
	for _, tg := range on {
		if tg.Tool == "claude-code" && tg.Launchable {
			sawLaunchable = true
		}
	}
	if !sawLaunchable {
		t.Error("launcher enabled: claude-code launchable=false, want true")
	}
}

// stubHandoffRunner returns a canned handoffsvc result and records the
// request it saw — the endpoints are thin wrappers, so the tests pin the
// wiring (param → Request mapping, status mapping, JSON shape), not the
// service logic (owned by internal/handoffsvc's own tests).
func stubHandoffRunner(t *testing.T, got *handoffsvc.Request, res handoffsvc.Result, err error) func(context.Context, handoffsvc.Request) (handoffsvc.Result, error) {
	t.Helper()
	return func(_ context.Context, req handoffsvc.Request) (handoffsvc.Result, error) {
		*got = req
		return res, err
	}
}

func handoffStubResult() handoffsvc.Result {
	return handoffsvc.Result{
		ShortID:     "abcd1234",
		CarryUsed:   handoff.CarryDistilledTail,
		TargetModel: "opus-4-8",
		Fork:        handoff.ForkResolution{ResolvedIndex: 5},
		Estimate: handoff.EstimateResult{
			TargetModel: "opus-4-8",
			ForkShare:   1,
			Rows: []handoff.CarryEstimate{
				{Mode: handoff.CarryMetadata, Tokens: 400, CostUSD: 0.02, Note: "action-derived facts only"},
			},
		},
		Boundaries: []handoff.Boundary{
			{Index: 1, Role: "user", Stable: false, Reason: "awaiting reply", CumulativeShare: 0.4, Preview: "build it"},
			{Index: 2, Role: "assistant", Stable: true, CumulativeShare: 1, Preview: "built"},
		},
	}
}

func TestHandleSessionHandoffEstimate(t *testing.T) {
	srv, _ := newTestServer(t)
	var got handoffsvc.Request
	srv.opts.BuildHandoff = stubHandoffRunner(t, &got, handoffStubResult(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/handoff/estimate?to=codex&fork=3&carry=distilled&target_model=gpt-5.4", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	// Wiring: query params → Request, always a dry run with boundaries.
	if got.SessionID != "sA" || got.TargetTool != "codex" || got.TargetModel != "gpt-5.4" ||
		got.Carry != handoff.CarryMode("distilled") || !got.DryRun || !got.IncludeBoundaries {
		t.Errorf("request = %+v", got)
	}
	if got.Fork.Kind != handoff.ForkMessageIndex || got.Fork.MessageIndex != 3 {
		t.Errorf("fork = %+v", got.Fork)
	}

	var resp handoffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "sA" || resp.CarryUsed != "distilled_tail" || len(resp.Estimate.Rows) != 1 {
		t.Errorf("response = %+v", resp)
	}
	if resp.FullCacheAvailable {
		t.Errorf("full_cache_available = true, want false (handoffStubResult's Estimate leaves SourceHasFullReader unset)")
	}
	if len(resp.Boundaries) != 2 || !resp.Boundaries[1].Stable {
		t.Errorf("boundaries = %+v", resp.Boundaries)
	}
	// Target picker comes from the integration registry — all 16 rows,
	// each with the universal file lane.
	if len(resp.Targets) < 16 {
		t.Fatalf("targets = %d, want the full registry", len(resp.Targets))
	}
	for _, tg := range resp.Targets {
		if !slices.Contains(tg.InjectLanes, "file") {
			t.Errorf("target %s missing file lane: %v", tg.Tool, tg.InjectLanes)
		}
	}
}

// TestBuildHandoffResponse_FullCacheAvailable pins that both endpoints
// (estimate GET and create POST share buildHandoffResponse) surface
// full_cache_available straight from handoff.EstimateResult.SourceHasFullReader
// — never re-derived a second way — for both the 4 adapters that implement
// FullTranscriptReader and the 30 that don't.
func TestBuildHandoffResponse_FullCacheAvailable(t *testing.T) {
	for _, hasReader := range []bool{false, true} {
		res := handoffStubResult()
		res.Estimate.SourceHasFullReader = hasReader
		resp := buildHandoffResponse("sA", "codex", res, true)
		if resp.FullCacheAvailable != hasReader {
			t.Errorf("SourceHasFullReader=%v: full_cache_available = %v, want %v", hasReader, resp.FullCacheAvailable, hasReader)
		}
	}
}

func TestHandleSessionHandoffEstimate_BadFork(t *testing.T) {
	srv, _ := newTestServer(t)
	var got handoffsvc.Request
	srv.opts.BuildHandoff = stubHandoffRunner(t, &got, handoffStubResult(), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/handoff/estimate?fork=zero", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestHandleSessionHandoff_NilRunnerIs503(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/api/session/sA/handoff/estimate", "/api/session/sA/handoff"} {
		method := http.MethodGet
		if !strings.HasSuffix(path, "estimate") {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		srv.handleSessionDetail(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d, want 503", path, rec.Code)
		}
	}
}

func TestHandleSessionHandoff_ErrorMapping(t *testing.T) {
	srv, _ := newTestServer(t)
	// The ErrSessionNotFound sentinel (wrapped) maps to 404.
	srv.opts.BuildHandoff = func(_ context.Context, _ handoffsvc.Request) (handoffsvc.Result, error) {
		return handoffsvc.Result{}, fmt.Errorf("%w: %q", handoffsvc.ErrSessionNotFound, "nope")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/session/nope/handoff/estimate", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	// Any other service error is a 400 carrying the honest message.
	srv.opts.BuildHandoff = func(_ context.Context, _ handoffsvc.Request) (handoffsvc.Result, error) {
		return handoffsvc.Result{}, errors.New("unknown carry mode \"x\"")
	}
	rec = httptest.NewRecorder()
	srv.handleSessionDetail(rec, httptest.NewRequest(http.MethodGet, "/api/session/sA/handoff/estimate", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown carry mode") {
		t.Fatalf("status %d body %q, want 400 with the service message", rec.Code, rec.Body.String())
	}
}

func TestHandleSessionHandoffCreate(t *testing.T) {
	srv, _ := newTestServer(t)
	var got handoffsvc.Request
	res := handoffStubResult()
	res.Doc = "# Session handoff"
	res.DocPath = "/tmp/p/HANDOFF-abcd1234.md"
	res.HandoffID = 7
	res.GitignoreHint = true
	srv.opts.BuildHandoff = stubHandoffRunner(t, &got, res, nil)

	body := `{"to":"codex","fork_message":4,"carry":"full","out_path":"/tmp/x.md"}`
	req := httptest.NewRequest(http.MethodPost, "/api/session/sA/handoff", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got.SessionID != "sA" || got.TargetTool != "codex" || got.Carry != handoff.CarryFull ||
		got.OutPath != "/tmp/x.md" || got.DryRun || got.IncludeBoundaries {
		t.Errorf("request = %+v", got)
	}
	if got.Fork.Kind != handoff.ForkMessageIndex || got.Fork.MessageIndex != 4 {
		t.Errorf("fork = %+v", got.Fork)
	}
	var resp handoffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DocPath != res.DocPath || resp.HandoffID != 7 || !resp.GitignoreHint || resp.Doc == "" {
		t.Errorf("response = %+v", resp)
	}

	// GET on the create route is a 405.
	reqGet := httptest.NewRequest(http.MethodGet, "/api/session/sA/handoff", nil)
	recGet := httptest.NewRecorder()
	srv.handleSessionDetail(recGet, reqGet)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status %d, want 405", recGet.Code)
	}
}
