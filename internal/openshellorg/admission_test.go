package openshellorg

import (
	"strings"
	"testing"
)

// TestAdmittedTable pins the request-id table (FX3 item 2, FX3-A2): the
// creates and the member's mutations carry an id, the execs, the reads and
// the worker's idempotent cleanup do not.
func TestAdmittedTable(t *testing.T) {
	for _, tc := range []struct {
		call GatewayCall
		want bool
	}{
		{GatewayCreate, true},
		{GatewayDelete, true},
		{GatewayAttach, true},
		{GatewayDetach, true},
		{GatewayCreateProvider, true},
		{GatewayStart, true},
		{GatewayCleanupDelete, false},
		{GatewayDeleteProvider, false},
		{GatewayStop, false},
		{GatewayExec, false},
		{GatewayExecLive, false},
		{GatewayGet, false},
	} {
		if got := Admitted(tc.call); got != tc.want {
			t.Errorf("%s admitted %v, want %v", tc.call, got, tc.want)
		}
	}
	if ExecRequestID() != "" || CleanupRequestID() != "" {
		t.Error("an exec or a cleanup call carries a request id, so the gateway admits it")
	}
}

// TestRunCostRows is one case per row of the run-cost table: a private
// clone costs the member 4 (create, attach, detach, delete) and the worker
// 1 (the provider's create; its delete is cleanup).
func TestRunCostRows(t *testing.T) {
	for _, tc := range []struct {
		name          string
		private, held bool
		want          RunCost
	}{
		{"private clone, held and resumed", true, true, RunCost{Member: 4, Worker: 2}},
		{"private clone", true, false, RunCost{Member: 4, Worker: 1}},
		{"held and resumed", false, true, RunCost{Member: 2, Worker: 1}},
		{"a plain run", false, false, RunCost{Member: 2}},
	} {
		if got := RunCostFor(tc.private, tc.held); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestBudget: the surfaced budget is the 0.1.6 gateway's, and a member's
// day is 500 plain runs (the live run saw about 3 while every exec counted).
func TestBudget(t *testing.T) {
	b := Budget()
	if b.PerCallerPerDay != 1000 || b.WindowHours != 24 || b.RunsPerMemberPerDay != 500 || b.Note == "" {
		t.Errorf("budget %+v", b)
	}
	if !IsAdmissionLimit("provider rate limit: caller has reached the durable mutation admission limit; unresolved requests require reconciliation") {
		t.Error("the gateway's own refusal text is not recognised")
	}
	if IsAdmissionLimit("quota_concurrent") {
		t.Error("an org quota read as the gateway's admission limit")
	}
}

// TestCollectOrDiscardCost (FX4 item 5, F-P6-6, measured live in phase
// 6a): the worker's collect or discard of a stopped or ending box costs the
// worker its start (1); its delete is cleanup; the member nothing. The
// surfaced budget carries it and its note names it.
func TestCollectOrDiscardCost(t *testing.T) {
	if got := CollectCost(); got != (RunCost{Worker: 1}) {
		t.Fatalf("collect or discard %+v, want the worker's one start", got)
	}
	b := Budget()
	if b.CollectOrDiscard != (RunCost{Worker: 1}) || !strings.Contains(b.Note, "collect or discard") {
		t.Errorf("budget %+v", b)
	}
}
