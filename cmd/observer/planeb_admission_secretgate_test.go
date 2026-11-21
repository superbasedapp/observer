package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
	"github.com/marmutapp/superbased-observer/internal/testsupport/promptjudgecases"
)

// TestDaemonNodeLaneSecretGateCases drives the node daemon's own wrapper
// (evaluateCodingAdmission, bound as codingAdmissionEngine, then
// promptadmit.Decide as the lane does) over the shared secret-gate table
// the org admin's simulate test also runs (lane adm-p2 lows, N3): the judge
// is never called and the outcome is the table's.
func TestDaemonNodeLaneSecretGateCases(t *testing.T) {
	if codingAdmissionEngine == nil {
		t.Skip("this build links no admission engine")
	}
	for _, tc := range promptjudgecases.SecretGateCases {
		t.Run(tc.Name, func(t *testing.T) {
			spec, _, err := planebadmission.CompileBody([]byte(tc.Draft), 0)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			judge := func(context.Context, string) (string, error) {
				calls.Add(1)
				return `{"decision":"allow"}`, nil
			}
			res := codingAdmissionEngine(context.Background(), promptjudgecases.SecretSample, spec.Admission, judge)
			o := promptadmit.Decide(planebadmission.Enforces(spec), spec.Admission.Strict, res)
			if calls.Load() != 0 {
				t.Fatalf("the daemon's lane called the judge %d times with a secret-bearing prompt", calls.Load())
			}
			if string(o.Action) != tc.WantAction || string(o.Basis) != tc.WantBasis || !strings.Contains(o.Reason, tc.WantReasonSub) {
				t.Fatalf("daemon lane = %+v, want %s/%s with %q", o, tc.WantAction, tc.WantBasis, tc.WantReasonSub)
			}
		})
	}
}
