package hookctx

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// noAnswer is the detail Fill records for a quick-scan provider that
// failed without naming a reason.
var noAnswer = policy.QuickScanDetail{Reason: policy.QuickScanReasonNoAnswer}

type reasonErr struct{ reason string }

func (e reasonErr) Error() string           { return "provider: " + e.reason }
func (e reasonErr) QuickScanReason() string { return e.reason }

type detailErr struct{ d policy.QuickScanDetail }

func (e detailErr) Error() string                           { return "provider timed out" }
func (e detailErr) QuickScanDetail() policy.QuickScanDetail { return e.d }

// TestQuickScanFailureCarriesTheReason: a provider failure Fill records is
// unknown with the error's own detail, else its reason, else no_answer, so
// the commit gate's verdict can say why (and wrapping keeps it).
func TestQuickScanFailureCarriesTheReason(t *testing.T) {
	timedOut := policy.QuickScanDetail{Reason: policy.QuickScanReasonOverBudget, Budget: 2 * time.Second, Elapsed: 2250 * time.Millisecond}
	for _, tc := range []struct {
		name string
		err  error
		want policy.QuickScanDetail
	}{
		{"plain error", errors.New("dial: refused"), noAnswer},
		{"deadline", context.DeadlineExceeded, noAnswer},
		{"reason", reasonErr{policy.QuickScanReasonNotServing}, policy.QuickScanDetail{Reason: policy.QuickScanReasonNotServing}},
		{"wrapped reason", fmt.Errorf("ask: %w", reasonErr{policy.QuickScanReasonNoTime}), policy.QuickScanDetail{Reason: policy.QuickScanReasonNoTime}},
		{"empty reason", reasonErr{""}, noAnswer},
		{"detail", fmt.Errorf("ask: %w", detailErr{timedOut}), timedOut},
	} {
		got := QuickScanFailure(tc.err)
		if got.Verdict != QuickScanUnknown || got.Detail != tc.want || got.DirtyCovered != 0 || len(got.Findings) != 0 {
			t.Errorf("%s: QuickScanFailure = %+v, want unknown with %+v", tc.name, got, tc.want)
		}
	}
}
