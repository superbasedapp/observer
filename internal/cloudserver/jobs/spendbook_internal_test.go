package jobs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestBookedSpendUSD is one row per (failure kind x usage known) cell of the
// #16 rule table.
func TestBookedSpendUSD(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind       FailKind
		usageKnown bool
		want       float64
	}{
		{FailInvalidOutput, true, 0.5},
		{FailInvalidOutput, false, 0.25},
		{FailProviderStatus5xx, true, 0.5},
		{FailProviderStatus5xx, false, 0.25},
		{FailProviderStatus4xx, false, 0},
		{FailQuota, false, 0},
		{FailTimeout, false, 0.25},
		{FailPersistenceViolation, false, 0.25},
		{FailPersistenceViolation, true, 0.5},
		{FailTransport, false, 0},
		{FailTransport, true, 0},
		{FailUnsupportedDialect, false, 0},
		{"", false, 0},
		{"", true, 0.5},
		{"made_up", false, 0},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/known=%v", c.kind, c.usageKnown), func(t *testing.T) {
			t.Parallel()
			if got := BookedSpendUSD(c.kind, c.usageKnown, 0.5, 0.25); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	if got := BookedSpendUSD(FailQuota, false, 0, -1); got != 0 {
		t.Fatalf("a negative estimate booked %v", got)
	}
}

// TestClassifyProviderErr is one row per error shape.
func TestClassifyProviderErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want FailKind
	}{
		{"persistence", inference.ErrPersistenceViolation, FailPersistenceViolation},
		{"quota", fmt.Errorf("x: %w", inference.ErrQuota), FailQuota},
		{"timeout", inference.ErrTimeout, FailTimeout},
		{"dialect", inference.ErrUnsupportedDialect, FailUnsupportedDialect},
		{"status 5xx", &inference.ProviderError{StatusCode: 503, Body: "x"}, FailProviderStatus5xx},
		{"status 4xx", &inference.ProviderError{StatusCode: 400, Body: "x"}, FailProviderStatus4xx},
		{"status 401", &inference.ProviderError{StatusCode: 401, Body: "x"}, FailProviderStatus4xx},
		{"transport", errors.New("dial tcp: refused"), FailTransport},
	}
	for _, c := range cases {
		if got := classifyProviderErr(c.err); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// TestEstimateCallUSD pins the estimate: prompt/4 input tokens plus the route's
// full output allowance.
func TestEstimateCallUSD(t *testing.T) {
	t.Parallel()
	route := store.RouteInfo{MaxOutputTokens: 1000, InputPricePerMTok: 1, OutputPricePerMTok: 5}
	got := estimateCallUSD(LunaPrompt{System: "abcd", User: "abcdabcd"}, route) // 12/4+1 = 4 in
	want := 4.0/1e6*1 + 1000.0/1e6*5
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}
