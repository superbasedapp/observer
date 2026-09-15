package aigateway_test

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aigateway"
)

// m2: the stale-reservation threshold must strictly exceed the max stream
// duration; zero fields normalize to the package defaults before comparison.
func TestValidateReconcileWindow(t *testing.T) {
	cases := []struct {
		name       string
		maxStream  time.Duration
		staleAfter time.Duration
		wantErr    bool
	}{
		{"defaults ok (0/0 -> 10m/15m)", 0, 0, false},
		{"stale below stream", 10 * time.Minute, 5 * time.Minute, true},
		{"stale equals stream", 10 * time.Minute, 10 * time.Minute, true},
		{"stale above stream", 10 * time.Minute, 15 * time.Minute, false},
		{"override stream above default stale", 20 * time.Minute, 0, true}, // eff stale=15m < 20m
		{"override stream below default stale", 5 * time.Minute, 0, false}, // eff stale=15m > 5m
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aigateway.ValidateReconcileWindow(tc.maxStream, tc.staleAfter)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}
