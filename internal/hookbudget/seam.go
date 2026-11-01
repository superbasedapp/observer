package hookbudget

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// seamRequest is a request that would use every provider: a write-capable
// call at a commit sink.
var seamRequest = hookctx.Request{
	Tool: "claude-code", Event: "pre-tool", ProjectRoot: "/repo", SessionID: "s",
	WriteCapable: true, QuickScan: &hookctx.QuickScanRequest{ProjectRoot: "/repo"},
}

// SeamSamples times n host-path fills of the hook context seam with
// today's nil providers (the Seam row). It touches no file or process.
// Every sample is timed with the harness clock (clock.go), never Go's
// monotonic clock, whose step on Windows is larger than the cost measured.
func SeamSamples(n int) []time.Duration {
	return seamSamples(n, hookctx.HostProviders{})
}

// SeamProviderSamples times n host-path fills with three no-op providers
// wired (the SeamProviders row).
func SeamProviderSamples(n int) []time.Duration {
	return seamSamples(n, hookctx.HostProviders{
		Sidecar: func(context.Context, hookctx.Request) (hookctx.Security, error) {
			return hookctx.Security{Posture: hookctx.PostureClean}, nil
		},
		Dirty: func(context.Context, string) error { return nil },
		QuickScan: func(context.Context, hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
			return hookctx.QuickScanResult{Verdict: hookctx.QuickScanClean}, nil
		},
	})
}

func seamSamples(n int, p hookctx.HostProviders) []time.Duration {
	ctx := context.Background()
	out := make([]time.Duration, n)
	for i := range out {
		start := Now()
		_ = hookctx.Host(ctx, seamRequest, hookctx.Source{}, p)
		out[i] = Since(start)
	}
	return out
}
