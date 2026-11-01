package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// blockingAdapter's WatchPaths blocks until release closes: the shape of a
// home walk stuck on a macOS privacy prompt (D-MU1).
type blockingAdapter struct {
	name    string
	paths   []string
	release chan struct{}
}

func (b blockingAdapter) Name() string { return b.name }
func (b blockingAdapter) WatchPaths() []string {
	if b.release != nil {
		<-b.release
	}
	return b.paths
}
func (blockingAdapter) IsSessionFile(string) bool { return false }
func (blockingAdapter) ParseSessionFile(context.Context, string, int64) (adapter.ParseResult, error) {
	return adapter.ParseResult{}, nil
}

// TestToolCatalogDoesNotWaitOnABlockedWatchPaths pins D-MU1 at the listener
// start path: the Connected-tools snapshot is built before the dashboard
// and proxy bind, so a blocked WatchPaths must cost at most the bound, and
// the other adapters keep their paths.
func TestToolCatalogDoesNotWaitOnABlockedWatchPaths(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	adapters := []adapter.Adapter{
		blockingAdapter{name: "fast", paths: []string{"/fast"}},
		blockingAdapter{name: "stuck", paths: []string{"/stuck"}, release: release},
	}
	start := time.Now()
	got := toolCatalogFrom(adapters, 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("catalog waited %s on a blocked adapter", elapsed)
	}
	if len(got) != 2 || got[0].Tool != "fast" || got[1].Tool != "stuck" {
		t.Fatalf("catalog = %+v, want both adapters in order", got)
	}
	if !slices.Equal(got[0].WatchPaths, []string{"/fast"}) {
		t.Errorf("fast adapter paths = %v", got[0].WatchPaths)
	}
	if got[1].WatchPaths != nil {
		t.Errorf("stuck adapter paths = %v, want nil", got[1].WatchPaths)
	}
}

// TestConfigureAdapterDiscoveryWatchedGate pins the "a disabled adapter
// does not walk" input: watched is false for an adapter outside
// enabled_adapters or with an inactive component.
func TestConfigureAdapterDiscoveryWatchedGate(t *testing.T) {
	prev := adapterDiscoveryConfigurers
	t.Cleanup(func() { adapterDiscoveryConfigurers = prev })
	var seen adapterDiscoveryEnv
	adapterDiscoveryConfigurers = []func(adapterDiscoveryEnv){func(e adapterDiscoveryEnv) { seen = e }}

	cfg := config.Default()
	cfg.Observer.Watch.EnabledAdapters = []string{"aider", "codex"}
	configureAdapterDiscovery(context.Background(), cfg, func(tool string) bool { return tool != "codex" })
	cases := map[string]bool{"aider": true, "codex": false, "goose": false}
	for tool, want := range cases {
		if got := seen.watched(tool); got != want {
			t.Errorf("watched(%q) = %v, want %v", tool, got, want)
		}
	}
	if !seen.cfg.Observer.Watch.HomeWalk {
		t.Error("home_walk default must be true")
	}
}
