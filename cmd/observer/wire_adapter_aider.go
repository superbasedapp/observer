//go:build !sbo_omit_adapter_aider

package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/aider"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// adapter.aider's watcher wiring (see adapterWirers): aider has no
// project index and its home walk never leaves the native home, so a
// transcript in a repo elsewhere (C:\programsx\<repo>, or the same repo
// seen from WSL as /mnt/c/programsx/<repo>) was never watched. Discovery
// also probes the project roots the store already knows, most recently
// active first, bounded by aider.MaxKnownRoots (T-924).
func init() {
	// D-MU1: in the daemon the home walk runs in the background (no
	// listener waits on it), stops with the daemon, honours
	// [observer.watch].home_walk, and does not run at all when aider is
	// not watched.
	adapterDiscoveryConfigurers = append(adapterDiscoveryConfigurers, func(env adapterDiscoveryEnv) {
		aider.ConfigureDiscovery(aider.DiscoveryOptions{
			Context:    env.ctx,
			Background: true,
			HomeWalk:   env.cfg.Observer.Watch.HomeWalk,
			Active:     env.watched(models.ToolAider),
		})
	})
	adapterWirers = append(adapterWirers, func(a adapter.Adapter, env adapterWireEnv) {
		if _, ok := a.(*aider.Adapter); !ok || env.st == nil {
			return
		}
		st, ctx := env.st, env.ctx
		aider.SetProjectRootSource(func() []string {
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			roots, err := st.RecentProjectRoots(qctx, aider.MaxKnownRoots)
			if err != nil {
				return nil
			}
			return roots
		})
	})
}
