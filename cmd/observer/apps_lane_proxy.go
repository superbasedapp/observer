//go:build !sbo_omit_capture_proxy

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// proxyAppLaneOptions maps [proxy.app_lanes] onto the proxy's local app lane
// options (internal/proxy/applane.go). The budget gate is bound later, at
// the obs wiring point (wireAppLaneGate), which knows the caps.
func proxyAppLaneOptions(cfg config.Config) proxy.AppLaneOptions {
	a := cfg.Proxy.AppLanes
	return proxy.AppLaneOptions{
		Models:                a.Models,
		IncludeUsage:          a.IncludeUsage,
		WorstCaseOutputTokens: a.WorstCaseOutput(),
	}
}
