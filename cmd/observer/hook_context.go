package main

import (
	"context"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// hostHookSource is the host-path Source of `observer hook`: the operating
// system (hookctx.HostSource) plus this package's /proc ancestry walker.
func hostHookSource() hookctx.Source {
	return hookctx.Source{Ancestors: defaultAncestors}
}

// hostHookProviders are the host-path extension points of the hook context
// seam: the signed posture sidecar reader, the dirty-marker raise and the
// quick-scan request over the owner-only local IPC (security pillar plan
// sections 4.7 and 4.8; hook_security.go). A build without the security
// module wires none, and the fill does no I/O. The invocation's first Fill
// carries no project root and no write, so it reads no posture file; the
// tool gate's enrich step fills again per event.
func hostHookProviders(configPath string) hookctx.HostProviders {
	return securityHostProviders(configPath)
}

// hookContext returns the invocation's filled hook context, attached by
// runHookInvocation. A handler reached without one (a test calling it
// directly) gets the host path with the production ancestry walker, which
// is exactly what it read before the seam.
func hookContext(ctx context.Context) *hookctx.Context {
	if c, ok := hookctx.Attached(ctx); ok {
		return c
	}
	return hookctx.Host(ctx, hookctx.Request{}, hostHookSource(), hookctx.HostProviders{})
}

// The invocation's hook context and config path, for the handlers that do
// not carry the invocation's context.Context (the tool gate entry points
// runToolGate and handleToolGateHook). An `observer hook` process serves
// one invocation, so one slot is enough; a test that calls a handler
// directly gets a fresh host context with the production providers.
var (
	invocationMu           sync.Mutex
	invocationHookCtx      *hookctx.Context
	hookSecurityConfigPath string
)

// setInvocationHookContext records the invocation's filled context.
func setInvocationHookContext(hc *hookctx.Context, configPath string) {
	invocationMu.Lock()
	invocationHookCtx, hookSecurityConfigPath = hc, configPath
	invocationMu.Unlock()
}

// invocationHookContext returns the invocation's hook context, or a fresh
// host context with the production providers for configPath.
func invocationHookContext(ctx context.Context, configPath string) *hookctx.Context {
	invocationMu.Lock()
	hc := invocationHookCtx
	invocationMu.Unlock()
	if hc != nil {
		return hc
	}
	return hookctx.Host(ctx, hookctx.Request{}, hostHookSource(), hostHookProviders(configPath))
}
