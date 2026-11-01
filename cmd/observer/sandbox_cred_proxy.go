//go:build !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// sandbox_cred_proxy.go joins credential injection to the proxy (lane
// GATES-SBX, G24): the daemon's injector behind proxy.CredentialInjector,
// installed only while terminals.sandbox.credentials is selected. A build
// without the proxy (sbo_omit_capture_proxy) has no injection.

func init() {
	credProxyBuilt = true
	sandboxDriversRebuildHooks = append(sandboxDriversRebuildHooks, credInstallInjector)
}

// Inject implements proxy.CredentialInjector.
func (i *credInjector) Inject(_ context.Context, in proxy.CredentialRequest) (string, string, bool) {
	return i.decide(in.RunID, in.Token, in.Host, in.XAPIKey, in.Authorization, in.GoogKey)
}

// credInstallInjector installs the proxy's injector in a process whose
// config selects the component, and clears it otherwise (a driver rebuild
// hook: the daemon rebuilds at start and on every config change).
func credInstallInjector() {
	if !credActive(context.Background()) {
		proxy.SetCredentialInjector(nil)
		return
	}
	proxy.SetCredentialInjector(&credInjector{observerDir: credObserverDir()})
}
