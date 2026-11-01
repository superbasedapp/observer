//go:build sbo_omit_security

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hook_security_omit.go stands in for hook_security.go without the
// security module: the hook context seam gets no security provider, the
// tool gate no enrich step and guard no rule pack, so the hook reads and
// writes nothing of the pillar's.

func securityHostProviders(string) hookctx.HostProviders { return hookctx.HostProviders{} }

func securityDaemonProviders(string) hookctx.DaemonProviders { return hookctx.DaemonProviders{} }

func securityToolGateEnrich(string, string, string, func(string) (map[string]string, bool)) func(*policy.Event) {
	// No security facts; the project lookup root is guard's (hook_projectroot.go).
	return withProjectLookupRoot(nil)
}

func securityHookPackRules(string) []policy.Rule { return nil }

func hookSecurityAliases(config.Config, error) func(string) (map[string]string, bool) { return nil }
