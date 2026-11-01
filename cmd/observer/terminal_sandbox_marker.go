//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandboxEnvMarker is the env var a sandboxed launch carries (set on the
// child inside the boundary, stripped from inherited env). Its owner is
// internal/sandbox; terminal_sandbox_omit.go repeats the literal for a build
// without terminals.sandbox, which still strips a spoofed marker.
const sandboxEnvMarker = sandbox.EnvMarker

// sandboxTierRouteNotice is the tier's own model-route notice for a
// launcher running inside a sandbox whose tier is named (sandbox.EnvEgress),
// or "" outside one, for an unnamed or unknown tier, or for a tier with a
// direct route (the caller's notice stands).
func sandboxTierRouteNotice(tool, proxyURL string) string {
	if os.Getenv(sandboxEnvMarker) != "1" {
		return ""
	}
	tier := strings.TrimSpace(os.Getenv(sandbox.EnvEgress))
	if tier == "" {
		return ""
	}
	p, err := sandbox.ResolveEgress(tier)
	if err != nil {
		return ""
	}
	return sandbox.ModelRouteNotice(p, tool, proxyURL)
}

// sandboxTierEnv is the tier variable (sandbox.EnvEgress) a sandboxed
// launch's child carries beside the marker, so the launcher inside the box
// says its own tier's model route (P-094 residual, lane SHR-FOLLOWUPS):
// nil when the tier cannot be read. It changes what the in-box launcher
// says, never a route. The tier is read from the launch's own wrap argv,
// the host helper's network flags (sandboxTierOfWrap), so every local
// driver whose wrap runs the host helper gets it from the one launcher
// line; the MXC row, whose wrap has no host helper, sets it from its plan
// (mxcBoxEnv).
func sandboxTierEnv(wrap []string) []string {
	if tier := sandboxTierOfWrap(wrap); tier != "" {
		return []string{sandbox.EnvEgress + "=" + tier}
	}
	return nil
}

// sandboxTierChildEnv returns env with the sandbox marker set and the tier
// variable (sandbox.EnvEgress) set only from the launch's own wrap
// (sandboxTierEnv), every inherited value removed first, so the developer's
// own environment can never name a tier for the box (ledger SBX-BE-16, lane
// LEFT-SBX). Both the CLI path (`observer <tool> --observer-sandbox`) and
// the dashboard launch build a sandboxed child's environment through it; the
// host helpers apply the same rule again on their side (withSandboxTier).
func sandboxTierChildEnv(env, wrap []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k == sandbox.EnvEgress || k == sandboxEnvMarker {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, sandboxEnvMarker+"=1")
	return append(out, sandboxTierEnv(wrap)...)
}

// sandboxTierOfWrap reads the tier from the host helper's flags in wrap:
// the tier table row whose network columns the flags show (its own
// namespace, the model proxy forwarded, the egress gateway). "" when the
// wrap runs no host helper or no row matches.
func sandboxTierOfWrap(wrap []string) string {
	for i := 1; i < len(wrap); i++ {
		if wrap[i] != sandbox.HostVerb {
			continue
		}
		h, err := sandbox.ParseHostArgs(wrap[i+1:])
		if err != nil {
			return ""
		}
		return sandboxTierOfHostArgs(h)
	}
	return ""
}

// sandboxTierOfHostArgs is the tier table row whose network columns the
// host helper's parsed flags show (its own namespace, the model proxy
// forwarded, the egress gateway); "" when no row matches.
func sandboxTierOfHostArgs(h sandbox.HostArgs) string {
	for _, m := range sandbox.EgressModes() {
		p, err := sandbox.ResolveEgress(m)
		if err == nil && p.UnshareNet == h.PrivateNet && p.ForwardProxy == (h.ProxyAddr != "") && p.Gateway == h.Gateway {
			return string(p.Mode)
		}
	}
	return ""
}

// withSandboxTier returns env with the tier variable (sandbox.EnvEgress)
// set from the host helper's own flags h, the one tier table, replacing any
// inherited value; with no matching row the inherited value is dropped, so
// a stale or spoofed tier never reaches the box. The host helper (bwrap and
// process_lite) and the container host helper (oci-runc, oci-runsc) apply
// it to the environment they hand on, so the launcher in every such box
// says its own tier's model route (Linux live check 2026-10-23, R3: the
// none tier on the OCI rows still said traffic goes straight to Anthropic).
func withSandboxTier(env []string, h sandbox.HostArgs) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k == sandbox.EnvEgress {
			continue
		}
		out = append(out, kv)
	}
	if tier := sandboxTierOfHostArgs(h); tier != "" {
		out = append(out, sandbox.EnvEgress+"="+tier)
	}
	return out
}
