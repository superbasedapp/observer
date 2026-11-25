// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package main

import "testing"

// TestDecideProxyFallback_Table pins representative rows across the four injected
// capability facts. The persistent-route rows are enumerated for BOTH
// canNeutralizePersistent values to prove the claude-vs-codex asymmetry: a route
// the launcher can override (claude `--settings`) neutralizes; one it can't
// (codex config.toml) fails closed.
func TestDecideProxyFallback_Table(t *testing.T) {
	cases := []struct {
		name       string
		in         proxyFallbackInputs
		wantAction proxyFallbackAction
		wantReason proxyFallbackReason
	}{
		// --no-proxy-route + persistent route, NOT overridable (codex shape) → fail
		// closed, regardless of proxy reachability.
		{
			"no-proxy-route + route + not-overridable + up → fail closed",
			proxyFallbackInputs{noProxyRoute: true, proxyReachable: true, persistentRoute: true, canNeutralizePersistent: false},
			proxyFailClosed, reasonNoProxyRouteConflict,
		},
		{
			"no-proxy-route + route + not-overridable + down → fail closed",
			proxyFallbackInputs{noProxyRoute: true, proxyReachable: false, persistentRoute: true, canNeutralizePersistent: false},
			proxyFailClosed, reasonNoProxyRouteConflict,
		},
		// --no-proxy-route + persistent route, OVERRIDABLE (claude --settings) →
		// neutralize (the row-1 rework honoring decision #2).
		{
			"no-proxy-route + route + overridable → neutralize",
			proxyFallbackInputs{noProxyRoute: true, proxyReachable: false, persistentRoute: true, canNeutralizePersistent: true},
			proxyNeutralize, reasonNoProxyRouteClean,
		},
		// --no-proxy-route + no persistent route → neutralize (canNeutralize moot).
		{
			"no-proxy-route + no route → neutralize",
			proxyFallbackInputs{noProxyRoute: true, proxyReachable: false, persistentRoute: false},
			proxyNeutralize, reasonNoProxyRouteClean,
		},
		// routed + proxy reachable → proceed (route present or not, overridable or
		// not).
		{
			"routed + proxy up + route + not-overridable → proceed",
			proxyFallbackInputs{noProxyRoute: false, proxyReachable: true, persistentRoute: true, canNeutralizePersistent: false},
			proxyRouteProceed, reasonRouteHealthy,
		},
		{
			"routed + proxy up + no route → proceed",
			proxyFallbackInputs{noProxyRoute: false, proxyReachable: true, persistentRoute: false},
			proxyRouteProceed, reasonRouteHealthy,
		},
		// routed + proxy DOWN + persistent route, NOT overridable (codex) → fail
		// closed (the dead baked-in proxy).
		{
			"routed + proxy down + route + not-overridable → fail closed",
			proxyFallbackInputs{noProxyRoute: false, proxyReachable: false, persistentRoute: true, canNeutralizePersistent: false},
			proxyFailClosed, reasonProxyDownConflict,
		},
		// routed + proxy DOWN + persistent route, OVERRIDABLE (claude --settings) →
		// neutralize (the row-4 rework: working daemon-down fallback via override).
		{
			"routed + proxy down + route + overridable → neutralize",
			proxyFallbackInputs{noProxyRoute: false, proxyReachable: false, persistentRoute: true, canNeutralizePersistent: true},
			proxyNeutralize, reasonProxyDownClean,
		},
		// routed + proxy DOWN + no route → neutralize (working daemon-down fallback).
		{
			"routed + proxy down + no route → neutralize",
			proxyFallbackInputs{noProxyRoute: false, proxyReachable: false, persistentRoute: false},
			proxyNeutralize, reasonProxyDownClean,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideProxyFallback(tc.in)
			if got.action != tc.wantAction || got.reason != tc.wantReason {
				t.Fatalf("decideProxyFallback(%+v) = {action:%d reason:%d}, want {action:%d reason:%d}",
					tc.in, got.action, got.reason, tc.wantAction, tc.wantReason)
			}
		})
	}
}

// TestDecideProxyFallback_Exhaustive proves the table is total over all 2^5
// inputs and that fail-closed happens EXACTLY on a blocking route
// (persistentRoute && !canNeutralizePersistent) combined with a non-proceed
// intent, or on a routed proxy-down launch whose organization owns the route
// (orgRequiresRoute) — never otherwise.
func TestDecideProxyFallback_Exhaustive(t *testing.T) {
	failClosed := 0
	for _, npr := range []bool{false, true} {
		for _, reach := range []bool{false, true} {
			for _, route := range []bool{false, true} {
				for _, canNeut := range []bool{false, true} {
					for _, org := range []bool{false, true} {
						in := proxyFallbackInputs{
							noProxyRoute: npr, proxyReachable: reach,
							persistentRoute: route, canNeutralizePersistent: canNeut,
							orgRequiresRoute: org,
						}
						d := decideProxyFallback(in)
						switch d.action {
						case proxyRouteProceed, proxyNeutralize, proxyFailClosed:
						default:
							t.Fatalf("undefined action for %+v", in)
						}
						blocking := route && !canNeut
						want := (blocking && (npr || !reach)) || (org && !npr && !reach)
						if (d.action == proxyFailClosed) != want {
							t.Errorf("%+v: fail-closed = %v, want %v", in, d.action == proxyFailClosed, want)
						}
						if d.action == proxyFailClosed {
							failClosed++
						}
						if d.reason == reasonProxyDownOrgRoute && (!org || blocking || npr || reach) {
							t.Errorf("%+v: the org reason fired outside its row", in)
						}
					}
				}
			}
		}
	}
	// Blocking (route && !canNeut): {npr,down}, {npr,up}, {routed,down} fail
	// closed, for both org values: 6. Org on a routed, down, non-blocking
	// launch: (route,canNeut) in {(f,f),(f,t),(t,t)}: 3 more. So 9.
	if failClosed != 9 {
		t.Fatalf("expected 9 fail-closed combinations, got %d", failClosed)
	}
}

// TestDecideProxyFallback_OrgRow pins the managed-node row: a routed,
// proxy-down launch with nothing pinned fails closed with its own reason
// when the organization owns the route, and neutralizes otherwise.
func TestDecideProxyFallback_OrgRow(t *testing.T) {
	got := decideProxyFallback(proxyFallbackInputs{orgRequiresRoute: true})
	if got.action != proxyFailClosed || got.reason != reasonProxyDownOrgRoute {
		t.Fatalf("org-owned, down = %+v, want fail closed / reasonProxyDownOrgRoute", got)
	}
	got = decideProxyFallback(proxyFallbackInputs{orgRequiresRoute: true, proxyReachable: true})
	if got.action != proxyRouteProceed {
		t.Fatalf("org-owned, up = %+v, want proceed", got)
	}
}
