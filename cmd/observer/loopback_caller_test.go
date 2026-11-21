//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
)

// TestCallerGateDecisions drives the gate with fake sources, one case per
// shape the dashboard relies on: the owner's browser passes while a box
// runs, a process inside a box is refused, an unidentified caller is
// refused only while a reachable box lives, and a reachable box with no
// known root keeps the coarse refusal.
func TestCallerGateDecisions(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:54321")
	srv := netip.MustParseAddrPort("127.0.0.1:8081")
	ex := func(ids ...string) []exposedBox {
		var out []exposedBox
		for _, id := range ids {
			out = append(out, exposedBox{RunID: id, TreeContained: true})
		}
		return out
	}
	terminalBox := []dashapi.LaunchInfo{{ID: "h-box", RunID: "run-term", Sandboxed: true, Isolation: &dashapi.LaunchIsolation{Class: "process", Backend: "bwrap", EgressTier: "host"}}}
	cases := []struct {
		name     string
		client   netip.AddrPort
		mutating bool
		snap     []dashapi.LaunchInfo
		markers  []sandboxCLIMarker
		cliAlive bool
		exposed  []exposedBox
		expFail  bool
		peer     peerproc.Peer
		findErr  error
		refuse   string // substring; "" = allowed
		noLookup bool
	}{
		{name: "a read passes", client: loop, snap: terminalBox, exposed: ex("run-term"), noLookup: true},
		{name: "a remote peer passes", client: netip.MustParseAddrPort("192.168.1.9:4000"), mutating: true, snap: terminalBox, exposed: ex("run-term"), noLookup: true},
		{name: "no box: no lookup at all", client: loop, mutating: true, noLookup: true},
		{name: "the owner's browser while a terminal box runs", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), peer: peerproc.Peer{PID: 900, Ancestors: []int{800, 1}}},
		{name: "a process inside a terminal box", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), peer: peerproc.Peer{PID: 4242, Ancestors: []int{4100, 4000, 1}}, refuse: "inside sandboxed run run-term"},
		{name: "a process inside a CLI box", client: loop, mutating: true, markers: []sandboxCLIMarker{{RunID: "run-cli", PID: 7000, Start: "s"}}, cliAlive: true, exposed: ex("run-cli"), peer: peerproc.Peer{PID: 7100, Ancestors: []int{7050, 7000, 1}}, refuse: "inside sandboxed run run-cli"},
		{name: "a CLI root whose start changed is no root", client: loop, mutating: true, markers: []sandboxCLIMarker{{RunID: "run-cli", PID: 7000, Start: "s"}}, cliAlive: false, peer: peerproc.Peer{PID: 7100, Ancestors: []int{7000, 1}}, noLookup: true},
		{name: "unidentified while a reachable box lives", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), findErr: errors.New("no process"), refuse: "could not be identified"},
		{name: "only boxes that cannot reach us: no lookup at all (L4)", client: loop, mutating: true, snap: terminalBox, findErr: errors.New("no process"), noLookup: true},
		{name: "another uid's socket, holder unreadable, every box process read (WSL browser, H2)", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), peer: peerproc.Peer{Outside: true, SocketUID: 0}},
		{name: "this user's socket with no holder found is refused (fixes-2, N1)", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), peer: peerproc.Peer{Outside: true, SocketUID: 1000}, refuse: "could not be identified"},
		{name: "an unknown socket owner is never another uid", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), peer: peerproc.Peer{Outside: true, SocketUID: -1}, refuse: "could not be identified"},
		{name: "holder unreadable and a box process unreadable (H2)", client: loop, mutating: true, snap: terminalBox, exposed: ex("run-term"), findErr: peerproc.ErrBoxUnreadable, refuse: "could not be identified"},
		{name: "a reachable box whose backend has no PID namespace refuses everyone (H3)", client: loop, mutating: true, snap: terminalBox, exposed: []exposedBox{{RunID: "run-term", TreeContained: false}}, peer: peerproc.Peer{PID: 900, Ancestors: []int{1}}, refuse: "cannot all be traced"},
		{name: "a reachable box with no known root", client: loop, mutating: true, exposed: ex("run-orphan"), peer: peerproc.Peer{PID: 900, Ancestors: []int{1}}, refuse: "cannot all be traced"},
		{name: "the exposure read failed: unidentified refused", client: loop, mutating: true, snap: terminalBox, expFail: true, findErr: errors.New("no process"), refuse: "could not be identified"},
		{name: "the exposure read failed: the owner still passes", client: loop, mutating: true, snap: terminalBox, expFail: true, peer: peerproc.Peer{PID: 900, Ancestors: []int{1}}},
		{name: "an unparsable client address is a local unidentified caller", mutating: true, snap: terminalBox, exposed: ex("run-term"), refuse: "could not be identified", noLookup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			g := callerGateSources{
				snapshot: func() []dashapi.LaunchInfo { return tc.snap },
				pidFor:   func(h string) (int, bool) { return map[string]int{"h-box": 4000}[h], h == "h-box" },
				markers:  func() []sandboxCLIMarker { return tc.markers },
				cliAlive: func(int, string) bool { return tc.cliAlive },
				exposures: func(context.Context) ([]exposedBox, string, bool) {
					if tc.expFail {
						return nil, "the live sandboxed runs could not be read", true
					}
					return tc.exposed, "refused while sandboxed run is live", false
				},
				find: func(context.Context, netip.AddrPort, netip.AddrPort, map[int]string) (peerproc.Peer, error) {
					lookups++
					return tc.peer, tc.findErr
				},
				uid: func() int { return 1000 },
			}
			reason, refused := g.check(context.Background(), tc.client, srv, tc.mutating)
			if tc.refuse == "" && refused {
				t.Fatalf("refused: %s", reason)
			}
			if tc.refuse != "" && (!refused || !strings.Contains(reason, tc.refuse) || !strings.Contains(reason, "LAUNCH-1")) {
				t.Fatalf("reason %q refused %v, want %q", reason, refused, tc.refuse)
			}
			if tc.noLookup && lookups != 0 {
				t.Fatalf("looked the peer up %d times, want none", lookups)
			}
		})
	}
}
