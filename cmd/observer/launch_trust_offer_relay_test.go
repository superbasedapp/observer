//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// The sandboxed clone row of TestTrustOfferedByDefault: the relay gate of a
// copy run reads the clone's files with the source project's accepts.
// Observe goes on; enforce refuses naming the source until it is accepted,
// then the clone launches.
func init() {
	trustOfferRows = append(trustOfferRows, func(e trustOfferEnv) {
		t := e.t
		source, clone := e.newClone(), e.newClone()
		run := sandboxrelayd.RunRecord{
			RunID: "offer", Tool: "claude-code", ProjectRoot: source, WorkspaceDir: clone,
			Roots: []string{clone}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: clone,
		}
		gate := func() error {
			return sandboxGateWalk(context.Background(), e.cfgPath, "claude-code", budgetLaunchEvidence{}, clone, relayRunTrustAcceptRoot(run))
		}
		switch e.mode {
		case "observe":
			if err := gate(); err != nil {
				t.Fatalf("sandboxed clone, observe: %v", err)
			}
		case "enforce":
			if err := gate(); err == nil || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+source) {
				t.Fatalf("sandboxed clone, enforce: %v, want a refusal naming the source", err)
			}
			e.accept(source)
			if err := gate(); err != nil {
				t.Fatalf("sandboxed clone after the source's accept: %v", err)
			}
		}
	})
}
