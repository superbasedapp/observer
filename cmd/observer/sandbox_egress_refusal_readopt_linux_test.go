//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
)

// TestReadoptGatewayRefusalsStillLand (lane N1, the re-adoption row beside
// TestReadoptGatewayKeepsTheHostList): a run re-adopted after a daemon
// restart serves a gateway whose refusals still reach the daemon's refusal
// audit, through the re-keyed run record the re-adoption reads.
func TestReadoptGatewayRefusalsStillLand(t *testing.T) {
	h := leftsbxReadoptRun(t)
	st := refusalDaemon(t, h.ObserverDir)
	stop, err := readoptHostServices(h)
	defer stop()
	if err != nil {
		t.Fatal(err)
	}
	b := refusedThroughGateway(t, h.SockDir, "evil.invalid:443")
	if b.Rule != string(sandboxnet.RefusalAllowListMiss) || b.Host != "evil.invalid" {
		t.Fatalf("body %+v", b)
	}
	rows := waitRefusalRows(t, st, h.RelayRun, 1)
	if r := rows[0]; r.Host != "evil.invalid" || r.Rule != "allow-list-miss" || r.Key != sandboxnet.KeyEgressAllowHosts {
		t.Fatalf("row %+v", r)
	}
}
