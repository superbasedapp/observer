//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// TestSandboxSetupCheckFindsAStaleRootlessSocket (R4 (e) shape 4): a
// podman.sock file a stopped podman.socket left behind makes the
// docker-group step not applicable passively (R1: no dial), and after a
// check whose probe found that socket did not answer the step is judged
// from Docker's socket alone. A check that reached the engine keeps it not
// applicable.
func TestSandboxSetupCheckFindsAStaleRootlessSocket(t *testing.T) {
	row, ok := sandboxbackend.Get(sandboxbackend.BackendOCIRunc)
	if !ok {
		t.Fatal("no oci-runc row")
	}
	// Only the docker-group step: the other steps' facts read host seams
	// this test does not set.
	row.Setup = []string{"docker-group"}
	const podman = "/run/user/1000/podman/podman.sock"
	access := sandboxsetup.DockerAccess{
		UID: 1000, Groups: []uint32{1000},
		DockerSocket: "/run/docker.sock", DockerGID: 109, DockerMode: 0o660,
		EngineSocket: podman, EngineUID: 1000,
	}
	cases := []struct {
		name              string
		verdict           string
		wantNotApplicable bool
		reasonHas         string
	}{
		{"the socket did not answer", "engine_unreachable", false, "not group read-write"},
		{"the engine answered", "image_missing", true, "rootless engine socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := sandboxSetupHost{
				dockerAccess: func(config.Config) (sandboxsetup.DockerAccess, bool) { return access, true },
				probeRow: func(context.Context, string, config.Config) (sandboxselect.Probe, bool) {
					return sandboxselect.Probe{Compiled: true, Verdict: tc.verdict, Reason: "the engine on " + podman + " did not answer: connection refused"}, true
				},
			}
			var cfg config.Config
			passive := passiveFacts(h, cfg, row, nil)
			if f := passive["docker-group"]; !f.NotApplicable {
				t.Fatalf("passive docker-group = %+v, want not applicable (R1: no dial)", f)
			}
			in := activeCheck(context.Background(), h, sandboxSetupInput{in: sandboxsetup.PlanInput{Row: row, Facts: passive}, cfg: cfg})
			f := in.Facts["docker-group"]
			if f.NotApplicable != tc.wantNotApplicable || !strings.Contains(f.Reason, tc.reasonHas) || !f.Checked {
				t.Fatalf("checked docker-group = %+v, want not applicable %v holding %q", f, tc.wantNotApplicable, tc.reasonHas)
			}
		})
	}
}
