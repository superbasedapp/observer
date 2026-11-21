//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// fu9Answer reads one real OpenShell v0.1.6 answer saved by live check
// FU8-L1 (the fixtures of internal/sandboxopenshell).
func fu9Answer(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "sandboxopenshell", "testdata", "openshell-0.1.6", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOpenShellGatewayPolicyStepRealAnswers (lane FU9, tracker F-040): row
// PS's step over the real v0.1.6 answers, in both modes. An untouched
// gateway (every setting "<unset>", no global policy ever set: exit 1)
// passes, and so does a deleted (superseded) global policy; a loaded global
// policy and auto approval with the other setting unset are refused; the
// global read asks for --full.
func TestOpenShellGatewayPolicyStepRealAnswers(t *testing.T) {
	untouched := fu9Answer(t, "settings-global.txt")
	auto := []byte(strings.Replace(string(untouched), "proposal_approval_mode = <unset>", "proposal_approval_mode = auto", 1))
	none := extrun.Result{Outcome: extrun.OutcomeExitNonZero, ExitCode: 1, Stderr: fu9Answer(t, "global-none.err")}
	loaded := extrun.Result{Outcome: extrun.OutcomeOK, Stdout: fu9Answer(t, "global-set-loaded.json")}
	superseded := extrun.Result{Outcome: extrun.OutcomeOK, Stdout: fu9Answer(t, "global-after-delete-full.json")}
	for _, c := range []struct {
		name     string
		settings []byte
		global   extrun.Result
		want     string
	}{
		{"untouched", untouched, none, ""},
		{"global policy deleted", untouched, superseded, ""},
		{"global policy loaded", untouched, loaded, sandboxopenshell.VerdictGatewayGlobalPolicy},
		{"auto approval", auto, none, sandboxopenshell.VerdictGatewayAutoApproval},
	} {
		for _, mode := range []string{sandboxopenshell.GatewayExternal, sandboxopenshell.GatewayManaged} {
			prev := openShellManagedDBDrift()
			g := &openShellGathering{}
			g.out.facts.GatewayMode = mode
			g.out.pin.Target = sandboxopenshell.Target{Gateway: "observer-0123456789ab"}
			fullAsked := false
			g.runAt = func(_ context.Context, _ sandboxopenshell.Target, _ integration.BinaryResolveSpec, args []string) extrun.Result {
				if slices.Contains(args, "settings") {
					return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: c.settings}
				}
				fullAsked = slices.Contains(args, "--full")
				return c.global
			}
			openShellGatewayPolicyStep(context.Background(), g)
			openShellRecordManagedDB(prev)
			if !fullAsked {
				t.Errorf("%s (%s): the global read did not ask for --full", c.name, mode)
			}
			if v, r, _ := sandboxopenshell.GatewayPolicyVerdict(mode, g.out.facts.GatewayPolicy); v != c.want {
				t.Errorf("%s (%s): got %q (%s), want %q", c.name, mode, v, r, c.want)
			}
		}
	}
}
