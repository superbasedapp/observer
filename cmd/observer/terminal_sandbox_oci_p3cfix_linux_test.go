//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// terminal_sandbox_oci_p3cfix_linux_test.go holds the helper-side tests of
// the SBX-P3C audit fixes.

// TestOCIAfterRunSaysAReturnRefusal is audit finding 8's terminal line: a
// run whose clone-remote return could not be planned says so when it ends,
// from the run's plan record.
func TestOCIAfterRunSaysAReturnRefusal(t *testing.T) {
	tt := newOCITestTerm()
	ociAfterRun(ociPlanFile{ReturnRefused: "the box's commits will not be returned from this clone-remote copy: read the clone's HEAD: exit status 128; the copy is kept at /m/RUN/x"}, tt.term)
	if out := tt.out.String(); !strings.Contains(out, "will not be returned") || !strings.Contains(out, "the copy is kept at /m/RUN/x") {
		t.Fatalf("the terminal did not say it: %q", out)
	}
}

// TestGuestForwardsHaveOneOwner is ruling P-121 (audit finding 6): the
// container init's guest command (ociInitTakeGuest) and runSandboxGuest
// read the SAME forward table through the same function; a stand-in table
// is read once by each path.
func TestGuestForwardsHaveOneOwner(t *testing.T) {
	orig := guestForwardRows
	t.Cleanup(func() { guestForwardRows = orig })
	reads := 0
	guestForwardRows = func(sandbox.GuestArgs) []guestForwardRow {
		reads++
		return []guestForwardRow{{name: "stand-in", port: 1, sock: "/nonexistent/observer-test.sock", missingOK: true, env: []string{"OBSERVER_TEST_ROW=1"}}}
	}
	args := []string{"--", "/bin/true"}
	if _, err := sandbox.ParseGuestArgs(args); err != nil {
		t.Skipf("guest args shape: %v", err)
	}
	run, _, err := ociInitTakeGuest(context.Background(), append([]string{"/usr/bin/observer", sandbox.GuestVerb}, args...), os.Environ())
	if err != nil || len(run) == 0 || run[0] != "/bin/true" {
		t.Fatalf("init path: %v %v", run, err)
	}
	if code := runSandboxGuest(args); code != 0 {
		t.Fatalf("guest path exit %d", code)
	}
	if reads != 2 {
		t.Fatalf("the forward table was read %d times; both paths must read it", reads)
	}
}
