//go:build !windows && !sbo_omit_org_update

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
)

// update_launchd_unix_test.go: the launchd hand-over's handshake half with a
// real child process (a shell script, so Unix only; the hand-over only ever
// ends with a supervisor restart under launchd).

// TestLaunchdHandshakeEndsByStoppingTheChild: under the agent, a passed
// self-check returns a hand-over that ends with the supervisor's restart,
// and its stop reaches the child, which drains and exits.
func TestLaunchdHandshakeEndsByStoppingTheChild(t *testing.T) {
	dir := t.TempDir()
	mark := filepath.Join(dir, "stopped")
	t.Setenv("STOP_MARK", mark)
	isolateSupervisionEnv(t)
	t.Setenv("XPC_SERVICE_NAME", service.LaunchdLabel)
	withLaunchAgentPlist(t, restartsPlist)
	bin := writeFakeBinary(t, dir, "child-ready", `trap 'echo stopped > "$STOP_MARK"; exit 0' TERM
echo "ready $OBSERVER_UPDATE_HANDSHAKE" >&3
while :; do sleep 0.1; done`)
	res, err := superviseNewBinary(context.Background(), bin, nil, dir, 5*time.Second, nil)
	if err != nil || !res.Ready || !res.RestartBySupervisor || res.stopChild == nil {
		t.Fatalf("superviseNewBinary under launchd: %+v, %v", res, err)
	}
	if err := res.stopChild(5 * time.Second); err != nil {
		t.Fatalf("stopping the child: %v", err)
	}
	if b, err := os.ReadFile(mark); err != nil || !strings.Contains(string(b), "stopped") {
		t.Fatalf("the child was not stopped with SIGTERM: %q %v", b, err)
	}

	// Under systemd or with no supervisor the hand-over ends clean.
	isolateSupervisionEnv(t)
	bin2 := writeFakeBinary(t, dir, "child-ready2", `echo "ready $OBSERVER_UPDATE_HANDSHAKE" >&3
exec sleep 1`)
	res2, err := superviseNewBinary(context.Background(), bin2, nil, dir, 5*time.Second, nil)
	if err != nil || !res2.Ready || res2.RestartBySupervisor || res2.stopChild != nil {
		t.Fatalf("superviseNewBinary unsupervised: %+v, %v", res2, err)
	}
}
