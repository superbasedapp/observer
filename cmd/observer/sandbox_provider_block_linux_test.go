//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestBwrapIntegrationProviderBlockA1 is acceptance A1's live half for
// bwrap on the internet tier (sandbox plan v2 sections 7.3 and 13.12),
// through the real launch path: a proxy-routed tool (claude-code) whose
// state is bound computes full capture only through the gateway (rule C6),
// so from inside the sandbox a CONNECT to the model provider's host and a
// literal-IP CONNECT are refused with the block's rules, while the
// forwarded model proxy stays reachable. The api_turns half (a real turn
// through the daemon's proxy) needs a running daemon and is owed to the
// release's combined check.
func TestBwrapIntegrationProviderBlockA1(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH (needed for /dev/tcp)")
	}
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create a network namespace here (%v)", err)
	}
	proxyPort, proxyHits := pongListener(t)
	wrap, home, _, _ := prepLiveWrapArgvTier(t, "internet", proxyPort, nil)
	if !strings.Contains(strings.Join(wrap, " "), "--provider-block") {
		t.Fatalf("the launch of a proxy-routed tool on the internet tier did not turn the block on: %v", wrap)
	}
	gw := strconv.Itoa(sandbox.GatewayPort(proxyPort))
	script := `
connect() {
  exec 5<>/dev/tcp/127.0.0.1/` + gw + ` || { echo "NOGATEWAY"; return; }
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&5
  read -r status <&5
  body=$(timeout 2 cat <&5 | tr '\r\n' '  ')
  echo "RESULT $1 $status $body"
  exec 5<&-
}
connect api.anthropic.com:443
connect 1.1.1.1:443
(exec 4<>/dev/tcp/127.0.0.1/` + strconv.Itoa(proxyPort) + `) 2>/dev/null && echo "PROXY REACHED" || echo "PROXY UNREACHABLE"
`
	out, err := runSandboxed(t, wrap, home, "read -r _ <&3; "+script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"RESULT api.anthropic.com:443 HTTP/1.1 403",
		"model-provider-host",
		"RESULT 1.1.1.1:443 HTTP/1.1 403",
		"literal-ip",
		"PROXY REACHED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in sandbox output:\n%s", want, out)
		}
	}
	if proxyHits.Load() == 0 {
		t.Error("the model proxy stand-in saw no connection")
	}
}
