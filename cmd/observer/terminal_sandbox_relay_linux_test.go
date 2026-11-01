//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestBwrapRelayLive is the live proof of the capture relay on bwrap (lane
// sbx-p2, roadmap section 11 item 4), through the real launch path:
// sandboxRuntime.Prepare writes the run record, the host helper (this test
// binary) serves the box's relay socket, the daemon's handler runs on the
// real link endpoint with the production executor and a real observer
// binary. From INSIDE the box:
//   - a guard deny round-trips: a dangerous PreToolUse is answered with the
//     host's deny;
//   - a run's own channel is the only voice: nothing in the box can reach the
//     daemon's link endpoint (it lives under the observer dir, a tmpfs here);
//
// and with the daemon's endpoint closed:
//   - a gate event blocks, whatever the guard mode;
//   - a capture-only event is spooled and the hook exits 0.
func TestBwrapRelayLive(t *testing.T) {
	bwrapUsableForTest(t)
	bin := probeHookTestBinary(t)
	proxyPort, _ := pongListener(t)
	cfg := config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "none", ExtraROBinds: []string{filepath.Dir(bin)}}
	wrap, home, ws, obs := prepLiveWrapArgvCfg(t, cfg, proxyPort, nil)

	daemonCfg := writeRelayConfig(t, obs, "[guard]\nenabled = true\nmode = \"enforce\"\n")
	writePosture(t, daemonCfg, enforcedPosture)
	ep, err := sandboxRelayEndpoint(obs)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &sandboxrelayd.Daemon{ObserverDir: obs, Exec: relayExecutor(daemonCfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
	go func() { _ = d.Serve(ctx, ln) }()

	// A served tool gate (codex's PreToolUse) with the destructive fixture
	// the tool-gate end-to-end test uses.
	deny := toolGateE2EFixture("codex", "PreToolUse", "", ws)
	script := fmt.Sprintf(`
printf '%%s' %[1]q | %[2]q hook codex PreToolUse; echo "EXIT=$?"
[ -S %[3]q ] && echo "LINK VISIBLE" || echo "LINK HIDDEN"
`, deny, bin, ep)
	out, err := runSandboxed(t, wrap, home, script)
	if err != nil {
		t.Fatalf("sandboxed run failed: %v\n%s", err, out)
	}
	if !toolGateBlockWords.MatchString(out) {
		t.Fatalf("the relayed PreToolUse was not denied:\n%s", out)
	}
	if !strings.Contains(out, "LINK HIDDEN") {
		t.Fatalf("the daemon's link endpoint is visible in the box:\n%s", out)
	}
	if st, ok := d.Run(wrapRunID(t, wrap)); !ok || st.Served.Load() == 0 {
		t.Fatalf("the daemon handler served nothing for the run")
	}

	// The relay down: the daemon endpoint closes.
	cancel()
	_ = ln.Close()
	_ = os.Remove(ep)
	wrap2, home2, ws2, _ := prepLiveWrapArgvCfg(t, cfg, proxyPort, nil)
	gate := fmt.Sprintf(`{"session_id":"live-2","hook_event_name":"PreToolUse","cwd":%q,"tool_name":"Read","tool_input":{"file_path":"x"}}`, ws2)
	post := fmt.Sprintf(`{"session_id":"live-2","hook_event_name":"PostToolUse","cwd":%q,"tool_name":"Read","tool_input":{"file_path":"x"}}`, ws2)
	script = fmt.Sprintf(`
printf '%%s' %[1]q | %[3]q hook codex PreToolUse; echo "GATEEXIT=$?"
printf '%%s' %[2]q | %[3]q hook codex PostToolUse; echo "POSTEXIT=$?"
ls /tmp/.observer-relay-spool | wc -l | sed 's/^/SPOOLED=/'
`, gate, post, bin)
	out, err = runSandboxed(t, wrap2, home2, script)
	if err != nil {
		t.Fatalf("sandboxed run failed: %v\n%s", err, out)
	}
	if !toolGateBlockWords.MatchString(out) || !strings.Contains(out, "relay could not be reached") {
		t.Fatalf("a gate event with the relay down did not block:\n%s", out)
	}
	if !strings.Contains(out, "POSTEXIT=0") || !strings.Contains(out, "SPOOLED=1") {
		t.Fatalf("a capture-only event with the relay down was not spooled:\n%s", out)
	}
}

// wrapRunID returns the run id the host helper argv names.
func wrapRunID(t *testing.T, wrap []string) string {
	t.Helper()
	for i, a := range wrap {
		if a == "--relay-run" && i+1 < len(wrap) {
			return wrap[i+1]
		}
	}
	t.Fatalf("no --relay-run in %v", wrap)
	return ""
}
