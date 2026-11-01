//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// leftsbxReadoptRun writes a relayed run whose daemon config sets the host
// list, and returns the helper args a re-adoption would serve it with.
func leftsbxReadoptRun(t *testing.T) sandbox.HostArgs {
	t.Helper()
	obs := relayShortDir(t)
	cfgPath := writeRelayConfig(t, obs, "[terminal.sandbox]\negress = \"internet\"\negress_allow_hosts = [\"registry.npmjs.org\"]\n")
	prevPath := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(&cfgPath)
	t.Cleanup(func() { daemonConfigPathSetting.Store(prevPath) })
	run := termsvc.SandboxRun{ID: "ReAdOpTrUnReAdOpTrUnRe", Tool: "claude-code", Dir: t.TempDir()}
	if err := (&sandboxRuntime{observerDir: obs}).writeRunRecord(run); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(relayShortDir(t), "s")
	if err := os.Mkdir(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	return sandbox.HostArgs{SockDir: sock, Gateway: true, RelayRun: run.ID, ObserverDir: obs}
}

// TestReadoptGatewayKeepsTheHostList (OSH-R-153, the re-adoption row of the
// LEFT-SBX host-list tests): a run re-adopted after a daemon restart serves
// its egress gateway with the same host list the launch helper read, so a
// host off the list is refused by the list's own rule.
func TestReadoptGatewayKeepsTheHostList(t *testing.T) {
	h := leftsbxReadoptRun(t)
	stop, err := readoptHostServices(h)
	defer stop()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("unix", filepath.Join(h.SockDir, sandbox.GatewaySocketName), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "may reach only registry.npmjs.org") {
		t.Fatalf("the re-adopted gateway lost the host list: %d %s", resp.StatusCode, body)
	}
}

// TestReadoptRefusesAnUnreadableHostList (OSH-R-153): when the list cannot
// be read, the run is not re-adopted at all (fail closed), and nothing of
// its host services is left serving in the socket dir.
func TestReadoptRefusesAnUnreadableHostList(t *testing.T) {
	h := leftsbxReadoptRun(t)
	prev := sandboxAgentEgressLoad
	sandboxAgentEgressLoad = func(string) (config.Config, error) { return config.Config{}, errors.New("unreadable") }
	t.Cleanup(func() { sandboxAgentEgressLoad = prev })
	stop, err := readoptHostServices(h)
	stop()
	if err == nil {
		t.Fatal("a run whose host list cannot be read was re-adopted")
	}
	for _, name := range []string{sandbox.GatewaySocketName, sandboxrelayd.RelaySocketName} {
		if _, serr := os.Lstat(filepath.Join(h.SockDir, name)); serr == nil {
			t.Fatalf("%s is served after the refusal", name)
		}
	}
}
