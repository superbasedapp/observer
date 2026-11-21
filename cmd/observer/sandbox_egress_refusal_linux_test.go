//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// refusedThroughGateway sends one CONNECT to the run's gateway socket in
// sockDir and returns the structured 403 body.
func refusedThroughGateway(t *testing.T, sockDir, target string) sandboxnet.RefusalBody {
	t.Helper()
	conn, err := net.DialTimeout("unix", filepath.Join(sockDir, sandbox.GatewaySocketName), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var b sandboxnet.RefusalBody
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Content-Type") != "application/json" || json.Unmarshal(body, &b) != nil {
		t.Fatalf("not a structured refusal: %d %s", resp.StatusCode, body)
	}
	return b
}

// waitRefusalRows waits until runID has want rows.
func waitRefusalRows(t *testing.T, st *store.Store, runID string, want int) []store.SandboxEgressRefusal {
	t.Helper()
	var rows []store.SandboxEgressRefusal
	waitForRefusal(t, func() bool {
		rows, _ = st.ListSandboxEgressRefusalsByRun(context.Background(), runID, 0, 0)
		return len(rows) == want
	})
	return rows
}

// TestLaunchHelperRefusalsLand: the Linux launch helper's gateway (bwrap,
// process_lite and oci-runc all build it through hostEgressGateway) hands a
// refusal to the daemon, which records one row per host per minute.
func TestLaunchHelperRefusalsLand(t *testing.T) {
	obs := relayShortDir(t)
	cfgPath := writeRelayConfig(t, obs, "[terminal.sandbox]\negress = \"internet\"\negress_allow_hosts = [\"registry.npmjs.org\"]\n")
	prevPath := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(&cfgPath)
	t.Cleanup(func() { daemonConfigPathSetting.Store(prevPath) })
	run := termsvc.SandboxRun{ID: "LaUnChRuNlAuNcHrUnLaUn", Tool: "claude-code", Dir: t.TempDir()}
	if err := (&sandboxRuntime{observerDir: obs}).writeRunRecord(run); err != nil {
		t.Fatal(err)
	}
	st := refusalDaemon(t, obs)
	sock := filepath.Join(relayShortDir(t), "s")
	h := sandbox.HostArgs{SockDir: sock, Gateway: true, RelayRun: run.ID, ObserverDir: obs}
	stop, err := startHostServices(h)
	defer stop()
	if err != nil {
		t.Fatal(err)
	}
	b := refusedThroughGateway(t, sock, "evil.invalid:443")
	if b.Rule != string(sandboxnet.RefusalAllowListMiss) || b.Key != sandboxnet.KeyEgressAllowHosts || b.Host != "evil.invalid" {
		t.Fatalf("body %+v", b)
	}
	// The same host again in the same minute is not a second row.
	refusedThroughGateway(t, sock, "evil.invalid:443")
	waitRefusalRows(t, st, run.ID, 1)
	time.Sleep(50 * time.Millisecond)
	rows, _ := st.ListSandboxEgressRefusalsByRun(context.Background(), run.ID, 0, 0)
	if len(rows) != 1 {
		t.Fatalf("%d rows for one host in one minute", len(rows))
	}
	if r := rows[0]; r.Host != "evil.invalid" || r.Port != 443 || r.Rule != "allow-list-miss" {
		t.Fatalf("row %+v", r)
	}
	_ = os.RemoveAll(sock)
}

// refusalDaemon serves the daemon's relay link for obs with a receiver
// writing into a real store, and returns the store.
func refusalDaemon(t *testing.T, obs string) *store.Store {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	ep, err := sandboxRelayEndpoint(obs)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser,
		Exec: func(context.Context, sandboxrelayd.RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			return sandboxrelay.HookResponse{}, nil
		},
		OnEgressRefusal: newEgressRefusalReceiver(ctx, st, nil).onEgressRefusal(),
	}
	go func() { _ = d.Serve(ctx, ln) }()
	return st
}

// TestEgressRefusalSinkReachesTheStore: the sink a helper's gateway gets
// for its run carries a refusal over the real link into the table.
func TestEgressRefusalSinkReachesTheStore(t *testing.T) {
	obs := relayShortDir(t)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "SiNkRuNsInKrUnSiNkRuN1", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}, ProjectRoot: "/p/sink"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	st := refusalDaemon(t, obs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if sandboxEgressRefusalSink(ctx, obs, "") != nil || sandboxEgressRefusalSink(ctx, obs, "NoSuChRuN") != nil {
		t.Fatal("a run with no relay record got a sink")
	}
	sink := sandboxEgressRefusalSink(ctx, obs, rec.RunID)
	if sink == nil {
		t.Fatal("no sink")
	}
	sink(sandboxnet.Refusal{Host: "evil.example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, Key: sandboxnet.KeyEgressAllowHosts, At: time.Now()})
	var rows []store.SandboxEgressRefusal
	waitForRefusal(t, func() bool {
		rows, _ = st.ListSandboxEgressRefusalsByRun(ctx, rec.RunID, 0, 0)
		return len(rows) == 1
	})
	if r := rows[0]; r.Host != "evil.example" || r.Rule != "allow-list-miss" || r.ProjectRoot != "/p/sink" || r.Port != 443 {
		t.Fatalf("row %+v", r)
	}
}
