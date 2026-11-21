//go:build linux

// Linux only, like every other test of this package that serves the relay
// over unix sockets: it uses shortDir (relayd_test.go, linux) and the
// daemon's same-user peer check on a unix socket (Windows checks
// named-pipe clients instead, so it would refuse these connections; macOS
// has the check but no Mac runs it yet, register item MAC-5). Without the
// tag the package's tests did not build on Windows or macOS (F-023).

package sandboxrelayd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// egressRelay is a daemon and a helper forwarder for one run, with the
// daemon's refusal hook recording what it receives.
type egressRelay struct {
	obs, sock, link string
	rec             RunRecord
	mu              sync.Mutex
	got             []sandboxrelay.EgressRefusalReport
	runs            []string
	execs           int
	d               *Daemon
}

func startEgressRelay(t *testing.T) *egressRelay {
	t.Helper()
	e := &egressRelay{obs: shortDir(t), sock: shortDir(t)}
	_ = os.Chmod(e.sock, 0o700)
	rec, err := NewRunRecord(RunRecord{RunID: "run-e", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}, TerminalRunID: "term-e"})
	if err != nil {
		t.Fatal(err)
	}
	e.rec = rec
	if err := WriteRun(e.obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := WriteBoxRecord(e.sock, rec); err != nil {
		t.Fatal(err)
	}
	e.link = filepath.Join(e.obs, "link.sock")
	dln, err := net.Listen("unix", e.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{
		ObserverDir: e.obs, Rules: testRules, Peer: PeerSameUser,
		Exec: func(context.Context, RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			e.mu.Lock()
			e.execs++
			e.mu.Unlock()
			return sandboxrelay.HookResponse{}, nil
		},
		OnEgressRefusal: func(run RunRecord, rep sandboxrelay.EgressRefusalReport) {
			e.mu.Lock()
			e.got = append(e.got, rep)
			e.runs = append(e.runs, run.RunID+"/"+run.TerminalRunID)
			e.mu.Unlock()
		},
	}
	e.d = d
	go func() { _ = d.Serve(ctx, dln) }()
	bln, err := net.Listen("unix", filepath.Join(e.sock, RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	fw := &Forwarder{Run: rec, Rules: testRules, Peer: PeerSameUser, DialDaemon: e.dial}
	go func() { _ = fw.Serve(ctx, bln) }()
	return e
}

func (e *egressRelay) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", e.link)
}

func (e *egressRelay) received() ([]sandboxrelay.EgressRefusalReport, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]sandboxrelay.EgressRefusalReport(nil), e.got...), append([]string(nil), e.runs...)
}

// TestEgressRefusalReachesTheDaemon: the helper's report crosses the link
// and reaches OnEgressRefusal with the run the channel names.
func TestEgressRefusalReachesTheDaemon(t *testing.T) {
	e := startEgressRelay(t)
	rep := sandboxrelay.EgressRefusalReport{Host: "evil.example", Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts", AtMS: 1793400000000}
	if err := SendEgressRefusal(context.Background(), e.dial, e.rec, rep, sandboxrelay.ConnLimits{}); err != nil {
		t.Fatal(err)
	}
	got, runs := e.received()
	rep.V = sandboxrelay.EgressRefusalVersion
	if len(got) != 1 || got[0] != rep || runs[0] != "run-e/term-e" {
		t.Fatalf("received %+v runs %v", got, runs)
	}
}

// TestEgressRefusalFromABoxIsRefused: a box cannot send a refusal report
// (its channel accepts BoxKind only), so it cannot write refusal rows.
func TestEgressRefusalFromABoxIsRefused(t *testing.T) {
	e := startEgressRelay(t)
	br, ok, err := ReadBoxRecord(filepath.Join(e.sock, BoxRecordName))
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	body, _ := sandboxrelay.EncodeEgressRefusalReport(sandboxrelay.EgressRefusalReport{Host: "h.example", Rule: "ssrf-floor"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := BoxRoundTrip(ctx, e.sock, br, sandboxrelay.HookRequest{Kind: sandboxrelay.KindEgressRefusal, Args: []string{"claude-code"}, Stdin: body}, sandboxrelay.DefaultConnLimits)
	if err == nil && resp.Hop == "" {
		t.Fatalf("a box's refusal report was answered: %+v", resp)
	}
	if got, _ := e.received(); len(got) != 0 {
		t.Fatalf("a box's report reached the daemon: %+v", got)
	}
}

// TestEgressRefusalMalformedReportIsRefused: a report that fails the
// payload schema never reaches OnEgressRefusal.
func TestEgressRefusalMalformedReportIsRefused(t *testing.T) {
	e := startEgressRelay(t)
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindEgressRefusal, Args: []string{"claude-code"}, Stdin: []byte(`{"v":1,"host":"a b","rule":"x","at_ms":0}`)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := LinkRoundTrip(ctx, e.dial, e.rec, msg, sandboxrelay.DefaultConnLimits); err == nil {
		t.Fatal("a malformed report was answered")
	}
	if got, _ := e.received(); len(got) != 0 {
		t.Fatalf("a malformed report reached the daemon: %+v", got)
	}
}

// TestEgressRefusalTakesNoHookSlot (audit N1-A1): with every hook slot of
// the run held, a refusal report is still answered, and the run's capture
// is not lowered.
func TestEgressRefusalTakesNoHookSlot(t *testing.T) {
	e := startEgressRelay(t)
	st := e.d.state(e.rec)
	for range cap(st.sem) {
		st.sem <- struct{}{}
	}
	defer func() {
		for range cap(st.sem) {
			<-st.sem
		}
	}()
	rep := sandboxrelay.EgressRefusalReport{Host: "evil.example", Port: 443, Rule: "allow-list-miss", AtMS: 1793400000000}
	if err := SendEgressRefusal(context.Background(), e.dial, e.rec, rep, sandboxrelay.ConnLimits{}); err != nil {
		t.Fatalf("a refusal report with every hook slot held: %v", err)
	}
	if got, _ := e.received(); len(got) != 1 {
		t.Fatalf("received %+v", got)
	}
	e.d.FlushHealth()
	if h := st.Health(); h.Degraded() {
		t.Fatalf("a refusal report lowered the run: %+v", h)
	}
}

// TestEgressRefusalBusyLowersNothing (audit N1-A1): a refusal report that
// finds the refusal budget taken fails without lowering the run, and a hook
// request sent while it is in flight still gets its hook slot.
func TestEgressRefusalBusyLowersNothing(t *testing.T) {
	e := startEgressRelay(t)
	st := e.d.state(e.rec)
	st.refusalSem <- struct{}{}
	rep := sandboxrelay.EgressRefusalReport{Host: "evil.example", Port: 443, Rule: "allow-list-miss", AtMS: 1793400000000}
	if err := SendEgressRefusal(context.Background(), e.dial, e.rec, rep, sandboxrelay.ConnLimits{}); err == nil {
		t.Fatal("a report past the refusal budget was answered")
	}
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}, Stdin: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := LinkRoundTrip(ctx, e.dial, e.rec, msg, sandboxrelay.DefaultConnLimits); err != nil {
		t.Fatalf("a hook request beside a refusal report in flight: %v", err)
	}
	<-st.refusalSem
	e.mu.Lock()
	execs := e.execs
	e.mu.Unlock()
	if execs != 1 {
		t.Fatalf("the hook request ran %d times", execs)
	}
	e.d.FlushHealth()
	if h := st.Health(); h.Degraded() {
		t.Fatalf("a refused refusal report lowered the run: %+v", h)
	}
}
