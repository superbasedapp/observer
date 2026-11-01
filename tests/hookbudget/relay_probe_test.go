package hookbudget

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookbudget"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// The relay row's probe (sandbox plan section 5.2 "Expected cost"; roadmap
// spike JSP-2): the capture relay's own channel overhead over the host path,
// measured through the real relay code on real unix sockets: the box-side
// client, the host helper's forwarder (every box frame verified under the
// run's box key), the link to the daemon's per-run handler (every frame
// verified under the link key), and back. The executor is a stub that
// answers at once, because the hook pipeline it would run is the same
// process the host path runs: the row is the relay's cost only. Built by
// lane sbx-p2.

// relayProbe is a running relay topology for the probe.
type relayProbe struct {
	sock string
	rec  sandboxrelayd.BoxRecord
	stop func()
}

func startRelayProbe(t testing.TB) *relayProbe {
	t.Helper()
	obs, err := os.MkdirTemp("/tmp", "sbrp")
	if err != nil {
		t.Fatal(err)
	}
	sock, err := os.MkdirTemp("/tmp", "sbrs")
	if err != nil {
		t.Fatal(err)
	}
	run, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "probe", Tool: "claude-code", WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, run); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sock, run); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(obs, "link.sock")
	dln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	bln, err := net.Listen("unix", filepath.Join(sock, sandboxrelayd.RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	rules := sandboxrelay.RequestRules{EnvAllowed: func(string) bool { return false }}
	ctx, cancel := context.WithCancel(context.Background())
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: rules, Peer: sandboxrelayd.PeerSameUser, PerRun: 64, MaxConns: 256,
		Exec: func(context.Context, sandboxrelayd.RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			return sandboxrelay.HookResponse{Stdout: []byte(`{"decision":"approve"}`)}, nil
		},
	}
	go func() { _ = d.Serve(ctx, dln) }()
	fw := &sandboxrelayd.Forwarder{Run: run, Rules: rules, Peer: sandboxrelayd.PeerSameUser, MaxConns: 256, DialDaemon: func(ctx context.Context) (net.Conn, error) {
		var dl net.Dialer
		return dl.DialContext(ctx, "unix", link)
	}}
	go func() { _ = fw.Serve(ctx, bln) }()
	br, ok, err := sandboxrelayd.ReadBoxRecord(filepath.Join(sock, sandboxrelayd.BoxRecordName))
	if !ok || err != nil {
		t.Fatalf("box record: %v %v", ok, err)
	}
	return &relayProbe{sock: sock, rec: br, stop: func() {
		cancel()
		_ = os.RemoveAll(obs)
		_ = os.RemoveAll(sock)
	}}
}

// relaySamples times n relay round trips of a payload of size bytes.
func relaySamples(t testing.TB, n, size int) []time.Duration {
	t.Helper()
	if runtime.GOOS != "linux" {
		return nil // the relay ships with bwrap (Linux, WSL2)
	}
	p := startRelayProbe(t)
	defer p.stop()
	req := sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}, Stdin: bytes.Repeat([]byte("x"), size)}
	ctx := context.Background()
	once := func() time.Duration {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		start := hookbudget.Now()
		if _, err := sandboxrelayd.BoxRoundTrip(cctx, p.sock, p.rec, req, sandboxrelay.DefaultConnLimits); err != nil {
			t.Fatalf("relay round trip: %v", err)
		}
		return hookbudget.Since(start)
	}
	for range 20 {
		once() // warm the sockets and the allocator
	}
	out := make([]time.Duration, 0, n)
	for range n {
		out = append(out, once())
	}
	return out
}

// TestRelayProbe keeps the probe working in every test run (a short run,
// no timing asserted) and, with SBO_HOOK_BUDGET=1, logs the relay's cost at
// the three payload sizes JSP-2 measured against its budgets (2 ms p99 up to
// 16 KiB, 8 ms p99 at 256 KiB).
func TestRelayProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the relay ships on Linux and WSL2")
	}
	if got := len(relaySamples(t, 20, 1<<10)); got != 20 {
		t.Fatalf("%d samples", got)
	}
	if os.Getenv(envEnable) != "1" {
		return
	}
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10} {
		s := hookbudget.Summarize(relaySamples(t, 2000, size))
		t.Logf("relay round trip, %d KiB payload: p50 %s p95 %s p99 %s (n=%d)", size>>10, s.P50, s.P95, s.P99, s.N)
	}
}

// relayP99Budget is JSP-2's p99 budget for the whole relay hop at a
// payload size (sandbox plan P2 acceptance): 2 ms up to 16 KiB, 8 ms at
// 256 KiB.
func relayP99Budget(size int) time.Duration {
	if size <= 16<<10 {
		return 2 * time.Millisecond
	}
	return 8 * time.Millisecond
}

// BenchmarkRelayRoundTrip is the relay probe as a benchmark (one round
// trip per op), for profiles and for the pinned cost figures (plans
// decision log P-032, lane sbx-p2c): besides ns/op it reports the p50 and
// p99 of the round trips it timed and JSP-2's p99 budget for the size, so
// `go test -run '^$' -bench RelayRoundTrip -benchtime 2000x
// ./tests/hookbudget/` prints the figures docs/sandboxed-terminals.md
// records. A benchmark, never a test: timing on a shared machine is not a
// pass or fail.
func BenchmarkRelayRoundTrip(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("linux only")
	}
	for _, size := range []int{16 << 10, 256 << 10} {
		b.Run(byteSize(size), func(b *testing.B) {
			p := startRelayProbe(b)
			defer p.stop()
			req := sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}, Stdin: bytes.Repeat([]byte("x"), size)}
			b.SetBytes(int64(size))
			samples := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for b.Loop() {
				start := hookbudget.Now()
				if _, err := sandboxrelayd.BoxRoundTrip(context.Background(), p.sock, p.rec, req, sandboxrelay.DefaultConnLimits); err != nil {
					b.Fatal(err)
				}
				samples = append(samples, hookbudget.Since(start))
			}
			b.StopTimer()
			s := hookbudget.Summarize(samples)
			ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
			b.ReportMetric(ms(s.P50), "p50-ms")
			b.ReportMetric(ms(s.P99), "p99-ms")
			b.ReportMetric(ms(relayP99Budget(size)), "budget-p99-ms")
		})
	}
}

func byteSize(n int) string {
	if n >= 1<<10 {
		return strconv.Itoa(n>>10) + "KiB"
	}
	return strconv.Itoa(n) + "B"
}
