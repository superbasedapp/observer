package secipc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func serve(t *testing.T, scan hookctx.QuickScanner) string {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	// A short root keeps the unix socket path under its length limit.
	dir, err := os.MkdirTemp("", "secipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, scan) }()
	return ep
}

var req = hookctx.QuickScanRequest{ProjectRoot: "/repo", DirtySeen: 7, Form: policy.GitWrite{Form: policy.GitWriteCommit, All: true, Pathspecs: []string{"a"}}}

func TestAskRoundTrip(t *testing.T) {
	t.Parallel()
	var got hookctx.QuickScanRequest
	ep := serve(t, func(_ context.Context, r hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		got = r
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean, DirtyCovered: r.DirtySeen}, nil
	})
	res, err := Ask(context.Background(), ep, req, 2*time.Second)
	if err != nil || res.Verdict != policy.QuickScanClean || res.DirtyCovered != 7 {
		t.Fatalf("Ask = %+v, %v", res, err)
	}
	if got.ProjectRoot != "/repo" || !got.Form.All || got.Form.Form != policy.GitWriteCommit || len(got.Form.Pathspecs) != 1 {
		t.Fatalf("the daemon saw %+v", got)
	}
}

func TestNilScannerAnswersUnknown(t *testing.T) {
	t.Parallel()
	ep := serve(t, nil)
	res, err := Ask(context.Background(), ep, req, time.Second)
	if err != nil || res.Verdict != policy.QuickScanUnknown {
		t.Fatalf("Ask = %+v, %v", res, err)
	}
}

func TestAnswerTable(t *testing.T) {
	t.Parallel()
	slow := func(ctx context.Context, _ hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		<-ctx.Done()
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean}, nil
	}
	panics := func(context.Context, hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) { panic("boom") }
	dirty := func(context.Context, hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean, Findings: []policy.SecurityHit{{RuleID: "S-721"}}}, nil
	}
	root := t.TempDir()
	rootJSON, _ := json.Marshal(root)
	good := `{"v":1,"project_root":` + string(rootJSON) + `,"form":"commit","budget_ms":20}`
	allowOnly := func(r string) bool { return r == root }
	cases := []struct {
		name   string
		raw    string
		scan   hookctx.QuickScanner
		want   policy.QuickScanVerdict
		reason string
	}{
		{"bad json", `{`, dirty, policy.QuickScanUnknown, "bad_request"},
		{"wrong version", `{"v":2,"project_root":"/r"}`, dirty, policy.QuickScanUnknown, "bad_request"},
		{"no project", `{"v":1}`, dirty, policy.QuickScanUnknown, "bad_request"},
		{"no scanner", good, nil, policy.QuickScanUnknown, "quick_scan_not_available"},
		{"over budget", good, slow, policy.QuickScanUnknown, "over_budget"},
		{"panic", good, panics, policy.QuickScanUnknown, "scan_failed"},
		{"relative root", `{"v":1,"project_root":"r","form":"commit"}`, dirty, policy.QuickScanUnknown, "root_not_allowed"},
		{"unknown root", strings.Replace(good, string(rootJSON[1:len(rootJSON)-1]), string(rootJSON[1:len(rootJSON)-1])+"x", 1), dirty, policy.QuickScanUnknown, "root_not_allowed"},
	}
	for _, tc := range cases {
		resp := answer(context.Background(), []byte(tc.raw), tc.scan, allowOnly)
		if policy.QuickScanVerdict(resp.Verdict) != tc.want || resp.Reason != tc.reason {
			t.Errorf("%s: %+v", tc.name, resp)
		}
	}
	// A "clean" answer carrying findings decodes as blocking, never clean.
	res := answer(context.Background(), []byte(good), dirty, allowOnly).decode()
	if res.Verdict != policy.QuickScanBlocking {
		t.Errorf("clean with findings decoded as %s", res.Verdict)
	}
	if (response{V: 9, Verdict: "clean"}).decode().Verdict != policy.QuickScanUnknown {
		t.Error("a foreign version decodes as unknown")
	}
	if (response{V: 1, Verdict: "maybe"}).decode().Verdict != policy.QuickScanUnknown {
		t.Error("an unknown verdict decodes as unknown")
	}
}

func TestAskFailsWithoutAServer(t *testing.T) {
	t.Parallel()
	if !localipc.Supported() {
		t.Skip("no IPC")
	}
	dir, _ := os.MkdirTemp("", "secipc")
	defer func() { _ = os.RemoveAll(dir) }()
	ep, err := Endpoint(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Ask(context.Background(), ep, req, 100*time.Millisecond); err == nil {
		t.Fatal("no server must be an error, which the seam reads as unknown")
	}
}

// TestWireKeepsFormDirectoryAndPushOperands (SEC-C2): the directory, the
// push operands and the opaque mark cross the wire, so the daemon's seam
// can answer unknown for a `git -C` commit instead of scanning the root.
func TestWireKeepsFormDirectoryAndPushOperands(t *testing.T) {
	in := hookctx.QuickScanRequest{ProjectRoot: "/repo", Form: policy.GitWrite{Form: policy.GitWriteCommit, Dir: "sub"}}
	got, _ := encodeRequest(in, time.Second).decode()
	if got.Form.Dir != "sub" || got.Form.Form != policy.GitWriteCommit {
		t.Fatalf("decoded %+v", got)
	}
	push := hookctx.QuickScanRequest{ProjectRoot: "/repo", Form: policy.GitWrite{Push: true, PushOperands: []string{"origin", "main"}}}
	got, _ = encodeRequest(push, time.Second).decode()
	if !got.Form.Push || len(got.Form.PushOperands) != 2 || got.Form.PushOpaque {
		t.Fatalf("decoded %+v", got)
	}
	many := make([]string, MaxPathspecs+1)
	for i := range many {
		many[i] = "main"
	}
	push.Form.PushOperands = many
	got, _ = encodeRequest(push, time.Second).decode()
	if !got.Form.PushOpaque {
		t.Fatal("a cut operand list did not mark the push opaque")
	}
}

// TestServeCapsConnections (lane SEC-GATEFIX milestone 2h): connections
// over the cap are answered busy at once, never queued behind a scan.
func TestServeCapsConnections(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no IPC")
	}
	dir, _ := os.MkdirTemp("", "secipc")
	defer func() { _ = os.RemoveAll(dir) }()
	ln, ep, err := Listen(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, started := make(chan struct{}), make(chan struct{}, 1)
	hold := func(ctx context.Context, _ hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean}, nil
	}
	go func() { _ = ServeWith(ctx, ln, hold, Options{MaxConns: 1}) }()
	root := t.TempDir()
	first := make(chan hookctx.QuickScanResult, 1)
	go func() {
		r, _ := Ask(ctx, ep, hookctx.QuickScanRequest{ProjectRoot: root, Form: policy.GitWrite{Form: policy.GitWriteCommit}}, 5*time.Second)
		first <- r
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request never reached the scanner")
	}
	start := time.Now()
	r, err := Ask(ctx, ep, hookctx.QuickScanRequest{ProjectRoot: root, Form: policy.GitWrite{Form: policy.GitWriteCommit}}, 5*time.Second)
	if err != nil || r.Verdict != policy.QuickScanUnknown || time.Since(start) > 2*time.Second {
		t.Fatalf("over the cap: %+v %v after %s", r, err, time.Since(start))
	}
	close(release)
	if r := <-first; r.Verdict != policy.QuickScanClean {
		t.Fatalf("the held request = %+v", r)
	}
}
