package dockersbx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func spec(run string, tier vocab.Tier) sandboxremote.BoxSpec {
	return sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 600, Tier: tier, Labels: map[string]string{"extra": "x"}}
}

// TestNewRefusesHostsOffTheVendor: the API endpoint and the exchange URL
// must be https under docker.com (loopback http is the test server only),
// and both login values are required; New makes no call.
func TestNewRefusesHostsOffTheVendor(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    Options
	}{
		{"endpoint elsewhere", Options{Endpoint: "https://connect.example.com/sandboxes", DockerID: "u", Access: "a-1234"}},
		{"http endpoint", Options{Endpoint: "http://connect.docker.com/sandboxes", DockerID: "u", Access: "a-1234"}},
		{"exchange elsewhere", Options{Endpoint: "https://connect.docker.com/sandboxes", ExchangeURL: "https://hub.example.com/v2/auth/token", DockerID: "u", Access: "a-1234"}},
		{"no id", Options{Endpoint: "https://connect.docker.com/sandboxes", Access: "a-1234"}},
		{"no access", Options{Endpoint: "https://connect.docker.com/sandboxes", DockerID: "u"}},
	} {
		if _, err := New(tc.o); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if _, err := New(Options{Endpoint: "https://connect.docker.com/sandboxes", DockerID: "u", Access: "a-1234"}); err != nil {
		t.Fatalf("the documented endpoint refused: %v", err)
	}
}

// TestCreateBodyPerTier: the exchange sends the Docker ID and the access
// token to the exchange URL only; the create carries the image, the small
// size, the run label, the keep-alive start command, the delete timeout and
// an inline denyAll below the internet tier, under an Idempotency-Key from
// the run; the management token, not the access token, authorizes it.
func TestCreateBodyPerTier(t *testing.T) {
	for _, tc := range []struct {
		tier   vocab.Tier
		policy bool
	}{{vocab.TierNone, true}, {vocab.TierProxyOnly, true}, {vocab.TierInternet, false}} {
		f := newFake(t)
		c := f.client(t)
		info, err := c.Create(context.Background(), spec("run-1", tc.tier))
		if err != nil {
			t.Fatalf("%s: %v", tc.tier, err)
		}
		if !info.Running || info.ID != "sbx1" || info.Labels[sandboxremote.LabelKey] != "run-1" || info.Region != sandboxremote.ProviderChosen {
			t.Fatalf("%s: info %+v", tc.tier, info)
		}
		if f.lastExchange.Identifier != "dev-user" || f.exchanges != 1 {
			t.Fatalf("%s: exchange %+v x%d", tc.tier, f.lastExchange.Identifier, f.exchanges)
		}
		b := f.creates[0]
		if b.ImageRef != DefaultImage || b.Resources.CPUs != 2 || b.Resources.MemoryMiB != 4096 || b.DisplayName != "observer-run-1" ||
			b.Labels["extra"] != "x" || strings.Join(b.StartupExecution.RawImage.Start.Argv, " ") != "sleep infinity" ||
			b.Features.Timeouts.Timeout != "600s" || b.Features.Timeouts.OnTimeout != "delete" {
			t.Fatalf("%s: body %+v", tc.tier, b)
		}
		if got := len(b.NetworkPolicies) == 1 && b.NetworkPolicies[0].Mode == "denyAll" && strings.Join(b.NetworkPolicies[0].DenyNetworks, " ") == "** 0.0.0.0/0 ::/0"; got != tc.policy {
			t.Fatalf("%s: network policies %+v", tc.tier, b.NetworkPolicies)
		}
		if f.createKeys[0] != "observer-create-observer-run-1" {
			t.Fatalf("%s: idempotency key %q", tc.tier, f.createKeys[0])
		}
	}
}

// TestCreateWaitsUntilRunning: a 202 (creating) is read until it runs; one
// that fails is deleted, and with a template reads template-unavailable.
func TestCreateWaitsUntilRunning(t *testing.T) {
	f := newFake(t)
	f.createStatus, f.pollsToRun = "creating", 3
	c := f.client(t)
	info, err := c.Create(context.Background(), spec("run-2", vocab.TierNone))
	if err != nil || !info.Running {
		t.Fatalf("create %+v %v", info, err)
	}
	if b := f.boxes["sbx1"]; b == nil || b.polls != 3 {
		t.Fatalf("polls %+v", b)
	}

	f2 := newFake(t)
	f2.createStatus, f2.pollsToRun, f2.failNewBoxes = "creating", 1, true
	c2 := f2.client(t)
	sp := spec("run-3", vocab.TierNone)
	sp.Template = "ghcr.io/acme/agent:1"
	_, err = c2.Create(context.Background(), sp)
	if !errors.Is(err, sandboxremote.ErrTemplateUnavailable) {
		t.Fatalf("failed box: %v", err)
	}
	if len(f2.boxes) != 0 || len(f2.deletes) != 1 {
		t.Fatalf("the failed box was not deleted: %v %v", f2.boxes, f2.deletes)
	}

	// A create the service refuses for its image reference made no box.
	f3 := newFake(t)
	sp.Template = "missing/image:1"
	if _, err := f3.client(t).Create(context.Background(), sp); !errors.Is(err, sandboxremote.ErrTemplateUnavailable) {
		t.Fatalf("refused image: %v", err)
	}
}

// TestCreateLostIsRecoveredByItsKey: an answer cut after the box was
// admitted is recovered by repeating the request under the same key (one
// box, not two); past the retries it is create_unknown and the label finds
// the box.
func TestCreateLostIsRecoveredByItsKey(t *testing.T) {
	f := newFake(t)
	f.cutCreates = 1
	c := f.client(t)
	info, err := c.Create(context.Background(), spec("run-4", vocab.TierNone))
	if err != nil || info.ID != "sbx1" || len(f.boxes) != 1 || len(f.creates) != 2 || f.createKeys[0] != f.createKeys[1] {
		t.Fatalf("recovered %+v %v boxes %d creates %d", info, err, len(f.boxes), len(f.creates))
	}

	f2 := newFake(t)
	f2.cutCreates = 10
	c2 := f2.client(t)
	_, err = c2.Create(context.Background(), spec("run-5", vocab.TierNone))
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("lost create: %v", err)
	}
	boxes, err := c2.ListByLabel(context.Background(), sandboxremote.LabelKey, "run-5")
	if err != nil || len(boxes) != 1 {
		t.Fatalf("label list %+v %v", boxes, err)
	}
}

// TestRateLimitAndReexchange: a 429 with a RetryInfo delay is retried after
// it; one past MaxRetryWait fails as rate limited; an expired management
// token (401) is exchanged again once.
func TestRateLimitAndReexchange(t *testing.T) {
	f := newFake(t)
	f.retry429 = 1
	var waits []time.Duration
	c := f.client(t, func(o *Options) {
		o.Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	})
	if _, err := c.Create(context.Background(), spec("run-6", vocab.TierNone)); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 1 || waits[0] != 1500*time.Millisecond {
		t.Fatalf("waits %v", waits)
	}

	f2 := newFake(t)
	f2.retry429, f2.retryDelay = 1, "60s"
	if _, err := f2.client(t).Create(context.Background(), spec("run-7", vocab.TierNone)); !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("past the cap: %v", err)
	}

	f3 := newFake(t)
	c3 := f3.client(t)
	if _, err := c3.Create(context.Background(), spec("run-8", vocab.TierNone)); err != nil {
		t.Fatal(err)
	}
	f3.mu.Lock()
	f3.reject401 = 1
	f3.mu.Unlock()
	if _, err := c3.Get(context.Background(), "sbx1"); err != nil {
		t.Fatalf("get after expiry: %v", err)
	}
	if f3.exchanges != 2 {
		t.Fatalf("exchanges %d", f3.exchanges)
	}
}

// TestGetListDelete: the list reads every page and matches the label in
// the client; the delete sends the etag as If-Match with force, reads it
// again after a 412, and a deleted box reads not found.
func TestGetListDelete(t *testing.T) {
	f := newFake(t)
	f.listPage = 1
	c := f.client(t)
	ctx := context.Background()
	for _, r := range []string{"a", "b", "c"} {
		if _, err := c.Create(ctx, spec(r, vocab.TierNone)); err != nil {
			t.Fatal(err)
		}
	}
	boxes, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "c")
	if err != nil || len(boxes) != 1 || boxes[0].ID != "sbx3" {
		t.Fatalf("list %+v %v", boxes, err)
	}
	f.staleEtag = 1
	if err := c.Delete(ctx, "sbx2"); err != nil {
		t.Fatal(err)
	}
	if len(f.deletes) != 2 || f.deletes[0] != `"v1"` || f.deletes[1] != `"v2"` {
		t.Fatalf("If-Match %v", f.deletes)
	}
	if _, err := c.Get(ctx, "sbx2"); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	if err := c.Delete(ctx, "sbx2"); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("delete absent: %v", err)
	}
}

func newBox(t *testing.T, f *fake, c *Client) string {
	t.Helper()
	info, err := c.Create(context.Background(), spec("run-x", vocab.TierInternet))
	if err != nil {
		t.Fatal(err)
	}
	return info.ID
}

// TestExecOutputExitAndStderrSink: a pipe process's stdout is read to EOF,
// its stderr reaches the sink (and never the output), its stdin is closed
// at once, and Wait returns the exit code; a box base environment, HOME,
// the cwd and root reach the process.
func TestExecOutputExitAndStderrSink(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()
	sp := spec("run-env", vocab.TierNone)
	sp.Env = map[string]string{"BASE": "b1"}
	info, err := c.Create(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"fail"}, Stderr: &errBuf})
	if err != nil || p == nil {
		t.Fatalf("exec %v %v", p, err)
	}
	out, _ := io.ReadAll(p)
	code, err := p.Wait(ctx)
	if string(out) != "out\n" || errBuf.String() != "oops\n" || code != 3 || err != nil {
		t.Fatalf("out %q err %q code %d %v", out, errBuf.String(), code, err)
	}
	// cat ends only when its stdin closes: a non-stdin process gets it
	// closed at once.
	cp, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}})
	if err != nil {
		t.Fatal(err)
	}
	if code, err := cp.Wait(ctx); code != 0 || err != nil {
		t.Fatalf("a non-stdin process kept its stdin open: %d %v", code, err)
	}
	p, err = c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"env"}, Env: map[string]string{"HOME": "/root"}, Cwd: "/w", AsRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	out, _ = io.ReadAll(p)
	if string(out) != "/root|b1|root|/w" {
		t.Fatalf("env %q", out)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{}); err == nil {
		t.Fatal("an empty argv was accepted")
	}
}

// TestExecStdinPTYResizeKill: a streaming stdin is echoed by cat and a
// closed stdin ends it; a PTY process gets its resize frame and a kill ends
// it; a pipe process refuses a resize.
func TestExecStdinPTYResizeKill(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()
	box := newBox(t, f, c)
	p, err := c.Exec(ctx, box, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(p, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("echo %q %v", buf, err)
	}
	if err := p.Resize(ctx, 10, 10); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Fatalf("pipe resize %v", err)
	}
	_ = p.Close()

	t2, err := c.Exec(ctx, box, sandboxremote.ExecSpec{Argv: []string{"sh"}, PTY: true, Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	if err := t2.Resize(ctx, 40, 120); err != nil {
		t.Fatal(err)
	}
	if _, err := t2.Write([]byte("ls")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 4)
	if _, err := io.ReadFull(t2, buf); err != nil || string(buf) != "> ls" {
		t.Fatalf("pty %q %v", buf, err)
	}
	if err := t2.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	if code, err := t2.Wait(ctx); code != 137 || err != nil {
		t.Fatalf("killed %d %v", code, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	pr := f.procs[strings.TrimPrefix(t2.PID(), "processes/")]
	if pr.body.PTY == nil || pr.body.PTY.InitialSize == nil || pr.body.PTY.InitialSize.Rows != 24 || len(pr.sizes) != 1 || pr.sizes[0].Cols != 120 {
		t.Fatalf("pty body %+v sizes %v", pr.body.PTY, pr.sizes)
	}
	if len(f.signals) != 1 || f.signals[0] != "kill" {
		t.Fatalf("signals %v", f.signals)
	}
}

// TestStreamCutResumesFromLastSequence: a stream cut with 1008 after an
// expired endpoint grant is re-attached with a fresh grant from the last
// sequence received; no output repeats or is lost.
func TestStreamCutResumesFromLastSequence(t *testing.T) {
	f := newFake(t)
	f.dropAfter = 2
	c := f.client(t)
	box := newBox(t, f, c)
	ctx := context.Background()
	p, err := c.Exec(ctx, box, sandboxremote.ExecSpec{Argv: []string{"multi"}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(p)
	code, err := p.Wait(ctx)
	if string(out) != "abcd" || code != 0 || err != nil {
		t.Fatalf("out %q code %d %v", out, code, err)
	}
	if len(f.attaches) != 2 || f.attaches[0] != 0 || f.attaches[1] != 2 {
		t.Fatalf("attaches %v", f.attaches)
	}
	if f.grants < 2 {
		t.Fatalf("no fresh grant after the cut (%d)", f.grants)
	}
}

// TestReattachByPID: Reattach re-opens a running process's stream by its
// name from the last sequence this client saw; a non-process id is refused.
func TestReattachByPID(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	box := newBox(t, f, c)
	ctx := context.Background()
	p, err := c.Exec(ctx, box, sandboxremote.ExecSpec{Argv: []string{"sh"}, PTY: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(p, buf); err != nil {
		t.Fatal(err)
	}
	pid := p.PID()
	_ = p.Close()
	np, err := c.Reattach(ctx, box, pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := np.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 5)
	if _, err := io.ReadFull(np, buf); err != nil || string(buf) != "> two" {
		t.Fatalf("reattached %q %v", buf, err)
	}
	if last := f.attaches[len(f.attaches)-1]; last != 1 {
		t.Fatalf("resumed from %d", last)
	}
	_ = np.Close()
	if _, err := c.Reattach(ctx, box, "p1"); err == nil {
		t.Fatal("a bare id was accepted")
	}
}

// TestWriteAndReadFiles: the directories are made with parents, the files
// stream with their modes, a read stops at max, and a missing file is not
// found.
func TestWriteAndReadFiles(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	box := newBox(t, f, c)
	ctx := context.Background()
	files := []sandboxremote.UploadFile{
		{Path: "/root/w/a.txt", Mode: 0o644, Size: 5, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("hello")), nil }},
		{Path: "/root/w/bin/run", Mode: 0o755, Size: 2, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("#!")), nil }},
		{Path: "/root/w/empty", Size: 0, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }},
	}
	if err := c.WriteFiles(ctx, box, files); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.mkdirs, ",") != "/root/w,/root/w/bin" {
		t.Fatalf("mkdirs %v", f.mkdirs)
	}
	if g := f.files["/root/w/bin/run"]; string(g.data) != "#!" || g.mode != 0o755 {
		t.Fatalf("file %+v", g)
	}
	if g := f.files["/root/w/empty"]; g.mode != 0o644 {
		t.Fatalf("empty file mode %o", g.mode)
	}
	b, err := c.ReadFile(ctx, box, "/root/w/a.txt", 0)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q %v", b, err)
	}
	if _, err := c.ReadFile(ctx, box, "/root/w/a.txt", 3); err == nil {
		t.Fatal("a read past max was accepted")
	}
	if _, err := c.ReadFile(ctx, box, "/nope", 0); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("missing %v", err)
	}
	grew := []sandboxremote.UploadFile{{Path: "/root/w/g", Size: 1, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("grown")), nil }}}
	if err := c.WriteFiles(ctx, box, grew); err == nil {
		t.Fatal("a file that grew was uploaded")
	}
	if err := c.WriteFiles(ctx, box, []sandboxremote.UploadFile{{Path: "rel/x"}}); err == nil {
		t.Fatal("a relative path was accepted")
	}
}

// TestEndpointGrantRefreshAndHostRefusal: an expired endpoint grant (401)
// is minted again once; a box endpoint off docker.com is refused before
// any grant is asked for.
func TestEndpointGrantRefreshAndHostRefusal(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	box := newBox(t, f, c)
	ctx := context.Background()
	if err := c.WriteFiles(ctx, box, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, box, sandboxremote.ExecSpec{Argv: []string{"echo", "x"}}); err != nil {
		t.Fatal(err)
	}
	before := f.grants
	f.expireScopes()
	f.mu.Lock()
	f.files["/f"] = fakeFile{data: []byte("z")}
	f.mu.Unlock()
	if _, err := c.ReadFile(ctx, box, "/f", 0); err != nil {
		t.Fatalf("read after expiry: %v", err)
	}
	if f.grants != before+1 {
		t.Fatalf("grants %d -> %d", before, f.grants)
	}

	f2 := newFake(t)
	f2.boxBase = "https://sandboxes.example.com"
	c2 := f2.client(t)
	box2 := newBox(t, f2, c2)
	_, err := c2.Exec(ctx, box2, sandboxremote.ExecSpec{Argv: []string{"echo"}})
	if !errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch) || f2.grants != 0 {
		t.Fatalf("off-domain endpoint: %v (grants %d)", err, f2.grants)
	}
}

// TestNoCredentialInErrors: a refused exchange and a refused call never
// carry the access token or an issued value in their error text.
func TestNoCredentialInErrors(t *testing.T) {
	f := newFake(t)
	c := f.client(t, func(o *Options) { o.Access = "dckr-wrong-access-9999" })
	_, err := c.Create(context.Background(), spec("run-9", vocab.TierNone))
	if err == nil || strings.Contains(err.Error(), "dckr-wrong-access-9999") {
		t.Fatalf("exchange error %v", err)
	}
	f2 := newFake(t)
	c2 := f2.client(t)
	box := newBox(t, f2, c2)
	_, err = c2.ReadFile(context.Background(), box, "/missing", 0)
	for _, v := range []string{"dckr-fake-access-1234", "mgmt-1", "scope-"} {
		if err == nil || strings.Contains(err.Error(), v) {
			t.Fatalf("error %v carries %q", err, v)
		}
	}
}

// TestBoxNameIsBounded: the display name keeps only allowed characters and
// fits 64.
func TestBoxNameIsBounded(t *testing.T) {
	if n := BoxName("a/b c." + strings.Repeat("x", 100)); len(n) != 64 || strings.ContainsAny(n, "/ .") {
		t.Fatalf("%q", n)
	}
}

// TestInfoCarriesFailure: a box's failure body reaches BoxInfo.Extra
// (redacted), with its status and deadline, so a caller can say why a box
// died before it deletes it.
func TestInfoCarriesFailure(t *testing.T) {
	c := newFake(t).client(t)
	var s sandboxJSON
	s.UID = "sbx9"
	s.Core.Status = "failed"
	s.EffectiveFeatures.Timeouts.ExpiresAt = "2026-11-12T01:24:52Z"
	s.Failure = &errorBody{Code: "internal", Message: "upstream unavailable"}
	info := c.info(s)
	if info.Extra["status"] != "failed" || info.Extra["failure"] != "internal upstream unavailable" || info.Running || info.Deadline.IsZero() {
		t.Errorf("info = %+v", info)
	}
	s.Failure = nil
	if _, ok := c.info(s).Extra["failure"]; ok {
		t.Error("a box with no failure body has a failure entry")
	}
}
