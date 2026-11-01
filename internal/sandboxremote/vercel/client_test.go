package vercel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestRecordedShapes decodes the recorded answers through the client's own
// types, so a drift between the spec's shapes and the client shows here.
func TestRecordedShapes(t *testing.T) {
	c := newFakeVercel(t).client(t)
	var cr sandboxResp
	b, _ := os.ReadFile(filepath.Join("testdata", "create_200.json"))
	if err := json.Unmarshal(b, &cr); err != nil {
		t.Fatal(err)
	}
	info := c.info(cr)
	if info.ID != "observer-run-1" || info.Extra["session"] != "sbx_abc123" || !info.Running || info.Region != "iad1" || info.Labels[sandboxremote.LabelKey] != "run-1" || info.Deadline.IsZero() {
		t.Errorf("create info %+v", info)
	}
	b, _ = os.ReadFile(filepath.Join("testdata", "get_stopped_200.json"))
	var gr sandboxResp
	_ = json.Unmarshal(b, &gr)
	if c.info(gr).Running {
		t.Error("a stopped session reads running")
	}
	f, _ := os.Open(filepath.Join("testdata", "logs_200.ndjson"))
	defer f.Close()
	p := &process{c: c}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := p.take(sc.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if string(p.pending) != "hello world\n" {
		t.Errorf("stdout %q (stderr must be dropped)", p.pending)
	}
	if err := p.take([]byte(`{"stream":"error","data":{"code":"sandbox_stream_closed","message":"closed"}}`)); err == nil || !strings.Contains(err.Error(), "sandbox_stream_closed") {
		t.Errorf("error line: %v", err)
	}
}

// TestCreateBodyPerTier pins the create call: v3 with the projectId in the
// body and the teamId in the query, persistent=false (no snapshot), no
// ports, deny-all for none and proxy_only and allow-all for internet, the
// timeout in ms, the run tag, the region unless the provider chooses.
func TestCreateBodyPerTier(t *testing.T) {
	cases := []struct {
		tier   vocab.Tier
		region string
		mode   string
	}{
		{vocab.TierNone, "fra1", "deny-all"},
		{vocab.TierProxyOnly, "", "deny-all"},
		{vocab.TierInternet, sandboxremote.ProviderChosen, "allow-all"},
	}
	for i, tc := range cases {
		f := newFakeVercel(t)
		c := f.client(t)
		run := "run-" + string(rune('a'+i))
		info, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 2700, Tier: tc.tier, Region: tc.region, Template: "vercel/sandbox/node:22"})
		if err != nil {
			t.Fatal(err)
		}
		body := f.creates[0]
		np, _ := body["networkPolicy"].(map[string]any)
		if np["mode"] != tc.mode || body["persistent"] != false || body["projectId"] != f.project || body["timeout"] != float64(2700000) || body["image"] != "vercel/sandbox/node:22" {
			t.Errorf("tier %s body %v", tc.tier, body)
		}
		if _, ok := body["ports"]; ok {
			t.Error("ports were asked for")
		}
		if got, want := body["region"], tc.region; (want == "fra1") != (got == "fra1") || (want != "fra1" && got != nil) {
			t.Errorf("region %v", got)
		}
		if tags, _ := body["tags"].(map[string]any); tags[sandboxremote.LabelKey] != run {
			t.Errorf("tags %v", body["tags"])
		}
		if info.ID != BoxName(run) || info.Extra["session"] == "" {
			t.Errorf("info %+v", info)
		}
	}
}

// TestCreateConflictAndLost: a retried create (409) is accepted only for
// this run's tag; a lost answer reads ErrCreateUnknown and the label finds
// the box.
func TestCreateConflictAndLost(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	ctx := context.Background()
	spec := sandboxremote.BoxSpec{RunID: "run-1", TimeoutSeconds: 60}
	first, err := c.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Create(ctx, spec)
	if err != nil || again.ID != first.ID {
		t.Fatalf("retried create %+v %v", again, err)
	}
	f.boxes[BoxName("run-2")] = &fakeBox{name: BoxName("run-2"), sid: "sbx_x", tags: map[string]string{sandboxremote.LabelKey: "someone-else"}, running: true, files: map[string]fakeFile{}}
	if _, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "run-2", TimeoutSeconds: 60}); err == nil {
		t.Fatal("a sandbox of another run was adopted")
	}
	f.dropCreate = true
	_, err = c.Create(ctx, sandboxremote.BoxSpec{RunID: "run-3", TimeoutSeconds: 60})
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("lost create: %v", err)
	}
	list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "run-3")
	if err != nil || len(list) != 1 {
		t.Fatalf("lost box by label %+v %v", list, err)
	}
}

// TestCreate5xxIsLost (the SBX-P7 merge's audit finding 6): a 5xx left
// after the retries on create is a lost create (resolved by the label),
// never a definite failure.
func TestCreate5xxIsLost(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	f.fail500 = 100
	_, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-5", TimeoutSeconds: 60})
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) || strings.Contains(err.Error(), "FAKEtoken") {
		t.Fatalf("a create 5xx after the retries: %v", err)
	}
}

// TestRetries: a 429 or 5xx is retried within the bound; a 429 past it or
// with a Retry-After over the cap is ErrRateLimited.
func TestRetries(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	ctx := context.Background()
	f.fail429, f.retryAt = 1, "0"
	if _, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 60}); err != nil {
		t.Fatalf("one 429: %v", err)
	}
	f.fail500 = 2
	if _, err := c.Get(ctx, BoxName("r1")); err != nil {
		t.Fatalf("two 5xx: %v", err)
	}
	f.fail429 = 5
	if _, err := c.Get(ctx, BoxName("r1")); !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("persistent 429: %v", err)
	}
	f.fail429, f.retryAt = 1, "60"
	if _, err := c.Get(ctx, BoxName("r1")); !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("Retry-After past the cap: %v", err)
	}
}

func TestGetDeleteConfirmAndList(t *testing.T) {
	f := newFakeVercel(t)
	f.pageSize = 1
	c := f.client(t)
	ctx := context.Background()
	for _, r := range []string{"r1", "r2", "r3"} {
		if _, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: r, TimeoutSeconds: 60, Labels: map[string]string{"group": "g"}}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := c.ListByLabel(ctx, "group", "g")
	if err != nil || len(list) != 3 {
		t.Fatalf("paginated list %d %v", len(list), err)
	}
	if err := c.Delete(ctx, BoxName("r1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, BoxName("r1")); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := c.Delete(ctx, BoxName("r1")); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestWriteAndReadFiles(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	open := func(s string) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
	}
	files := []sandboxremote.UploadFile{
		{Path: "/home/u/p/main.go", Mode: 0o644, Size: 13, Open: open("package main\n")},
		{Path: "/vercel/sandbox/.observer-box/run/secret", Mode: 0o600, Size: 2, Open: open("s3")},
		{Path: "/vercel/sandbox/.observer-box/bin/observer", Mode: 0o755, Open: open("ELF")},
	}
	if err := c.WriteFiles(ctx, info.ID, files); err != nil {
		t.Fatal(err)
	}
	b := f.boxes[info.ID]
	if string(b.files["/home/u/p/main.go"].data) != "package main\n" || b.files["/vercel/sandbox/.observer-box/run/secret"].mode != 0o600 || b.files["/vercel/sandbox/.observer-box/bin/observer"].mode != 0o755 {
		t.Errorf("files %+v", b.files)
	}
	got, err := c.ReadFile(ctx, info.ID, "/home/u/p/main.go", 100)
	if err != nil || string(got) != "package main\n" {
		t.Fatalf("read %q %v", got, err)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/home/u/p/main.go", 4); err == nil {
		t.Error("an over-cap file was read")
	}
	if _, err := c.ReadFile(ctx, info.ID, "/none", 100); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
	for _, bad := range []string{"rel/path", "/a/../b"} {
		if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: bad, Open: open("x")}}); err == nil {
			t.Errorf("path %q was written", bad)
		}
	}
}

// TestExecStreamCoalescesStdin: the relay's exec is the documented stdin
// pipe and log stream; many small writes go in far fewer stdin POSTs (each
// one is a control-plane request), in order, and close ends the command.
func TestExecStreamCoalescesStdin(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true, Cwd: "/w", Env: map[string]string{"A": "b"}, AsRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	for i := 0; i < 200; i++ {
		line := []byte(strings.Repeat("x", i%7) + "\n")
		want.Write(line)
		if _, err := p.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(p); done <- b }()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	// Close flushed stdin, closed it and ended the reader's stream; what the
	// command received is checked on the vendor side.
	<-done
	f.mu.Lock()
	var cmd *fakeCmd
	for _, c := range f.cmds {
		cmd = c
	}
	posts := f.stdinPosts
	f.mu.Unlock()
	if string(cmd.stdin) != want.String() || !cmd.closed {
		t.Fatalf("stdin %d bytes closed=%v", len(cmd.stdin), cmd.closed)
	}
	if posts >= 200 {
		t.Errorf("%d stdin POSTs for 200 writes: not coalesced", posts)
	}
	if !cmd.sudo || cmd.cwd != "/w" || cmd.env["A"] != "b" {
		t.Errorf("command %+v", cmd)
	}
}

// TestLogStreamDropResumes: a dropped log stream is re-requested and the
// bytes already delivered are skipped, so nothing repeats or goes missing;
// a 504 on stdin carries the count taken and the rest is sent again.
func TestLogStreamDropResumes(t *testing.T) {
	f := newFakeVercel(t)
	f.dropLogsAt = 2
	f.stdin504 = 2
	c := f.client(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	pr := p.(*process)
	var want strings.Builder
	got := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 7)
		for {
			n, err := p.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				got <- b.String()
				return
			}
		}
	}()
	for i := 0; i < 5; i++ {
		s := "chunk-" + string(rune('0'+i)) + "\n"
		want.WriteString(s)
		_, _ = p.Write([]byte(s))
	}
	if err := pr.pump.close(); err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != want.String() {
		t.Fatalf("output %q, want %q", s, want.String())
	}
	if code, err := p.Wait(ctx); err != nil || code != 0 {
		t.Fatalf("wait %d %v", code, err)
	}
	_ = p.Close()
}

func TestExitCodeKillAndUnsupported(t *testing.T) {
	f := newFakeVercel(t)
	c := f.client(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", "exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(p)
	if code, err := p.Wait(ctx); string(out) != "bye\n" || code != 3 || err != nil {
		t.Fatalf("out %q code %d %v", out, code, err)
	}
	if _, err := p.Write([]byte("x")); err == nil {
		t.Error("stdin accepted on a command started without it")
	}
	k, _ := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true})
	if err := k.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	if code, _ := k.Wait(ctx); code != 143 {
		t.Errorf("killed code %d", code)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh"}, PTY: true}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("vendor PTY: %v", err)
	}
	if !errors.Is(k.Resize(ctx, 1, 1), sandboxremote.ErrNotSupported) {
		t.Error("resize claimed")
	}
	if _, err := c.Reattach(ctx, info.ID, k.PID()); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Error("reattach claimed")
	}
}

// TestTokenNeverInErrors: an answer that echoes the token comes back
// redacted.
func TestTokenNeverInErrors(t *testing.T) {
	f := newFakeVercel(t)
	c, err := New(Options{Endpoint: f.srv.URL, Token: "vercel_OTHER_token_value", TeamID: f.team, ProjectID: f.project})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background(), "observer-x")
	if err == nil || strings.Contains(err.Error(), "vercel_OTHER_token_value") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestNewAndBoxName(t *testing.T) {
	for _, o := range []Options{
		{Endpoint: "http://api.vercel.com", Token: "t", TeamID: "a", ProjectID: "b"},
		{Endpoint: "https://api.vercel.com", Token: "t", TeamID: "a"},
		{Endpoint: "https://api.vercel.com", TeamID: "a", ProjectID: "b"},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("New(%+v) accepted", o)
		}
	}
	if BoxName("run/1 ok_A-b") != "observer-run1ok_A-b" || len(BoxName(strings.Repeat("a", 300))) != 128 {
		t.Errorf("BoxName %q", BoxName("run/1 ok_A-b"))
	}
	if _, err := New(Options{Endpoint: "https://api.vercel.com", Token: "t", TeamID: "a", ProjectID: "b", HTTP: http.DefaultClient}); err != nil {
		t.Error(err)
	}
}

// TestCreateImageNotOwned (live run 2026-10-23, finding F6): an image the
// team does not own answers 404 at create; the client reports a template
// refusal (no box was made), never a lost create.
func TestCreateImageNotOwned(t *testing.T) {
	f := newFakeVercel(t)
	f.missingImage = "node22"
	c := f.client(t)
	_, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-img", TimeoutSeconds: 600, Tier: vocab.TierProxyOnly, Template: "node22"})
	if !errors.Is(err, sandboxremote.ErrTemplateUnavailable) || errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("create with an image the team does not own: %v", err)
	}
	if len(f.boxes) != 0 {
		t.Error("a box was made")
	}
}
