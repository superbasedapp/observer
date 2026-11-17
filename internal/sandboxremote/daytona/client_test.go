package daytona

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestRecordedShapes decodes the recorded answers through the client's own
// types (testdata/README.md says where each shape comes from).
func TestRecordedShapes(t *testing.T) {
	read := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var s sandboxJSON
	read("sandbox_200.json", &s)
	if s.ID != "sandbox123" || s.State != stateStarted || s.Target != "us" || s.Labels[sandboxremote.LabelKey] != "r1" || s.ToolboxProxyURL == "" || s.AutoDestroyAt == "" {
		t.Errorf("sandbox: %+v", s)
	}
	var l struct {
		Items      []sandboxJSON `json:"items"`
		NextCursor string        `json:"nextCursor"`
	}
	read("list_200.json", &l)
	if len(l.Items) != 2 || l.Items[1].State != "stopped" {
		t.Errorf("list: %+v", l)
	}
	var a sshAccess
	read("ssh_access_200.json", &a)
	host, port, err := sshTarget(a.SSHCommand)
	if err != nil || host != "ssh.app.daytona.io" || port != 2222 {
		t.Errorf("ssh access: %q -> %s %d %v", a.SSHCommand, host, port, err)
	}
	var e struct {
		StatusCode int    `json:"statusCode"`
		Message    string `json:"message"`
		Code       string `json:"code"`
	}
	read("error_404.json", &e)
	if e.StatusCode != 404 || e.Message == "" || e.Code == "" {
		t.Errorf("error: %+v", e)
	}
}

// TestCreateBodyPerTier pins the create call: the run's name and label, the
// TTL from the vendor timeout, auto-stop off, ephemeral, no public preview,
// networkBlockAll below the internet tier, the target and snapshot only
// when named.
func TestCreateBodyPerTier(t *testing.T) {
	cases := []struct {
		tier     vocab.Tier
		region   string
		template string
		block    bool
	}{
		{vocab.TierNone, "eu", "", true},
		{vocab.TierProxyOnly, sandboxremote.ProviderChosen, "my-snap", true},
		{vocab.TierInternet, "", "", false},
	}
	for i, tc := range cases {
		f := newFakeDaytona(t)
		c := f.client(t)
		run := "r" + string(rune('a'+i))
		info, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 3601, Tier: tc.tier, Region: tc.region, Template: tc.template, Env: map[string]string{"HOME": "/home/daytona"}})
		if err != nil {
			t.Fatalf("%s: %v", tc.tier, err)
		}
		if !info.Running || info.Labels[sandboxremote.LabelKey] != run || info.ID == "" {
			t.Errorf("%s: info %+v", tc.tier, info)
		}
		b := f.creates[0]
		if b["name"] != "observer-"+run || b["ttlMinutes"] != float64(61) || b["autoStopInterval"] != float64(0) || b["autoDeleteInterval"] != float64(0) || b["public"] != false || b["networkBlockAll"] != tc.block {
			t.Errorf("%s: body %v", tc.tier, b)
		}
		if lab, _ := b["labels"].(map[string]any); lab[sandboxremote.LabelKey] != run {
			t.Errorf("%s: labels %v", tc.tier, b["labels"])
		}
		_, hasTarget := b["target"]
		if hasTarget != (tc.region != "" && tc.region != sandboxremote.ProviderChosen) {
			t.Errorf("%s: target %v", tc.tier, b["target"])
		}
		_, hasSnap := b["snapshot"]
		if hasSnap != (tc.template != "") {
			t.Errorf("%s: snapshot %v", tc.tier, b["snapshot"])
		}
		for _, k := range []string{"autoPauseInterval", "volumes", "buildInfo", "outboundProxyUrl"} {
			if _, ok := b[k]; ok {
				t.Errorf("%s: the create sent %s", tc.tier, k)
			}
		}
	}
}

// TestCreateRefusesNoTimeout: every box carries the vendor timeout.
func TestCreateRefusesNoTimeout(t *testing.T) {
	f := newFakeDaytona(t)
	if _, err := f.client(t).Create(context.Background(), sandboxremote.BoxSpec{RunID: "r1"}); err == nil || len(f.creates) != 0 {
		t.Fatalf("a create without a timeout was sent: %v", err)
	}
}

// TestCreateConflictAndLost: a repeated name is accepted only for the same
// run's label; a lost answer and a 5xx left after the retries are lost
// creates, and the box is then found by its label.
func TestCreateConflictAndLost(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	c := f.client(t)
	spec := sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 600, Tier: vocab.TierNone}
	first, err := c.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Create(ctx, spec)
	if err != nil || again.ID != first.ID {
		t.Fatalf("a retried create of the same run: %+v %v", again, err)
	}
	f.boxes[first.ID].labels[sandboxremote.LabelKey] = "other"
	if _, err := c.Create(ctx, spec); err == nil || !strings.Contains(err.Error(), "another run") {
		t.Fatalf("a name held by another run was accepted: %v", err)
	}

	f.dropCreate = true
	_, err = c.Create(ctx, sandboxremote.BoxSpec{RunID: "r2", TimeoutSeconds: 600})
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("a lost answer: %v", err)
	}
	found, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "r2")
	if err != nil || len(found) != 1 {
		t.Fatalf("the lost box is not found by its label: %v %v", found, err)
	}

	f.fail500 = 3
	if _, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r3", TimeoutSeconds: 600}); !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("a 5xx past the retries: %v", err)
	}
}

// TestCreateSnapshotMissing: a snapshot the vendor does not have is
// ErrTemplateUnavailable (no box was made).
func TestCreateSnapshotMissing(t *testing.T) {
	f := newFakeDaytona(t)
	f.missingSnap = "nope"
	_, err := f.client(t).Create(context.Background(), sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 600, Template: "nope"})
	if !errors.Is(err, sandboxremote.ErrTemplateUnavailable) || len(f.boxes) != 0 {
		t.Fatalf("missing snapshot: %v", err)
	}
	f.createState = stateBuildFailed
	_, err = f.client(t).Create(context.Background(), sandboxremote.BoxSpec{RunID: "r2", TimeoutSeconds: 600, Template: "bad"})
	if !errors.Is(err, sandboxremote.ErrTemplateUnavailable) {
		t.Fatalf("build_failed: %v", err)
	}
}

// TestCreateNotReady: a create answered before the box started reads not
// running, so the core waits for it.
func TestCreateNotReady(t *testing.T) {
	f := newFakeDaytona(t)
	f.createState = "creating"
	info, err := f.client(t).Create(context.Background(), sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 600})
	if err != nil || info.Running {
		t.Fatalf("a creating box: %+v %v", info, err)
	}
}

// TestRetries: a 429 or 5xx is retried within the bound; a 429 past it or
// past MaxRetryWait is ErrRateLimited.
func TestRetries(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	c := f.client(t)
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	f.fail429, f.retryAt = 2, "1"
	if _, err := c.Get(ctx, info.ID); err != nil {
		t.Fatalf("two 429s within the bound: %v", err)
	}
	f.fail429 = 3
	if _, err := c.Get(ctx, info.ID); !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("three 429s: %v", err)
	}
	f.fail429, f.retryAt = 1, "3600"
	if _, err := c.Get(ctx, info.ID); !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("a Retry-After past the cap: %v", err)
	}
	f.fail429, f.retryAt = 0, ""
	f.fail500 = 2
	if _, err := c.Get(ctx, info.ID); err != nil {
		t.Fatalf("two 5xx within the bound: %v", err)
	}
}

// TestKeyNeverInErrors: an answer that echoes the key comes back redacted,
// and the credential never reaches a URL.
func TestKeyNeverInErrors(t *testing.T) {
	f := newFakeDaytona(t)
	f.echoToken = true
	_, err := f.client(t).Get(context.Background(), "sbx-1")
	if err == nil || strings.Contains(err.Error(), f.key) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("error: %v", err)
	}
}

// TestGetDeleteConfirmAndList: a deleted box reads not found (the vendor
// answers state destroyed); the list filters by label server side, is
// re-checked, and follows nextCursor.
func TestGetDeleteConfirmAndList(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	f.pageSize = 2
	c := f.client(t)
	var ids []string
	for _, run := range []string{"a", "b", "c", "d", "e"} {
		labels := map[string]string{"team": "x"}
		info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 600, Labels: labels})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, info.ID)
	}
	all, err := c.ListByLabel(ctx, "team", "x")
	if err != nil || len(all) != 5 {
		t.Fatalf("list across pages: %d %v", len(all), err)
	}
	if err := c.Delete(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, ids[0]); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("a destroyed box: %v", err)
	}
	if left, _ := c.ListByLabel(ctx, "team", "x"); len(left) != 4 {
		t.Fatalf("the destroyed box is still listed: %d", len(left))
	}
	if _, err := c.Get(ctx, "nope"); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("an unknown box: %v", err)
	}
	if err := c.Delete(ctx, "observer-b"); err != nil {
		t.Fatalf("delete by name: %v", err)
	}
}

// TestWriteAndReadFiles: each file is uploaded raw and then given its mode;
// a read stops at max.
func TestWriteAndReadFiles(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	c := f.client(t)
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	open := func(s string) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
	}
	files := []sandboxremote.UploadFile{
		{Path: "/home/daytona/ws/a.txt", Mode: 0o644, Size: 5, Open: open("hello")},
		{Path: "/home/daytona/.observer-box/bin/observer", Mode: 0o755, Size: 3, Open: open("bin")},
		{Path: "/home/daytona/empty", Open: open("")},
	}
	if err := c.WriteFiles(ctx, info.ID, files); err != nil {
		t.Fatal(err)
	}
	b := f.boxes[info.ID]
	if string(b.files["/home/daytona/ws/a.txt"]) != "hello" || b.modes["/home/daytona/.observer-box/bin/observer"] != "0755" || b.modes["/home/daytona/empty"] != "0644" {
		t.Errorf("files %v modes %v", b.files, b.modes)
	}
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: "rel/x", Open: open("x")}}); err == nil {
		t.Error("a relative path was uploaded")
	}
	got, err := c.ReadFile(ctx, info.ID, "/home/daytona/ws/a.txt", 64)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read: %q %v", got, err)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/home/daytona/ws/a.txt", 2); err == nil {
		t.Error("a read past max was accepted")
	}
	if _, err := c.ReadFile(ctx, info.ID, "/nope", 64); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("a missing file: %v", err)
	}
}

// TestToolboxHostRefused: a toolbox URL off the bound endpoint's host and
// Daytona's domain is never sent the key.
func TestToolboxHostRefused(t *testing.T) {
	c, err := New(Options{Endpoint: "https://app.daytona.io/api", Key: "k-FAKE"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://proxy.app.daytona.io/toolbox", true},
		{"https://app.daytona.io/toolbox", true},
		{"https://proxy.example.com/toolbox", false},
		{"http://proxy.app.daytona.io/toolbox", false},
		{"https://user@proxy.app.daytona.io/toolbox", false},
		{"https://proxy.app.daytona.io/toolbox?x=1", false},
		{"", false},
	}
	for _, tc := range cases {
		base, err := c.toolboxBase(tc.raw, "sbx 1")
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v", tc.raw, err)
		}
		if tc.ok && base != strings.TrimSuffix(tc.raw, "/")+"/sbx%201" {
			t.Errorf("%q: base %s", tc.raw, base)
		}
		if !tc.ok && tc.raw != "" && !errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch) {
			t.Errorf("%q: %v is not a credential endpoint mismatch", tc.raw, err)
		}
	}
}

// TestNewAndBoxName: New refuses a non-https endpoint and a missing key;
// the name is the run id's safe characters.
func TestNewAndBoxName(t *testing.T) {
	for _, o := range []Options{
		{Endpoint: "http://app.daytona.io/api", Key: "k"},
		{Endpoint: "https://app.daytona.io/api"},
		{Endpoint: "https://u@app.daytona.io/api", Key: "k"},
		{Endpoint: "https://app.daytona.io/api?x=1", Key: "k"},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("New(%+v) was accepted", o)
		}
	}
	cases := map[string]string{
		"r1":                     "observer-r1",
		"Run_ID.2/x":             "observer-runid2x",
		strings.Repeat("a", 100): "observer-" + strings.Repeat("a", 54),
		"--":                     "observer",
	}
	for in, want := range cases {
		if got := BoxName(in); got != want {
			t.Errorf("BoxName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSSHTarget: the documented connection command parses; anything else
// is refused.
func TestSSHTarget(t *testing.T) {
	cases := []struct {
		cmd  string
		host string
		port int
		ok   bool
	}{
		{"ssh tok@ssh.app.daytona.io", "ssh.app.daytona.io", 22, true},
		{"ssh -p 2222 tok@localhost", "localhost", 2222, true},
		{"ssh -p 0 tok@h", "", 0, false},
		{"ssh -o ProxyCommand=x tok@h", "", 0, false},
		{"scp tok@h", "", 0, false},
		{"ssh -p 22", "", 0, false},
	}
	for _, tc := range cases {
		host, port, err := sshTarget(tc.cmd)
		if (err == nil) != tc.ok || host != tc.host || port != tc.port {
			t.Errorf("%q: %s %d %v", tc.cmd, host, port, err)
		}
	}
}

// TestCommandLine pins the exec command: sh -c (sudo -n for root), the pid
// recorded, the cwd, the env sorted and quoted, stdin closed without a
// streaming stdin, and a quote in an argument kept whole.
func TestCommandLine(t *testing.T) {
	got, err := commandLine(sandboxremote.ExecSpec{Argv: []string{"echo", "it's"}, Env: map[string]string{"B": "2", "A": "1 2"}, Cwd: "/w s"}, "/tmp/p")
	if err != nil {
		t.Fatal(err)
	}
	inner, ok := unquoteWord(strings.TrimPrefix(got, "sh -c "))
	want := `echo $$ >'/tmp/p' && cd -- '/w s' && exec env 'A=1 2' 'B=2' 'echo' 'it'\''s' </dev/null`
	if !strings.HasPrefix(got, "sh -c ") || !ok || inner != want {
		t.Errorf("command line:\n got %s\n inner %s\nwant %s", got, inner, want)
	}
	root, _ := commandLine(sandboxremote.ExecSpec{Argv: []string{"mkdir", "x"}, AsRoot: true, Stdin: true}, "/tmp/p")
	if !strings.HasPrefix(root, "sudo -n -- sh -c ") || strings.Contains(root, "/dev/null") {
		t.Errorf("root: %s", root)
	}
	for _, bad := range []sandboxremote.ExecSpec{{}, {Argv: []string{"a=b"}, Env: map[string]string{"X": "1"}}, {Argv: []string{"a"}, Env: map[string]string{"X-Y": "1"}}} {
		if _, err := commandLine(bad, "/tmp/p"); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

// startBox creates a box on the fake and returns the client and its id.
func startBox(t *testing.T, f *fakeDaytona) (*Client, string) {
	t.Helper()
	c := f.client(t)
	info, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "r1", TimeoutSeconds: 1800})
	if err != nil {
		t.Fatal(err)
	}
	return c, info.ID
}

// TestExecRelayStreamOverSSH: the relay's exec streams stdin and stdout on
// an SSH exec channel, stdin's close is an EOF in the box (HalfCloser), the
// exit status comes back, stderr reaches the sink, and the token is the SSH
// user and password with the TTL as its lifetime.
func TestExecRelayStreamOverSSH(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	f.exec = func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		_, _ = io.WriteString(stderr, "relay: started\n")
		_, _ = io.Copy(stdout, stdin) // echo until EOF
		return 7
	}
	c, id := startBox(t, f)
	var errBuf lockedBuffer
	p, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"/home/daytona/.observer-box/bin/observer", "sandbox-guest"}, Stdin: true, Stderr: &errBuf})
	if err != nil || p == nil {
		t.Fatalf("exec: %v", err)
	}
	if _, err := p.Write([]byte("aGVsbG8=\n")); err != nil {
		t.Fatal(err)
	}
	hc, ok := p.(sandboxremote.HalfCloser)
	if !ok {
		t.Fatal("the process has no stdin-only close")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(p)
	if err != nil || string(out) != "aGVsbG8=\n" {
		t.Fatalf("stdout %q %v", out, err)
	}
	code, err := p.Wait(ctx)
	if err != nil || code != 7 {
		t.Fatalf("exit %d %v", code, err)
	}
	_ = p.Close()
	if !strings.Contains(errBuf.String(), "relay: started") {
		t.Errorf("stderr sink: %q", errBuf.String())
	}
	if len(f.tokens) != 1 || !strings.HasSuffix(f.tokens[0], "FAKE30") {
		t.Errorf("ssh access asked: %v (want one, with expiresInMinutes 30)", f.tokens)
	}
	if len(f.sshAddrs) != 1 || f.sshAddrs[0] != "127.0.0.1:22" {
		t.Errorf("ssh dials: %v", f.sshAddrs)
	}
	if !strings.HasPrefix(f.execs[0], "sh -c ") || !strings.Contains(f.execs[0], "sandbox-guest") {
		t.Errorf("exec command: %s", f.execs[0])
	}

	// A second exec reuses the connection (one access, one dial).
	p2, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(p2)
	if code, err := p2.Wait(ctx); err != nil || code != 7 {
		t.Fatalf("second exec: %d %v", code, err)
	}
	if len(f.tokens) != 1 || len(f.sshAddrs) != 1 {
		t.Errorf("the connection was not reused: %v %v", f.tokens, f.sshAddrs)
	}
}

// TestExecReconnectsAfterADroppedConnection: a dead connection is dropped
// and the next exec dials again with a fresh token.
func TestExecReconnectsAfterADroppedConnection(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	c, id := startBox(t, f)
	p, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Wait(ctx)
	c.mu.Lock()
	conn := c.ssh[id]
	c.mu.Unlock()
	_ = conn.client.Close()
	if _, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"true"}}); err != nil {
		t.Fatalf("exec after a drop: %v", err)
	}
	if len(f.tokens) != 2 {
		t.Errorf("tokens %v: want a fresh one after the drop", f.tokens)
	}
}

// TestExecKill: Kill signals the recorded pid through a second exec, as
// root for a root process.
func TestExecKill(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	release := make(chan struct{})
	var once sync.Once
	f.exec = func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		if strings.Contains(cmd, "kill -TERM") {
			once.Do(func() { close(release) })
			return 0
		}
		<-release
		return 143
	}
	c, id := startBox(t, f)
	p, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"sleep", "100"}, AsRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	var kill string
	f.mu.Lock()
	for _, e := range f.execs {
		if strings.Contains(e, "kill -TERM") {
			kill = e
		}
	}
	f.mu.Unlock()
	if !strings.HasPrefix(kill, "sudo -n -- sh -c ") || !strings.Contains(kill, "/tmp/.observer-exec-"+p.PID()+".pid") {
		t.Errorf("kill command: %q (pid %s)", kill, p.PID())
	}
}

// TestUnsupported: no vendor PTY, resize, reattach or one-shot stdin.
func TestUnsupported(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	c, id := startBox(t, f)
	if _, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"sh"}, PTY: true}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("PTY: %v", err)
	}
	if _, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"cat"}, StdinData: []byte("x")}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("one-shot stdin: %v", err)
	}
	if _, err := c.Reattach(ctx, id, "x"); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("reattach: %v", err)
	}
	p, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Resize(ctx, 24, 80); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("resize: %v", err)
	}
	if _, err := p.Write([]byte("x")); err == nil {
		t.Error("a write to a process without stdin was accepted")
	}
	_, _ = p.Wait(ctx)
	_ = p.Close()
}

// TestSSHGatewayGuards: a gateway off Daytona's domain is never sent the
// token, and a host key that changes within the client's life is refused.
func TestSSHGatewayGuards(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaytona(t)
	f.sshHost = "ssh.example.com"
	c, id := startBox(t, f)
	if _, err := c.Exec(ctx, id, sandboxremote.ExecSpec{Argv: []string{"true"}}); !errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch) || len(f.sshAddrs) != 0 {
		t.Fatalf("a foreign gateway: %v (dials %v)", err, f.sshAddrs)
	}

	f2 := newFakeDaytona(t)
	c2, id2 := startBox(t, f2)
	p, err := c2.Exec(ctx, id2, sandboxremote.ExecSpec{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Wait(ctx)
	c2.dropSSH(id2, nil)
	other := newFakeDaytona(t)
	f2.hostKey = other.hostKey
	if _, err := c2.Exec(ctx, id2, sandboxremote.ExecSpec{Argv: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("a changed host key: %v", err)
	}
	for _, tok := range f2.tokens {
		if strings.Contains(errString(err), tok) {
			t.Errorf("the token %s is in the error", tok)
		}
	}
}

// unquoteWord reads one POSIX shell word made of single-quoted runs and
// backslash-escaped characters (what shellQuote writes); ok is false for
// anything else.
func unquoteWord(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch s[i] {
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case '\\':
			if i+1 >= len(s) {
				return "", false
			}
			b.WriteByte(s[i+1])
			i += 2
		default:
			return "", false
		}
	}
	return b.String(), true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// lockedBuffer is a bytes.Buffer safe for the SSH reader's goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
