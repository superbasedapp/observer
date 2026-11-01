package modal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

const (
	fakeTokenID     = "ak-FAKEtokenIDdoNotUse"
	fakeTokenSecret = "as-FAKEtokenSECRETdoNotUse"
)

// answers are the recorded SDK answers (testdata/answers.json).
type answers struct {
	Create struct {
		SandboxID string `json:"sandbox_id"`
	} `json:"create"`
	GetTags  map[string]string `json:"get_tags"`
	NotFound struct {
		Error string `json:"error"`
	} `json:"not_found"`
	ResourceExhausted struct {
		Error string `json:"error"`
	} `json:"resource_exhausted"`
	LostCreate struct {
		Error string `json:"error"`
	} `json:"lost_create"`
}

func loadAnswers(t *testing.T) answers {
	t.Helper()
	b, err := os.ReadFile("testdata/answers.json")
	if err != nil {
		t.Fatal(err)
	}
	var a answers
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// fakeBox is one box the fake holds.
type fakeBox struct {
	running bool
	tags    map[string]string
	files   map[string][]byte
}

// fakeBackend scripts the SDK seam from the recorded answers.
type fakeBackend struct {
	a          answers
	mu         sync.Mutex
	boxes      map[string]*fakeBox
	creates    []createSpec
	execs      []execSpec
	createErr  error
	terminated []string
	// echo makes an exec copy its stdin to its stdout (the relay path).
	echo bool
	// code is every exec's exit code.
	code int
	// leakErr makes every call fail with an error that quotes the token.
	leakErr bool
}

func newFake(t *testing.T) *fakeBackend {
	return &fakeBackend{a: loadAnswers(t), boxes: map[string]*fakeBox{}}
}

func (f *fakeBackend) leak() error {
	if f.leakErr {
		return errors.New("transport: x-modal-token-secret=" + fakeTokenSecret + " rejected")
	}
	return nil
}

func (f *fakeBackend) create(_ context.Context, s createSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, s)
	if f.createErr != nil {
		return "", f.createErr
	}
	id := f.a.Create.SandboxID
	f.boxes[id] = &fakeBox{running: true, tags: s.tags, files: map[string][]byte{}}
	return id, nil
}

func (f *fakeBackend) get(_ context.Context, id string) (boxState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[id]
	if !ok {
		return boxState{}, errNotFound
	}
	return boxState{id: id, running: b.running, tags: b.tags}, nil
}

func (f *fakeBackend) list(_ context.Context, tags map[string]string) ([]boxState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []boxState
	for id, b := range f.boxes {
		if b.running {
			out = append(out, boxState{id: id, running: true, tags: b.tags})
		}
	}
	_ = tags // the fake ignores the vendor filter: the client must filter
	return out, nil
}

func (f *fakeBackend) terminate(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[id]
	if !ok {
		return errNotFound
	}
	b.running = false
	f.terminated = append(f.terminated, id)
	return nil
}

func (f *fakeBackend) exec(_ context.Context, id string, s execSpec) (proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.leak(); err != nil {
		return nil, err
	}
	if _, ok := f.boxes[id]; !ok {
		return nil, errNotFound
	}
	f.execs = append(f.execs, s)
	pr, pw := io.Pipe()
	p := &fakeProc{out: pr, code: f.code}
	if f.echo {
		p.in = pw
	} else {
		p.in = nopWriteCloser{io.Discard}
		_ = pw.Close()
	}
	return p, nil
}

func (f *fakeBackend) write(_ context.Context, id, p string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[id]
	if !ok {
		return errNotFound
	}
	b.files[p] = bytes.Clone(data)
	return nil
}

func (f *fakeBackend) read(_ context.Context, id, p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[id]
	if !ok {
		return nil, errNotFound
	}
	d, ok := b.files[p]
	if !ok {
		return nil, errNotFound
	}
	return d, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// fakeProc is one exec: what is written to in comes out of out (echo).
type fakeProc struct {
	in   io.WriteCloser
	out  *io.PipeReader
	code int
}

func (p *fakeProc) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *fakeProc) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *fakeProc) closeStdin() error           { return p.in.Close() }
func (p *fakeProc) closeStdout() error          { return p.out.Close() }
func (p *fakeProc) wait(context.Context) (int, error) {
	return p.code, nil
}

func newTestClient(t *testing.T, f *fakeBackend) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: "https://api.modal.com:443", TokenID: fakeTokenID, TokenSecret: fakeTokenSecret, backend: f})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewNeedsBothTokenHalves(t *testing.T) {
	for _, o := range []Options{{TokenID: fakeTokenID}, {TokenSecret: fakeTokenSecret}, {}} {
		if _, err := New(o); err == nil {
			t.Fatalf("New(%+v) accepted a partial token", o)
		}
	}
}

// TestCreateMapsTiersRegionsAndTags pins the create mapping per tier: the
// network is blocked for none and proxy_only (the relay is the only path
// out) and open only for internet; the region is passed unless the provider
// chooses; the run label is always a tag; gVisor and no ports are the SDK
// call's (sdk.go).
func TestCreateMapsTiersRegionsAndTags(t *testing.T) {
	cases := []struct {
		tier    vocab.Tier
		region  string
		block   bool
		regions []string
	}{
		{vocab.TierNone, "", true, nil},
		{vocab.TierProxyOnly, sandboxremote.ProviderChosen, true, nil},
		{vocab.TierInternet, "us-east", false, []string{"us-east"}},
	}
	for _, tc := range cases {
		f := newFake(t)
		c := newTestClient(t, f)
		info, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "run-1", TimeoutSeconds: 3600, Tier: tc.tier, Region: tc.region})
		if err != nil {
			t.Fatal(err)
		}
		got := f.creates[0]
		if got.blockNetwork != tc.block || strings.Join(got.regions, ",") != strings.Join(tc.regions, ",") {
			t.Errorf("tier %s: block=%v regions=%v", tc.tier, got.blockNetwork, got.regions)
		}
		if got.tags[sandboxremote.LabelKey] != "run-1" || got.image != DefaultImage || got.app != DefaultApp || got.timeoutSeconds != 3600 {
			t.Errorf("create spec %+v", got)
		}
		if info.ID != f.a.Create.SandboxID || info.Region == "" {
			t.Errorf("info %+v", info)
		}
	}
}

func TestCreateRefusesNoTimeout(t *testing.T) {
	c := newTestClient(t, newFake(t))
	if _, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "r"}); err == nil {
		t.Fatal("a box without a timeout was created")
	}
}

// TestLostCreateAndRateLimit: a lost create answer reads ErrCreateUnknown
// (the core lists the label), a 429-class answer ErrRateLimited.
func TestLostCreateAndRateLimit(t *testing.T) {
	f := newFake(t)
	f.createErr = errLostAnswer
	c := newTestClient(t, f)
	_, err := c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("lost create: %v", err)
	}
	f.createErr = classify(status.Error(codes.ResourceExhausted, f.a.ResourceExhausted.Error))
	_, err = c.Create(context.Background(), sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	if !errors.Is(err, sandboxremote.ErrRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestClassifyAndLost(t *testing.T) {
	a := loadAnswers(t)
	if !errors.Is(classify(status.Error(codes.NotFound, a.NotFound.Error)), errNotFound) {
		t.Error("gRPC NotFound not classified")
	}
	if !lost(status.Error(codes.Unavailable, a.LostCreate.Error)) || lost(status.Error(codes.InvalidArgument, "bad")) {
		t.Error("lost answer misclassified")
	}
	if !errors.Is(classify(sandboxremote.ErrCredentialEndpointMismatch), sandboxremote.ErrCredentialEndpointMismatch) {
		t.Error("the binding refusal lost its name")
	}
}

// TestDeleteConfirmsAndListFilters: terminate makes Get read stopped, a
// second terminate reads ErrNotFound only for an unknown box, and the label
// filter is applied by the client too.
func TestDeleteConfirmsAndListFilters(t *testing.T) {
	f := newFake(t)
	c := newTestClient(t, f)
	ctx := context.Background()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "run-1", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	f.boxes["sb-other"] = &fakeBox{running: true, tags: map[string]string{sandboxremote.LabelKey: "run-2"}}
	list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "run-1")
	if err != nil || len(list) != 1 || list[0].ID != info.ID {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := c.Delete(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, info.ID)
	if err != nil || got.Running {
		t.Fatalf("after terminate %+v %v", got, err)
	}
	if err := c.Delete(ctx, "sb-gone"); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("unknown box: %v", err)
	}
}

// TestExecRelayStreamAndUnsupported: the relay's exec is a plain stdin and
// stdout stream; a vendor PTY, a resize and a reattach are refused by name
// (Modal documents none), so the run takes the guest helper and ends on a
// cut transport (A6 register entry, A7 native resume).
func TestExecRelayStreamAndUnsupported(t *testing.T) {
	f := newFake(t)
	f.echo = true
	c := newTestClient(t, f)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh"}, PTY: true}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Fatalf("vendor PTY: %v", err)
	}
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"observer", "sandbox-guest", "--relay-stdio"}, Stdin: true, Cwd: "/w", Env: map[string]string{"A": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = p.Write([]byte("frame\n")); _ = p.Kill(ctx) }()
	out, err := io.ReadAll(p)
	if err != nil || string(out) != "frame\n" {
		t.Fatalf("relay stream %q %v", out, err)
	}
	if f.execs[0].cwd != "/w" || f.execs[0].env["A"] != "b" {
		t.Errorf("exec spec %+v", f.execs[0])
	}
	if !errors.Is(p.Resize(ctx, 10, 10), sandboxremote.ErrNotSupported) || p.PID() != "" {
		t.Error("resize or PID claimed")
	}
	if _, err := c.Reattach(ctx, info.ID, "x"); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("reattach: %v", err)
	}
	_ = p.Close()
}

// TestWriteFilesSetsModes: the SDK takes no mode, so every non-default mode
// is set by one chmod after the writes (the relay secret's 0600 included).
func TestWriteFilesSetsModes(t *testing.T) {
	f := newFake(t)
	c := newTestClient(t, f)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	open := func(s string) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
	}
	files := []sandboxremote.UploadFile{
		{Path: "/w/a.txt", Mode: 0o644, Size: 1, Open: open("a")},
		{Path: "/root/.observer-box/run/secret", Mode: 0o600, Size: 2, Open: open("s3")},
		{Path: "/root/.observer-box/bin/observer", Mode: 0o755, Open: open("ELF")},
	}
	if err := c.WriteFiles(ctx, info.ID, files); err != nil {
		t.Fatal(err)
	}
	if string(f.boxes[info.ID].files["/w/a.txt"]) != "a" {
		t.Error("file not written")
	}
	var chmods []string
	for _, e := range f.execs {
		chmods = append(chmods, strings.Join(e.argv, " "))
	}
	want := []string{"chmod 600 -- /root/.observer-box/run/secret", "chmod 755 -- /root/.observer-box/bin/observer"}
	if strings.Join(chmods, "|") != strings.Join(want, "|") {
		t.Fatalf("chmods %q", chmods)
	}
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: "rel", Open: open("x")}}); err == nil {
		t.Error("a relative path was written")
	}
	big := sandboxremote.UploadFile{Path: "/w/grew", Size: 1, Open: open("grown")}
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{big}); err == nil {
		t.Error("a file that grew past its listed size was written")
	}
}

func TestReadFileCap(t *testing.T) {
	f := newFake(t)
	c := newTestClient(t, f)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	f.boxes[info.ID].files["/t.jsonl"] = []byte("0123456789")
	if _, err := c.ReadFile(ctx, info.ID, "/t.jsonl", 4); err == nil {
		t.Error("an over-cap file was read")
	}
	if b, err := c.ReadFile(ctx, info.ID, "/t.jsonl", 0); err != nil || len(b) != 10 {
		t.Errorf("read %q %v", b, err)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/none", 0); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
}

// TestTokenNeverInErrors: an error that quotes the token comes back
// redacted from every call.
func TestTokenNeverInErrors(t *testing.T) {
	f := newFake(t)
	c := newTestClient(t, f)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	f.leakErr = true
	_, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"true"}})
	if err == nil || strings.Contains(err.Error(), fakeTokenSecret) || strings.Contains(err.Error(), fakeTokenID) {
		t.Fatalf("error leaks the token: %v", err)
	}
}

// TestBindingGuard pins SBX-GOV-4 for the SDK path: only the bound
// endpoint's domain is reachable, a non-https endpoint is refused, and a
// MODAL_SERVER_URL pointing elsewhere refuses the client by name.
func TestBindingGuard(t *testing.T) {
	ok, err := boundHosts("https://api.modal.com:443")
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]bool{
		"api.modal.com:443": true, "dns:///api.modal.com:443": true, "us-east.api.modal.com:443": true,
		"modal.com": true, "api.modal.com.evil.example:443": false, "evilmodal.com:443": false, "127.0.0.1:443": false,
	} {
		if ok(target) != want {
			t.Errorf("target %q: got %v", target, !want)
		}
	}
	if _, err := boundHosts("http://api.modal.com"); err == nil {
		t.Error("a plaintext endpoint was bound")
	}
	t.Setenv("MODAL_SERVER_URL", "https://api.evil.example:443")
	_, err = New(Options{Endpoint: "https://api.modal.com:443", TokenID: fakeTokenID, TokenSecret: fakeTokenSecret})
	if !errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch) {
		t.Fatalf("MODAL_SERVER_URL elsewhere: %v", err)
	}
	if !sameOrigin("https://api.modal.com", "https://api.modal.com:443") || sameOrigin("http://api.modal.com", "https://api.modal.com") {
		t.Error("sameOrigin")
	}
}
