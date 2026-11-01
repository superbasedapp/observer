package e2b

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

func spec() sandboxremote.BoxSpec {
	return sandboxremote.BoxSpec{
		RunID: "run1", Labels: map[string]string{sandboxremote.LabelKey: "run1"},
		TimeoutSeconds: 3600, Tier: "proxy_only", Region: "us-west-1",
	}
}

// TestRecordedResponsesParse: the shapes reconstructed from E2B's spec
// decode into what the client reads.
func TestRecordedResponsesParse(t *testing.T) {
	for _, name := range []string{"create_201.json", "get_200.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var s sandboxResp
		if err := json.Unmarshal(b, &s); err != nil || s.SandboxID == "" || s.EnvdAccessToken == "" {
			t.Errorf("%s: %+v %v", name, s, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "list_200.json"))
	var list []sandboxResp
	if err := json.Unmarshal(b, &list); err != nil || len(list) != 1 || list[0].Metadata[sandboxremote.LabelKey] != "run1" {
		t.Errorf("list: %+v %v", list, err)
	}
}

func TestLifecycle(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, spec())
	if err != nil {
		t.Fatal(err)
	}
	if f.lastCreate["autoPause"] != false || f.lastCreate["timeout"].(float64) != 3600 || f.lastCreate["allow_internet_access"] != false || f.lastCreate["templateID"] != "base" {
		t.Errorf("create body %v", f.lastCreate)
	}
	if f.seenIdem[0] != "observer-run1" {
		t.Errorf("idempotency key %v", f.seenIdem)
	}
	if info.EnvdToken == "" {
		t.Error("no envd token returned")
	}
	if got, err := c.Get(ctx, info.ID); err != nil || got.Labels[sandboxremote.LabelKey] != "run1" {
		t.Errorf("get %+v %v", got, err)
	}
	list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "run1")
	if err != nil || len(list) != 1 {
		t.Errorf("list %v %v", list, err)
	}
	data := []byte("package main\n")
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: "/w/p/main.go", Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadFile(ctx, info.ID, "/w/p/main.go", 1<<20); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read %q %v", got, err)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/w/p/main.go", 3); err == nil {
		t.Error("over-cap read accepted")
	}
	if _, err := c.ReadFile(ctx, info.ID, "/missing", 10); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
	if err := c.Delete(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, info.ID); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	if err := c.Delete(ctx, info.ID); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	spec2 := spec()
	spec2.Tier = "internet"
	if _, err := c.Create(ctx, spec2); err != nil || f.lastCreate["allow_internet_access"] != true {
		t.Errorf("internet tier body %v %v", f.lastCreate, err)
	}
	spec2.TimeoutSeconds = 0
	if _, err := c.Create(ctx, spec2); err == nil {
		t.Error("a create without a timeout was sent")
	}
}

func TestRetriesAndRedaction(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	ctx := context.Background()
	f.fail429 = 2
	if _, err := c.Create(ctx, spec()); err != nil {
		t.Fatalf("429 twice then ok: %v", err)
	}
	f.fail429 = 10
	_, err := c.Create(ctx, spec())
	if !errors.Is(err, sandboxremote.ErrRateLimited) || strings.Contains(err.Error(), "FAKEKEY") {
		t.Errorf("persistent 429: %v", err)
	}
	f.fail429 = 0
	f.fail503, f.noRetry503 = 1, true
	if _, err := c.Get(ctx, "sbx1"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("503 with Should-Retry false: %v", err)
	}
	bad, _ := New(Options{Endpoint: f.srv.URL, APIKey: "e2b_FAKEKEY_wrong_999", EnvdURL: f.srv.URL})
	_, err = bad.Get(ctx, "sbx1")
	if err == nil || strings.Contains(err.Error(), "FAKEKEY") {
		t.Errorf("an error echoed the key: %v", err)
	}
}

func TestLostCreateIsFoundByLabel(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	ctx := context.Background()
	f.loseCreate = true
	_, err := c.Create(ctx, spec())
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) {
		t.Fatalf("lost create: %v", err)
	}
	list, err := c.ListByLabel(ctx, sandboxremote.LabelKey, "run1")
	if err != nil || len(list) != 1 {
		t.Fatalf("the box of a lost create was not found by its label: %v %v", list, err)
	}
	if err := c.Delete(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
}

// TestCreate5xxIsLost (the SBX-P7 merge's audit finding 6): a 5xx left
// after the retries on create is a lost create (resolved by the label),
// never a definite failure.
func TestCreate5xxIsLost(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	f.fail503 = 100
	_, err := c.Create(context.Background(), spec())
	if !errors.Is(err, sandboxremote.ErrCreateUnknown) || strings.Contains(err.Error(), "FAKEKEY") {
		t.Fatalf("a create 5xx after the retries: %v", err)
	}
}

func TestProcessPTYResizeAndReattach(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, spec())
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"bash"}, PTY: true, Rows: 24, Cols: 80, Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.PID() != "101" {
		t.Errorf("pid %s", p.PID())
	}
	if _, err := p.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(p, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q %v", buf, err)
	}
	if err := p.Resize(ctx, 40, 120); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	size := f.boxes[info.ID].procs[101].size
	f.mu.Unlock()
	if size != [2]uint16{40, 120} {
		t.Errorf("size %v", size)
	}
	// A dropped stream: the process lives on; Connect by pid reattaches.
	f.mu.Lock()
	f.dropAfter = 1
	f.mu.Unlock()
	_ = p.Close()
	p2, err := c.Reattach(ctx, info.ID, "101")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p2.Write([]byte("again"))
	if _, err := io.ReadFull(p2, buf); err != nil || string(buf) != "again" {
		t.Fatalf("after reattach %q %v", buf, err)
	}
	if _, err := io.ReadFull(p2, buf); err == nil {
		t.Error("the dropped stream kept delivering")
	}
	p3, err := c.Reattach(ctx, info.ID, "101")
	if err != nil {
		t.Fatal(err)
	}
	if err := p3.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if code, err := p3.Wait(wctx); err != nil || code != 3 {
		t.Errorf("exit %d %v", code, err)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"true"}, AsRoot: true}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	users := strings.Join(f.authUser, ",")
	f.mu.Unlock()
	if !strings.Contains(users, "root") || !strings.Contains(users, "user") {
		t.Errorf("envd users %s", users)
	}
}
