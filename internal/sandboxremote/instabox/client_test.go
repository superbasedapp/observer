package instabox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

func newSpec(run string) sandboxremote.BoxSpec {
	return sandboxremote.BoxSpec{RunID: run, Labels: map[string]string{sandboxremote.LabelKey: run}, TimeoutSeconds: 3600}
}

func TestNewRefusesBadOptions(t *testing.T) {
	for _, o := range []Options{
		{Endpoint: "http://api.instabox.sh", Key: "k"},
		{Endpoint: "https://api.instabox.sh"},
		{Endpoint: "://", Key: "k"},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	if _, err := New(Options{Endpoint: "https://api.instabox.sh", Key: "k"}); err != nil {
		t.Fatal(err)
	}
}

func TestBoxName(t *testing.T) {
	for in, want := range map[string]string{
		"Run_1.x":               "observer-run1x",
		"abc-":                  "observer-abc",
		strings.Repeat("a", 80): "observer-" + strings.Repeat("a", 54),
	} {
		if got := BoxName(in); got != want {
			t.Errorf("BoxName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCreateGetListDelete(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	spec := newSpec("Run-1")
	spec.Template = "ci"
	spec.Labels["pool"] = "p"
	info, err := c.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Running || info.Labels[sandboxremote.LabelKey] != "Run-1" || info.Deadline.IsZero() || info.Region != sandboxremote.ProviderChosen {
		t.Fatalf("info %+v", info)
	}
	body := f.creates[0]
	if body["name"] != "observer-run-1" || body["deleteAfterSeconds"].(float64) != 3600 || body["templateId"] != "ci" {
		t.Errorf("create body %v", body)
	}
	for _, k := range []string{"maxRunMinutes", "autoSuspendAfterSeconds", "region", "timeoutSeconds"} {
		if _, ok := body[k]; ok {
			t.Errorf("create sent %s", k)
		}
	}
	if !strings.HasPrefix(f.createKeys[0], "observer-create-") {
		t.Errorf("idempotency key %q", f.createKeys[0])
	}
	got, err := c.Get(ctx, info.ID)
	if err != nil || got.ID != info.ID || !got.Running {
		t.Fatalf("get %+v %v", got, err)
	}
	spec2 := newSpec("run-2")
	spec2.Labels["pool"] = "p"
	if _, err := c.Create(ctx, spec2); err != nil {
		t.Fatal(err)
	}
	boxes, err := c.ListByLabel(ctx, "pool", "p")
	if err != nil || len(boxes) != 2 {
		t.Fatalf("list across pages: %v %v", boxes, err)
	}
	if one, _ := c.ListByLabel(ctx, sandboxremote.LabelKey, "run-2"); len(one) != 1 {
		t.Errorf("label filter: %v", one)
	}
	if err := c.Delete(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	if h := f.deletes[0]; h.Get("X-Confirm-Delete") != info.ID || h.Get("Idempotency-Key") == "" {
		t.Errorf("delete headers %v", h)
	}
	if _, err := c.Get(ctx, info.ID); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	if err := c.Delete(ctx, info.ID); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestCreateTimeoutIsTheVendorDeleteDeadline(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{30, 60}, {600, 600}, {100000, 86400}} {
		f := newFakeAPI(t)
		spec := newSpec("r")
		spec.TimeoutSeconds = tc.in
		if _, err := f.client(t).Create(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		if got := f.creates[0]["deleteAfterSeconds"].(float64); int(got) != tc.want {
			t.Errorf("timeout %d sent as %v, want %d", tc.in, got, tc.want)
		}
	}
	if _, err := newFakeAPI(t).client(t).Create(context.Background(), sandboxremote.BoxSpec{RunID: "r"}); err == nil {
		t.Error("a create with no timeout was sent")
	}
}

func TestCreateRefusalsAndLostCreates(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		setup func(*fakeAPI)
		is    error
		not   error
	}{
		{"template refused at once", func(f *fakeAPI) { f.createCode, f.createBody = http.StatusForbidden, "template_not_allowed" }, sandboxremote.ErrTemplateUnavailable, nil},
		{"template refused by the operation", func(f *fakeAPI) {
			f.createFail = map[string]any{"code": "template_unavailable", "message": "rolling out", "retryable": true}
		}, sandboxremote.ErrTemplateUnavailable, nil},
		{"no capacity", func(f *fakeAPI) {
			f.createFail = map[string]any{"code": "no_capacity", "message": "no room", "retryable": true}
		}, nil, sandboxremote.ErrCreateUnknown},
		{"a 500 the vendor does not call retryable", func(f *fakeAPI) { f.createCode, f.createBody = http.StatusInternalServerError, "internal" }, sandboxremote.ErrCreateUnknown, nil},
		{"quota", func(f *fakeAPI) { f.createCode, f.createBody = http.StatusTooManyRequests, "quota_exceeded" }, nil, sandboxremote.ErrCreateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			tc.setup(f)
			info, err := f.client(t).Create(ctx, newSpec("r1"))
			if tc.is == nil && errors.Is(tc.not, sandboxremote.ErrCreateUnknown) && tc.name == "quota" {
				// A retryable 429 is retried with the same key and then succeeds.
				if err != nil || info.ID == "" || len(f.createKeys) != 2 || f.createKeys[0] != f.createKeys[1] {
					t.Fatalf("retry: %v %+v %v", err, info, f.createKeys)
				}
				return
			}
			if err == nil {
				t.Fatal("no error")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("%v is not %v", err, tc.is)
			}
			if tc.not != nil && errors.Is(err, tc.not) {
				t.Errorf("%v is %v", err, tc.not)
			}
		})
	}
}

func TestCreateNameConflictReadsBack(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	first, err := c.Create(ctx, newSpec("r1"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Create(ctx, newSpec("r1"))
	if err != nil || again.ID != first.ID {
		t.Fatalf("same run: %+v %v", again, err)
	}
	// Another run whose name sanitises to the same one is refused.
	if _, err := c.Create(ctx, newSpec("R1")); err == nil || !strings.Contains(err.Error(), "another run") {
		t.Fatalf("another run: %v", err)
	}
}

func TestKeyNeverInErrors(t *testing.T) {
	f := newFakeAPI(t)
	f.createCode, f.createBody = http.StatusBadRequest, "echo_key"
	_, err := f.client(t).Create(context.Background(), newSpec("r"))
	if err == nil || strings.Contains(err.Error(), fakeKey) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("error %v", err)
	}
	c, _ := New(Options{Endpoint: f.srv.URL, Key: "ibk_wrong"})
	if _, err := c.Get(context.Background(), "x"); err == nil || strings.Contains(err.Error(), "ibk_wrong") {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestLiveStates(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	future, past := now.Add(time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339)
	cases := []struct {
		name string
		m    machineJSON
		want bool
	}{
		{"running and ready", machineJSON{State: "running", Runtime: struct {
			Ready bool `json:"ready"`
		}{true}}, true},
		{"running, not ready", machineJSON{State: "running"}, false},
		{"creating", machineJSON{State: "creating"}, false},
		{"paused for idleness", machineJSON{State: "suspended", AutoSuspendedAt: past}, true},
		{"paused by the user", machineJSON{State: "suspended"}, false},
		{"paused, in a cooldown", machineJSON{State: "suspended", AutoSuspendedAt: past, CooldownUntil: &future}, false},
		{"cooldown over", machineJSON{State: "suspended", AutoSuspendedAt: past, CooldownUntil: &past}, true},
		{"stopped", machineJSON{State: "stopped"}, false},
		{"error", machineJSON{State: "error"}, false},
	}
	for _, tc := range cases {
		if got := live(tc.m, now); got != tc.want {
			t.Errorf("%s: live %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFixturesDecode(t *testing.T) {
	var m machineJSON
	if err := json.Unmarshal(readFixture(t, "machine_200.json"), &m); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{Endpoint: "https://api.instabox.sh", Key: "k"})
	info := c.info(m)
	if info.ID != "m_agqteugyy5px6hzeadbh4ldjo4" || !info.Running || info.Labels[sandboxremote.LabelKey] != "run-1" ||
		info.Deadline.IsZero() || info.Extra["plan"] != "free" || info.Extra["template"] != "agent-browser" {
		t.Errorf("info %+v", info)
	}
	var op operationJSON
	if err := json.Unmarshal(readFixture(t, "operation_202.json"), &op); err != nil || op.MachineID == "" || op.State != "queued" {
		t.Errorf("operation %+v %v", op, err)
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("Retry-After", "1")
	rec.WriteHeader(http.StatusTooManyRequests)
	_, _ = rec.Body.Write(readFixture(t, "error_429.json"))
	ae := c.readError(rec.Result())
	if ae.code != "quota_exceeded" || !ae.retryable || ae.after != time.Second {
		t.Errorf("error %+v", ae)
	}
}

func TestExecOnce(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, newSpec("r"))
	if err != nil {
		t.Fatal(err)
	}
	f.execResult = map[string]any{"stdout": "out\n", "stderr": "warn\n", "exitCode": 2, "timedOut": false, "truncated": false}
	var stderr bytes.Buffer
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"mkdir", "-p", "/w"}, Cwd: "/w", Env: map[string]string{"HOME": "/data/home"}, AsRoot: true, Stderr: &stderr, StdinData: []byte("é text")})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(p)
	code, err := p.Wait(ctx)
	if string(out) != "out\n" || code != 2 || err != nil || stderr.String() != "warn\n" {
		t.Errorf("out %q code %d err %v stderr %q", out, code, err, stderr.String())
	}
	e := f.execs[0]
	if strings.Join(e.Argv, " ") != "sudo -n -- mkdir -p /w" || e.Cwd != "/w" || e.Envs["HOME"] != "/data/home" || e.Timeout != 600 || e.Stdin != "é text" {
		t.Errorf("exec request %+v", e)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"x"}, StdinData: []byte{0xff, 0xfe}}); err == nil {
		t.Error("binary stdin accepted")
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"x"}, PTY: true}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("vendor PTY: %v", err)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"x"}, Stdin: true, AsRoot: true}); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("streamed root: %v", err)
	}
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"x"}, Env: map[string]string{"A-B": "1"}}); err == nil {
		t.Error("bad env name accepted")
	}
	if _, err := c.Reattach(ctx, info.ID, "obs-1"); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("reattach: %v", err)
	}
}

func TestExecStreamIsByteTransparentAfterTheMarker(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, newSpec("r"))
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{
		Argv: []string{"/data/home/.observer-box/bin/observer", "sandbox-guest", "--relay-stdio", "--run", "it's"},
		Env:  map[string]string{"HOME": "/data/home", "SECRET_ISH": "a'b"}, Cwd: "/work dir", Stdin: true, Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.PID(), "obs-") || len(p.PID()) > 32 {
		t.Errorf("session %q", p.PID())
	}
	q := f.terms[0]
	if !strings.Contains(q, "restart=1") || !strings.Contains(q, "session="+p.PID()) {
		t.Errorf("terminal query %q", q)
	}
	var script fakeFile
	for k, v := range f.files {
		if strings.HasSuffix(k, "/start.sh") {
			script = v
		}
	}
	for _, want := range []string{"stty raw -echo || exit 97", "export SECRET_ISH='a'\\''b'", "cd -- '/work dir' || exit 96", "'--run' 'it'\\''s' 2>>"} {
		if !strings.Contains(string(script.data), want) {
			t.Errorf("start script lacks %q:\n%s", want, script.data)
		}
	}
	// Everything the program writes comes through unchanged; the banner,
	// prompt and echo before the marker never do.
	var mu sync.Mutex
	var got []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, err := p.Read(buf)
			mu.Lock()
			got = append(got, buf[:n]...)
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	big := bytes.Repeat([]byte("0123456789abcdef"), 6<<10) // 96 KiB: several messages
	payload := append(append([]byte("line one\n"), big...), "\nbye\n"...)
	if _, err := p.Write(payload); err != nil {
		t.Fatal(err)
	}
	code, err := p.Wait(ctx)
	<-readDone
	if code != 3 || err != nil {
		t.Errorf("wait %d %v", code, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(got, payload) {
		t.Errorf("stream carried %d bytes, want %d (prefix %q)", len(got), len(payload), got[:min(len(got), 60)])
	}
	if stderr.String() != "relay: started\n" {
		t.Errorf("stderr %q", stderr.String())
	}
	_ = p.Close()
}

func TestExecStreamStartFailure(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, newSpec("r"))
	if err != nil {
		t.Fatal(err)
	}
	f.noMarker = true
	if _, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"x"}, Stdin: true}); err == nil || !strings.Contains(err.Error(), "exited 97") {
		t.Fatalf("start failure: %v", err)
	}
	if _, err := c.Exec(ctx, "m_missing", sandboxremote.ExecSpec{Argv: []string{"x"}, Stdin: true}); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Fatalf("missing box: %v", err)
	}
}

func TestExecStreamKillAndEndStream(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, newSpec("r"))
	if err != nil {
		t.Fatal(err)
	}
	f.shell = func(in <-chan []byte, out func([]byte), exit func(int)) {
		for range in { // runs until the connection goes
		}
	}
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sleep", "inf"}, Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Resize(ctx, 24, 80); !errors.Is(err, sandboxremote.ErrNotSupported) {
		t.Errorf("resize: %v", err)
	}
	if _, ok := p.(sandboxremote.HalfCloser); ok {
		t.Error("a raw PTY has no stdin half-close; the stream must not claim one")
	}
	if err := sandboxremote.EndStream(ctx, p, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	var kill *fakeExec
	for i := range f.execs {
		if len(f.execs[i].Argv) == 5 && f.execs[i].Argv[2] == killScript {
			kill = &f.execs[i]
		}
	}
	if kill == nil || !strings.HasSuffix(kill.Argv[4], "/pid") {
		t.Fatalf("no kill by the recorded pid: %+v", f.execs)
	}
	if _, err := p.Wait(ctx); err == nil {
		t.Error("a killed stream reported an exit status")
	}
}

func TestWriteAndReadFiles(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, newSpec("r"))
	if err != nil {
		t.Fatal(err)
	}
	open := func(s string) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
	}
	err = c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{
		{Path: "/w/a.sh", Mode: 0o755, Size: 5, Open: open("hello")},
		{Path: "/w/b", Open: open("")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a := f.files[info.ID+":/w/a.sh"]; string(a.data) != "hello" || a.mode != "0755" {
		t.Errorf("a.sh %+v", a)
	}
	if b := f.files[info.ID+":/w/b"]; b.mode != "0644" {
		t.Errorf("b %+v", b)
	}
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: "/w/c", Size: 2, Open: open("grown")}}); err == nil {
		t.Error("a file that grew while uploading was sent")
	}
	if err := c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{{Path: "w/../x", Open: open("")}}); err == nil {
		t.Error("an unclean path was sent")
	}
	if b, err := c.ReadFile(ctx, info.ID, "/w/a.sh", 10); err != nil || string(b) != "hello" {
		t.Errorf("read %q %v", b, err)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/w/a.sh", 3); err == nil {
		t.Error("an oversize read was accepted")
	}
	if _, err := c.ReadFile(ctx, info.ID, "/nope", 10); !errors.Is(err, sandboxremote.ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
}
