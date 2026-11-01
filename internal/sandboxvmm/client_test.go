package sandboxvmm

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// fakeVMM serves recorded answers on a unix socket and records the calls.
type fakeVMM struct {
	mu      sync.Mutex
	calls   []string
	bodies  map[string]string
	answers map[string]func(w http.ResponseWriter)
}

func recorded(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonAnswer(b []byte) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vmm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func startFake(t *testing.T, f *fakeVMM) Dialer {
	t.Helper()
	sock := filepath.Join(shortTemp(t), "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := strings.TrimPrefix(r.URL.Path, apiPrefix)
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+op)
		if f.bodies == nil {
			f.bodies = map[string]string{}
		}
		f.bodies[op] = string(b)
		ans := f.answers[op]
		f.mu.Unlock()
		if ans == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ans(w)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}
}

func testPlan(dir string) sandboxvm.Plan {
	return sandboxvm.Plan{
		RunID: "run-1", StateDir: "/home/u/.observer/sandbox-vm/runs/run-1",
		Kernel: "/home/u/.observer/sandbox-vm/runs/run-1/img/vmlinuz", Initramfs: "/home/u/.observer/sandbox-vm/runs/run-1/img/initrd.img",
		Rootfs: "/home/u/.observer/sandbox-vm/runs/run-1/img/rootfs.img", Verity: "/home/u/.observer/sandbox-vm/runs/run-1/img/rootfs.verity",
		VerityRootHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", CID: 7, GuestPort: sandboxvm.DefaultGuestPort, VCPUs: 2, MemoryMiB: 4096,
		Shares: []sandboxvm.Share{
			{Tag: sandboxvm.BootTag, Socket: "/home/u/.observer/sandbox-vm/runs/run-1/fs-obsboot.sock"},
			{Tag: sandboxvm.WorkspaceTag, Socket: "/home/u/.observer/sandbox-vm/runs/run-1/fs-ws.sock"},
		},
	}
}

// TestClientLifecycleOnRecordedAnswers: the full call sequence against the
// recorded answers, and the vm.info answer passes the read-back.
func TestClientLifecycleOnRecordedAnswers(t *testing.T) {
	f := &fakeVMM{answers: map[string]func(http.ResponseWriter){
		"vmm.ping": jsonAnswer(recorded(t, "vmm_ping.json")), "vm.create": noContent, "vm.boot": noContent,
		"vm.info": jsonAnswer(recorded(t, "vm_info_running.json")), "vm.shutdown": noContent, "vm.delete": noContent, "vmm.shutdown": noContent,
	}}
	c, err := New(startFake(t, f))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, err := c.Ping(ctx)
	if err != nil || p.Version != "54.0.0" || p.PID != 4242 {
		t.Fatalf("ping %+v %v", p, err)
	}
	plan := testPlan("")
	if err := c.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := c.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := sandboxvm.ReadBack(plan, info, true); !v.OK() {
		t.Fatalf("read-back %+v", v)
	}
	for _, step := range []func(context.Context) error{c.Shutdown, c.Delete, c.ShutdownVMM} {
		if err := step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	want := "GET vmm.ping,PUT vm.create,PUT vm.boot,GET vm.info,PUT vm.shutdown,PUT vm.delete,PUT vmm.shutdown"
	if got := strings.Join(f.calls, ","); got != want {
		t.Fatalf("calls %s", got)
	}
	want2, _ := sandboxvm.CreateBody(plan)
	if f.bodies["vm.create"] != string(want2) {
		t.Fatalf("create body %s", f.bodies["vm.create"])
	}
}

// TestClientRefusesUnknownAndMalformedAnswers is one case per refusal.
func TestClientRefusesUnknownAndMalformedAnswers(t *testing.T) {
	cases := []struct {
		name string
		op   string
		ans  func(http.ResponseWriter)
		run  func(*Client) error
		want func(error) bool
	}{
		{
			"create 500", "vm.create", func(w http.ResponseWriter) { w.WriteHeader(500); _, _ = w.Write([]byte("VmCreate(InvalidDisk)")) },
			func(c *Client) error { return c.Create(context.Background(), testPlan("")) },
			func(err error) bool {
				var a *APIError
				return errors.As(err, &a) && a.Status == 500 && strings.Contains(a.Message, "InvalidDisk")
			},
		},
		{
			"boot 200 is not the documented 204", "vm.boot", jsonAnswer([]byte(`{}`)),
			func(c *Client) error { return c.Boot(context.Background()) },
			func(err error) bool { var a *APIError; return errors.As(err, &a) && a.Status == 200 },
		},
		{
			"a plain 204 delete passes", "vm.delete", func(w http.ResponseWriter) { w.WriteHeader(204) },
			func(c *Client) error { return c.Delete(context.Background()) },
			func(err error) bool { return err == nil },
		},
		{
			"info not json", "vm.info", jsonAnswer([]byte(`{"config":`)),
			func(c *Client) error { _, err := c.Info(context.Background()); return err },
			func(err error) bool { return errors.Is(err, ErrMalformed) },
		},
		{
			"info oversized", "vm.info", jsonAnswer([]byte(`"` + strings.Repeat("a", maxBody) + `"`)),
			func(c *Client) error { _, err := c.Info(context.Background()); return err },
			func(err error) bool { return errors.Is(err, ErrMalformed) },
		},
		{
			"ping without a pid", "vmm.ping", jsonAnswer([]byte(`{"version":"54.0.0"}`)),
			func(c *Client) error { _, err := c.Ping(context.Background()); return err },
			func(err error) bool { return errors.Is(err, ErrMalformed) },
		},
		{
			"an unknown endpoint", "", nil,
			func(c *Client) error { return c.Shutdown(context.Background()) },
			func(err error) bool { var a *APIError; return errors.As(err, &a) && a.Status == 404 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVMM{answers: map[string]func(http.ResponseWriter){}}
			if tc.op != "" {
				f.answers[tc.op] = tc.ans
			}
			c, _ := New(startFake(t, f))
			if err := tc.run(c); !tc.want(err) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// fakeVsock serves the VMM's hybrid vsock socket: it reads the CONNECT
// line and answers with answer (closing with zero bytes when empty), then
// echoes what follows.
func fakeVsock(t *testing.T, answer string) VsockDialer {
	t.Helper()
	sock := filepath.Join(shortTemp(t), "vsock.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil || !strings.EqualFold(strings.Fields(line)[0], "CONNECT") {
					return
				}
				if answer == "" {
					return
				}
				if answer == "hang" {
					time.Sleep(10 * time.Second)
					return
				}
				_, _ = c.Write([]byte(answer + "guest-hello"))
			}(c)
		}
	}()
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}
}

func TestDialVsock(t *testing.T) {
	c, port, err := DialVsock(context.Background(), fakeVsock(t, "OK 1073741830\n"), 1024)
	if err != nil || port != 1073741830 {
		t.Fatalf("%d %v", port, err)
	}
	b := make([]byte, len("guest-hello"))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "guest-hello" {
		t.Fatalf("after the answer: %q %v", b, err)
	}
	_ = c.Close()
	if _, _, err := DialVsock(context.Background(), fakeVsock(t, ""), 1024); !errors.Is(err, sandboxvm.ErrVsockRefused) {
		t.Fatalf("a refused port: %v", err)
	}
	if _, _, err := DialVsock(context.Background(), fakeVsock(t, "NO\n"), 1024); !errors.Is(err, sandboxvm.ErrVsockMalformed) {
		t.Fatalf("a malformed answer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := DialVsock(ctx, fakeVsock(t, "hang"), 1024); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("a VMM that never answers: %v after %s", err, time.Since(start))
	}
}
