package dockersbx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestLiveSmoke is the client-level live smoke against a real Docker
// account (lane SBX-DOCKER). It runs only with SBO_DOCKER_SANDBOXES_LIVE=1
// and the row's two variables in the environment, and creates ONE box at
// the micro size with the run label, the keep-alive start command, a short
// delete-on-timeout deadline and the deny-all policy. A deferred cleanup
// deletes every box it created or that carries its label, even on failure.
// It never prints a credential: the client redacts every error.
//
// SBO_DOCKER_SANDBOXES_LIVE_LONG=1 also holds a process stream open past
// the five-minute endpoint grant.
func TestLiveSmoke(t *testing.T) {
	if os.Getenv("SBO_DOCKER_SANDBOXES_LIVE") != "1" {
		t.Skip("live smoke: set SBO_DOCKER_SANDBOXES_LIVE=1 with the row's variables")
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDockerSandboxes)
	access, id := os.Getenv(v.EnvCredential[0]), os.Getenv(v.EnvCredential[1])
	if access == "" || id == "" {
		t.Fatal("the row's two variables are not set")
	}
	c, err := New(Options{Endpoint: v.DefaultEndpoint, DockerID: id, Access: access, CPUs: 1, MemoryMiB: 2048})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
	defer cancel()
	run := "smoke-" + strconv.FormatInt(time.Now().Unix(), 10)
	t.Logf("run label %s=%s", sandboxremote.LabelKey, run)
	var created []string
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer ccancel()
		ids := append([]string(nil), created...)
		if boxes, lerr := c.ListByLabel(cctx, sandboxremote.LabelKey, run); lerr == nil {
			for _, b := range boxes {
				ids = append(ids, b.ID)
			}
		} else {
			t.Logf("cleanup list: %v", lerr)
		}
		seen := map[string]bool{}
		for _, b := range ids {
			if seen[b] {
				continue
			}
			seen[b] = true
			err := c.Delete(cctx, b)
			t.Logf("cleanup delete %s: %v", b, err)
			for i := 0; i < 60; i++ {
				info, gerr := c.Get(cctx, b)
				if errors.Is(gerr, sandboxremote.ErrNotFound) {
					t.Logf("cleanup: %s gone (not found) after %d reads", b, i+1)
					break
				}
				if gerr == nil && i == 0 {
					t.Logf("cleanup: %s status %s", b, info.Extra["status"])
				}
				time.Sleep(2 * time.Second)
			}
		}
		left, lerr := c.ListByLabel(cctx, sandboxremote.LabelKey, run)
		t.Logf("cleanup: boxes left with the run label: %d (%v)", len(left), lerr)
		for _, b := range left {
			t.Logf("  left: %s status %s", b.ID, b.Extra["status"])
		}
	}()

	step := func(name string, start time.Time) {
		t.Logf("%-28s %s", name, time.Since(start).Round(time.Millisecond))
	}

	t0 := time.Now()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 900, Tier: vocab.TierNone})
	if info.ID != "" {
		created = append(created, info.ID)
	}
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	step("create until running", t0)
	t.Logf("box %s running=%v status=%s deadline=%s labels=%v", info.ID, info.Running, info.Extra["status"], info.Deadline.Format(time.RFC3339), info.Labels)
	c.mu.Lock()
	base := c.uris[info.ID]
	c.mu.Unlock()
	if u, perr := url.Parse(base); perr == nil {
		t.Logf("box endpoint: scheme %s host %s path %s", u.Scheme, u.Host, u.Path)
	}

	logPolicy(ctx, t, c, "/v1/sandboxes/"+url.PathEscape(info.ID)+"/network-policies", "box policy")
	logPolicy(ctx, t, c, "/v1/network-policies", "account policy")

	run1 := func(name string, argv []string, wantCode int) (string, string) {
		t.Helper()
		ts := time.Now()
		var errBuf bytes.Buffer
		p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: argv, Env: map[string]string{"HOME": "/root"}, Stderr: &errBuf})
		if err != nil {
			t.Errorf("%s: exec: %v", name, err)
			return "", ""
		}
		out, _ := io.ReadAll(io.LimitReader(p, 1<<20))
		code, werr := p.Wait(ctx)
		step(name, ts)
		t.Logf("  %s: exit %d (%v) stdout %q stderr %q", name, code, werr, strings.TrimSpace(string(out)), strings.TrimSpace(errBuf.String()))
		if werr != nil || code != wantCode {
			t.Errorf("%s: exit %d %v, want %d", name, code, werr, wantCode)
		}
		return string(out), errBuf.String()
	}

	ts := time.Now()
	files := []sandboxremote.UploadFile{{Path: "/root/smoke/hello.txt", Mode: 0o644, Size: 12, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("hello docker")), nil
	}}}
	if err := c.WriteFiles(ctx, info.ID, files); err != nil {
		t.Errorf("write: %v", err)
	}
	step("write file", ts)
	ts = time.Now()
	got, err := c.ReadFile(ctx, info.ID, "/root/smoke/hello.txt", 1024)
	step("read file", ts)
	if err != nil || string(got) != "hello docker" {
		t.Errorf("read back %q %v", got, err)
	}

	run1("uname -a", []string{"uname", "-a"}, 0)
	run1("id", []string{"id"}, 0)
	run1("stat file", []string{"stat", "-c", "%a %U %s", "/root/smoke/hello.txt"}, 0)
	run1("tools", []string{"sh", "-c", "for x in sh git sha256sum gzip curl node npm uname; do command -v $x >/dev/null && printf '%s ' $x; done; echo"}, 0)
	run1("non-zero exit", []string{"sh", "-c", "echo to-stderr >&2; exit 7"}, 7)
	run1("egress https (none tier)", []string{"sh", "-c", "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://example.com; echo \" rc=$?\""}, 0)
	run1("egress metadata (none tier)", []string{"sh", "-c", "curl -sS -m 5 -o /dev/null -w '%{http_code}' http://169.254.169.254/; echo \" rc=$?\""}, 0)
	run1("egress by IP (none tier)", []string{"sh", "-c", "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://1.1.1.1/; echo \" rc=$?\""}, 0)
	run1("egress github (none tier)", []string{"sh", "-c", "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://github.com/; echo \" rc=$?\""}, 0)
	run1("egress npm (none tier)", []string{"sh", "-c", "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/; echo \" rc=$?\""}, 0)
	run1("egress private (none tier)", []string{"sh", "-c", "curl -sS -m 4 -o /dev/null -w '%{http_code}' http://10.0.0.1/; echo \" rc=$?\""}, 0)
	run1("dns (none tier)", []string{"sh", "-c", "getent hosts example.com; echo rc=$?"}, 0)
	run1("pid 1", []string{"sh", "-c", "cat /proc/1/cmdline | tr '\\0' ' '"}, 0)

	// A kill: a sleep killed through the signal endpoint ends with no
	// clean exit.
	ts = time.Now()
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sleep", "300"}})
	if err != nil {
		t.Errorf("kill: exec: %v", err)
	} else {
		if err := p.Kill(ctx); err != nil {
			t.Errorf("kill: %v", err)
		}
		wctx, wcancel := context.WithTimeout(ctx, time.Minute)
		code, werr := p.Wait(wctx)
		wcancel()
		step("kill", ts)
		t.Logf("  kill: exit %d (%v)", code, werr)
		if werr != nil || code == 0 {
			t.Errorf("kill: exit %d %v", code, werr)
		}
	}

	// A PTY with a resize.
	ts = time.Now()
	tp, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", "stty size; read x; echo got:$x; stty size"}, PTY: true, Rows: 24, Cols: 80, Env: map[string]string{"TERM": "xterm"}})
	if err != nil {
		t.Errorf("pty: exec: %v", err)
	} else {
		time.Sleep(time.Second)
		if err := tp.Resize(ctx, 40, 120); err != nil {
			t.Errorf("pty resize: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		_, _ = tp.Write([]byte("abc\r"))
		out, _ := io.ReadAll(io.LimitReader(tp, 1<<16))
		code, werr := tp.Wait(ctx)
		step("pty", ts)
		t.Logf("  pty: exit %d (%v) output %q", code, werr, string(out))
	}

	// Box still running (the keep-alive start command).
	if g, err := c.Get(ctx, info.ID); err == nil {
		t.Logf("box status after the execs: %s running=%v", g.Extra["status"], g.Running)
	}

	if os.Getenv("SBO_DOCKER_SANDBOXES_LIVE_LONG") == "1" {
		// A pipe process held open past the five-minute endpoint grant.
		ts = time.Now()
		lp, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true})
		if err != nil {
			t.Errorf("long: exec: %v", err)
		} else {
			if _, err := lp.Write([]byte("first\n")); err != nil {
				t.Errorf("long: write: %v", err)
			}
			buf := make([]byte, 6)
			_, rerr := io.ReadFull(lp, buf)
			t.Logf("  long: first echo %q %v", buf, rerr)
			time.Sleep(330 * time.Second)
			_, werr := lp.Write([]byte("second\n"))
			buf = make([]byte, 7)
			rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
			done := make(chan error, 1)
			go func() { _, e := io.ReadFull(lp, buf); done <- e }()
			select {
			case rerr = <-done:
			case <-rctx.Done():
				rerr = rctx.Err()
			}
			rcancel()
			pp := lp.(*process)
			pp.mu.Lock()
			re := pp.reattaches
			pp.mu.Unlock()
			step("long stream", ts)
			t.Logf("  long: after %s: write %v, echo %q %v, stream re-attaches %d", 330*time.Second, werr, buf, rerr, re)
			_ = lp.Kill(ctx)
			_ = lp.Close()
		}
	}

	ts = time.Now()
	if err := c.Delete(ctx, info.ID); err != nil {
		t.Errorf("delete: %v", err)
	}
	for i := 0; i < 60; i++ {
		g, err := c.Get(ctx, info.ID)
		if errors.Is(err, sandboxremote.ErrNotFound) {
			step("delete until not found", ts)
			break
		}
		if err == nil && i%5 == 0 {
			t.Logf("  after delete: status %s", g.Extra["status"])
		}
		time.Sleep(2 * time.Second)
	}
}

// logPolicy reads an effective network policy (GetNetworkPolicies) and logs
// its mode and attributed rules (destinations and layers, never a value
// that authorizes anything).
func logPolicy(ctx context.Context, t *testing.T, c *Client, path, what string) {
	t.Helper()
	var out struct {
		Effective struct {
			Mode          string `json:"mode"`
			AllowNetworks []struct {
				Network string `json:"network"`
				Layer   string `json:"layer"`
			} `json:"allowNetworks"`
			DenyNetworks []struct {
				Network string `json:"network"`
				Layer   string `json:"layer"`
			} `json:"denyNetworks"`
		} `json:"effective"`
	}
	if _, _, err := c.doJSON(ctx, request{plane: planeManagement, method: "GET", path: path, idempotent: true}, nil, &out); err != nil {
		t.Logf("%s: %v", what, err)
		return
	}
	var allow, deny []string
	for _, r := range out.Effective.AllowNetworks {
		allow = append(allow, r.Network+"("+r.Layer+")")
	}
	for _, r := range out.Effective.DenyNetworks {
		deny = append(deny, r.Network+"("+r.Layer+")")
	}
	t.Logf("%s: mode %s, %d allow %v, %d deny %v", what, out.Effective.Mode, len(allow), allow, len(deny), deny)
}
