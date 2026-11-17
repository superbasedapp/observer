package daytona

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// live_test.go is the client-level live smoke of the daytona row: one box
// against a real Daytona account. It never runs by default: it needs
// SBO_DAYTONA_LIVE=1 and SBO_DAYTONA_ENV_FILE naming a .env file, from which
// it reads exactly two names (the API key and, optionally, the API URL) and
// nothing else; their values are never logged. Every box it creates carries
// its own run label and is deleted, by id and by label, whatever happens.

// liveEnv reads the two names from the env file.
func liveEnv(t *testing.T) (key, endpoint string) {
	t.Helper()
	if os.Getenv("SBO_DAYTONA_LIVE") != "1" {
		t.Skip("live Daytona smoke: set SBO_DAYTONA_LIVE=1 and SBO_DAYTONA_ENV_FILE")
	}
	f, err := os.Open(os.Getenv("SBO_DAYTONA_ENV_FILE"))
	if err != nil {
		t.Fatal("the env file does not open")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(strings.TrimPrefix(name, "export "))
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch name {
		case "DAYTONA_API_KEY":
			key = val
		case "DAYTONA_API_URL":
			endpoint = val
		}
	}
	if key == "" {
		t.Fatal("the env file has no API key")
	}
	if endpoint == "" {
		v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
		endpoint = v.DefaultEndpoint
	}
	return key, endpoint
}

// runCmd runs argv in the box and returns its stdout and exit code.
func runCmd(ctx context.Context, c *Client, id string, spec sandboxremote.ExecSpec) (string, int, error) {
	p, err := c.Exec(ctx, id, spec)
	if err != nil {
		return "", -1, err
	}
	defer p.Close()
	out, _ := io.ReadAll(io.LimitReader(p, 64<<10))
	code, err := p.Wait(ctx)
	return string(out), code, err
}

func TestLiveSmoke(t *testing.T) {
	key, endpoint := liveEnv(t)
	c, err := New(Options{Endpoint: endpoint, Key: key})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	run := "smoke-" + hex.EncodeToString(b[:])
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	var created []string
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer ccancel()
		ids := append([]string(nil), created...)
		if boxes, err := c.ListByLabel(cctx, sandboxremote.LabelKey, run); err == nil {
			for _, bx := range boxes {
				ids = append(ids, bx.ID)
			}
		}
		ids = append(ids, BoxName(run))
		for _, id := range ids {
			if err := c.Delete(cctx, id); err != nil && !errors.Is(err, sandboxremote.ErrNotFound) {
				t.Logf("cleanup delete %s: %v", id, err)
			}
		}
		for i := 0; i < 10; i++ {
			left, err := c.ListByLabel(cctx, sandboxremote.LabelKey, run)
			if err == nil && len(left) == 0 {
				t.Logf("cleanup: no box labelled %s is listed", run)
				return
			}
			time.Sleep(3 * time.Second)
		}
		t.Errorf("cleanup: boxes labelled %s may remain; check the Daytona dashboard", run)
	})

	start := time.Now()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: run, TimeoutSeconds: 600, Tier: vocab.TierNone, Labels: map[string]string{"observer-smoke": "1"}})
	if err != nil {
		t.Fatalf("create (tier none): %v", err)
	}
	created = append(created, info.ID)
	t.Logf("created box %s (name %s) in %s, running=%v, region=%q, deadline=%s", info.ID, BoxName(run), time.Since(start).Round(time.Millisecond), info.Running, info.Region, info.Deadline.UTC().Format(time.RFC3339))

	for !info.Running {
		if ctx.Err() != nil {
			t.Fatal("the box never reached started")
		}
		time.Sleep(2 * time.Second)
		if info, err = c.Get(ctx, info.ID); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	t.Logf("running after %s", time.Since(start).Round(time.Millisecond))

	// The raw sandbox: what the create asked for, as the vendor recorded it.
	var raw map[string]any
	if err := c.doJSON(ctx, request{method: "GET", url: c.apiURL("/sandbox/"+info.ID, nil)}, nil, &raw); err == nil {
		for _, k := range []string{"state", "target", "user", "sandboxClass", "snapshot", "cpu", "memory", "disk", "networkBlockAll", "public", "autoStopInterval", "autoDeleteInterval", "autoArchiveInterval", "autoDestroyAt", "daemonVersion"} {
			t.Logf("sandbox.%s = %v", k, raw[k])
		}
	}

	// Who runs a process, where its home is, and whether sudo needs a
	// password.
	t0 := time.Now()
	out, code, err := runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", `id -un; id -u; echo "$HOME"; sudo -n true && echo sudo-ok || echo sudo-no`}})
	t.Logf("identity exec (first, dials SSH) in %s: code %d err %v out %q", time.Since(t0).Round(time.Millisecond), code, err, out)
	if err != nil {
		t.Fatalf("first exec: %v", err)
	}
	c.mu.Lock()
	for host, k := range c.hostKeys {
		if pk, perr := ssh.ParsePublicKey(k); perr == nil {
			t.Logf("SSH gateway %s host key %s %s", host, pk.Type(), ssh.FingerprintSHA256(pk))
		}
	}
	c.mu.Unlock()

	t0 = time.Now()
	out, code, err = runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"uname", "-a"}})
	t.Logf("uname -a in %s: code %d err %v out %q", time.Since(t0).Round(time.Millisecond), code, err, out)
	if err != nil || code != 0 || !strings.Contains(out, "Linux") {
		t.Errorf("uname -a: code %d err %v", code, err)
	}

	out, code, err = runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", "echo to-stderr >&2; exit 3"}})
	t.Logf("non-zero exit: code %d err %v out %q", code, err, out)
	if err != nil || code != 3 {
		t.Errorf("non-zero exit: code %d err %v", code, err)
	}

	out, code, err = runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"id", "-u"}, AsRoot: true})
	t.Logf("as root (sudo -n): code %d err %v out %q", code, err, out)

	// A streaming stdin with its close (the relay's shape), and stderr
	// separate.
	var errBuf lockedBuffer
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", "echo relay-stderr >&2; cat"}, Stdin: true, Stderr: &errBuf})
	if err != nil {
		t.Fatalf("stdin exec: %v", err)
	}
	if _, err := p.Write([]byte("aGVsbG8=\n")); err != nil {
		t.Errorf("stdin write: %v", err)
	}
	if hc, ok := p.(sandboxremote.HalfCloser); ok {
		_ = hc.CloseWrite()
	}
	echo, _ := io.ReadAll(io.LimitReader(p, 4096))
	code, err = p.Wait(ctx)
	_ = p.Close()
	t.Logf("stdin echo: %q, stderr %q, code %d err %v", echo, errBuf.String(), code, err)
	if string(echo) != "aGVsbG8=\n" || code != 0 {
		t.Errorf("stdin echo: %q code %d", echo, code)
	}

	// Kill a running process.
	kp, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"sleep", "120"}})
	if err == nil {
		time.Sleep(time.Second)
		kerr := kp.Kill(ctx)
		wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
		kcode, werr := kp.Wait(wctx)
		wcancel()
		t.Logf("kill: err %v; wait code %d err %v", kerr, kcode, werr)
	}

	// Files: upload with a mode, read back, and the home directory.
	home := "/home/daytona/observer-smoke/hello.txt"
	content := "hello from observer " + run + "\n"
	t0 = time.Now()
	err = c.WriteFiles(ctx, info.ID, []sandboxremote.UploadFile{
		{Path: home, Mode: 0o640, Size: int64(len(content)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil }},
	})
	t.Logf("upload in %s: %v", time.Since(t0).Round(time.Millisecond), err)
	if err == nil {
		got, rerr := c.ReadFile(ctx, info.ID, home, 1024)
		t.Logf("read back: %q err %v", got, rerr)
		if string(got) != content {
			t.Errorf("read back differs")
		}
		out, _, _ = runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"stat", "-c", "%a %U:%G", home}})
		t.Logf("uploaded file mode and owner: %q", out)
	}
	if _, err := c.ReadFile(ctx, info.ID, "/nonexistent/observer", 64); err != nil {
		t.Logf("missing file: %v (not found: %v)", err, errors.Is(err, sandboxremote.ErrNotFound))
	}

	// Network on the none tier.
	out, code, _ = runCmd(ctx, c, info.ID, sandboxremote.ExecSpec{Argv: []string{"sh", "-c", "getent hosts example.com >/dev/null && echo dns-ok || echo dns-blocked; (curl -s -m 5 -o /dev/null -w '%{http_code}' https://example.com || wget -q -T 5 -O /dev/null https://example.com && echo fetched) 2>&1 | tail -c 200"}})
	t.Logf("network on none: code %d out %q", code, out)

	// Listed by label, then deleted and confirmed.
	listed, err := c.ListByLabel(ctx, sandboxremote.LabelKey, run)
	t.Logf("listed by label: %d boxes, err %v", len(listed), err)
	t0 = time.Now()
	if err := c.Delete(ctx, info.ID); err != nil {
		t.Errorf("delete: %v", err)
	}
	for i := 0; i < 20; i++ {
		g, gerr := c.Get(ctx, info.ID)
		if errors.Is(gerr, sandboxremote.ErrNotFound) || (gerr == nil && !g.Running) {
			t.Logf("delete confirmed after %s (get: running=%v err=%v state=%s)", time.Since(t0).Round(time.Millisecond), g.Running, gerr, g.Extra["state"])
			break
		}
		time.Sleep(time.Second)
	}
}
