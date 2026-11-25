//go:build unix

package listenhandover

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// helperMode selects the re-exec helper's role.
const helperMode = "LISTENHANDOVER_HELPER"

// TestHandoverHelper is not a test: it is the daemon stand-in the
// re-exec test runs as a child. Mode "old" binds, serves "old" until it
// reads "restart" on stdin, then does what the daemon's in-place restart
// does (pause, duplicate, shut down, a gap, execve with the socket); mode
// "new" is the re-executed image, which claims the socket and serves "new".
func TestHandoverHelper(t *testing.T) {
	switch os.Getenv(helperMode) {
	case "old":
		helperOld()
	case "new":
		helperNew()
	default:
		t.Skip("helper process only")
	}
}

func helperOld() {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	addr := raw.Addr().String()
	p := NewPausable(raw)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "old")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(p) }()
	fmt.Println("addr", addr)
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		if in.Text() == "restart" {
			break
		}
	}
	p.Pause()
	f, err := Prepare(p)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
	fmt.Println("down")
	// The old image's own shutdown and the new image's start, during which
	// nothing accepts.
	time.Sleep(800 * time.Millisecond)
	env, err := ExecEnv(f, addr, os.Environ())
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	env = append(withoutVar(env, helperMode), helperMode+"=new")
	exe, _ := os.Executable()
	err = syscall.Exec(exe, []string{exe, "-test.run=^TestHandoverHelper$"}, env) //nolint:gosec // re-execs the test binary itself
	fmt.Println("error", err)
	os.Exit(2)
}

func helperNew() {
	in := Claim()
	if in == nil {
		fmt.Println("error no hand-over")
		os.Exit(2)
	}
	if os.Getenv(EnvFD) != "" || os.Getenv(EnvAddr) != "" {
		fmt.Println("error the variables survived Claim")
		os.Exit(2)
	}
	in.mu.Lock()
	flags, ferr := fdFlags(in.file)
	in.mu.Unlock()
	if ferr != nil || flags&unix.FD_CLOEXEC == 0 {
		fmt.Println("error the inherited socket is not close-on-exec after Claim")
		os.Exit(2)
	}
	ln, adopted, err := Listen(in, in.Addr)
	if err != nil || !adopted {
		fmt.Println("error adopt", err, adopted)
		os.Exit(2)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "new")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Println("adopted", os.Getpid())
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// fdFlags reads f's descriptor flags without f.Fd() (which would switch
// the socket to blocking mode).
func fdFlags(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var flags int
	var ferr error
	if err := rc.Control(func(d uintptr) { flags, ferr = unix.FcntlInt(d, unix.F_GETFD, 0) }); err != nil {
		return 0, err
	}
	return flags, ferr
}

func withoutVar(env []string, name string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// TestRestartKeepsThePortAnswering is L-168 (ii)'s restart test: a client
// that connects while the daemon restarts in place (the old image has shut
// down and the new one has not started) is never refused. Its connection
// waits in the socket's backlog and the re-executed image (same pid, a real
// execve) serves it.
func TestRestartKeepsThePortAnswering(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHandoverHelper$") //nolint:gosec // the test binary itself
	cmd.Env = append(withoutVar(os.Environ(), helperMode), helperMode+"=old")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}()
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	next := func(prefix string) string {
		t.Helper()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the helper ended before %q", prefix)
				}
				if strings.HasPrefix(l, "error") {
					t.Fatalf("helper: %s", l)
				}
				if strings.HasPrefix(l, prefix) {
					return strings.TrimSpace(strings.TrimPrefix(l, prefix))
				}
			case <-time.After(20 * time.Second):
				t.Fatalf("no %q from the helper", prefix)
			}
		}
	}
	addr := next("addr")
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	get := func() (string, error) {
		resp, err := client.Get("http://" + addr + "/v1/messages")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if body, err := get(); err != nil || body != "old" {
		t.Fatalf("before the restart: %q %v", body, err)
	}

	if _, err := io.WriteString(stdin, "restart\n"); err != nil {
		t.Fatal(err)
	}
	next("down")
	// The old image no longer accepts and the new one is not up: a client
	// now must wait, not be refused.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("a connection during the restart was refused: %v", err)
		}
		t.Fatalf("dial during the restart: %v", err)
	}
	_ = conn.Close()
	var wg sync.WaitGroup
	results := make(chan string, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := get()
			if err != nil {
				results <- "error: " + err.Error()
				return
			}
			results <- body
		}()
	}
	pid := next("adopted")
	wg.Wait()
	close(results)
	for r := range results {
		if r != "new" {
			t.Errorf("a request made during the restart got %q, want the new image's answer", r)
		}
	}
	if pid != fmt.Sprint(cmd.Process.Pid) {
		t.Errorf("the new image runs as pid %s, want the same pid %d (an in-place re-exec)", pid, cmd.Process.Pid)
	}
}

// TestExecEnvClearsCloseOnExec: the prepared duplicate keeps close-on-exec
// (a child started before the re-exec never inherits it) until ExecEnv.
func TestExecEnvClearsCloseOnExec(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := Prepare(ln)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	flags, err := fdFlags(f)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the prepared socket is not close-on-exec (flags %d, %v)", flags, err)
	}
	env, err := ExecEnv(f, ln.Addr().String(), []string{"A=1"})
	if err != nil {
		t.Fatal(err)
	}
	flags, err = fdFlags(f)
	if err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("ExecEnv left close-on-exec set (flags %d, %v)", flags, err)
	}
	if len(env) != 3 || !strings.HasPrefix(env[1], EnvFD+"=") {
		t.Fatalf("env = %v", env)
	}
}
