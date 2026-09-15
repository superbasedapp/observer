package sshforward

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sshprofile"
)

// osSpawner runs the composed argv as a direct child process.
//
// The argv is passed as a SLICE to exec.Command — never joined into a string,
// never handed to a shell. That is the other half of sshprofile's
// flag-injection defence: rejecting a leading '-' only helps if nothing later
// re-parses the tokens.
type osSpawner struct{}

// NewOSSpawner returns the default Spawner.
func NewOSSpawner() Spawner { return osSpawner{} }

// Spawn starts the child with no stdin and a bounded stderr capture.
func (osSpawner) Spawn(argv []string) (Process, error) {
	if len(argv) == 0 {
		return nil, errors.New("sshforward: empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv is composed by sshprofile from operator config, never from a request
	// No stdin: with BatchMode=yes there is nothing to answer, and leaving the
	// daemon's own stdin attached would let a child consume it.
	cmd.Stdin = nil
	cmd.Stdout = nil
	tail := &tailBuffer{}
	cmd.Stderr = tail
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &osProcess{cmd: cmd, tail: tail}, nil
}

// osProcess adapts *exec.Cmd to the Process seam.
type osProcess struct {
	cmd  *exec.Cmd
	tail *tailBuffer

	waitOnce sync.Once
	waitErr  error
	done     chan struct{}
	initOnce sync.Once
}

// Wait blocks for the child. exec.Cmd.Wait must be called exactly once, so it
// is memoized and every caller gets the same result.
func (p *osProcess) Wait() error {
	p.initOnce.Do(func() { p.done = make(chan struct{}) })
	p.waitOnce.Do(func() {
		p.waitErr = p.cmd.Wait()
		close(p.done)
	})
	<-p.done
	return p.waitErr
}

// Stop kills the child. A forward carries no state to flush, so there is
// nothing a graceful signal would preserve. Already-exited is not an error.
func (p *osProcess) Stop() error {
	if p.cmd.Process == nil {
		return nil
	}
	if err := p.cmd.Process.Kill(); err != nil {
		if errors.Is(err, exec.ErrWaitDelay) || strings.Contains(err.Error(), "process already finished") {
			return nil
		}
		return err
	}
	return nil
}

// StderrTail returns the bounded stderr capture.
func (p *osProcess) StderrTail() string { return p.tail.String() }

// tailBuffer keeps the LAST tailBytes of a stream. ssh writes its most
// diagnostic line ("Host key verification failed", "Permission denied") last,
// so keeping the tail beats keeping the head.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

const tailBytes = 4096

// Write implements io.Writer, retaining only the trailing window.
func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailBytes {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-tailBytes:]...)
	}
	return len(p), nil
}

// String returns a copy of the retained tail.
func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// allocLoopbackPort picks a free port by binding :0 on loopback and releasing
// it. There is a small window between release and ssh's own bind; losing it
// makes ssh exit (ExitOnForwardFailure=yes) and the operator retries, which is
// strictly better than the alternative — `-L 0:` does not report the port
// OpenSSH chose, leaving nothing honest to show the operator.
func allocLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(sshprofile.ForwardBindAddr, "0"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("sshforward: unexpected listener address type")
	}
	return addr.Port, nil
}

// probeLoopbackPort reports whether the forward is accepting connections yet.
func probeLoopbackPort(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(sshprofile.ForwardBindAddr, strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
}

// knownHostsProbeTimeout bounds each pre-flight exec. Both commands are local
// and connect to nothing, so this is generous.
const knownHostsProbeTimeout = 5 * time.Second

// NewOSKnownHostsChecker returns the default KnownHostsFunc: resolve the
// destination through the operator's own ~/.ssh/config (`ssh -G`, which
// connects to nothing), then ask `ssh-keygen -F` whether that hostname is in
// known_hosts.
//
// The alias resolution is the reason for the first step. A profile Host is
// often a ~/.ssh/config alias, and asking known_hosts about the alias would
// report a perfectly trusted machine as unknown. Any failure along the way
// yields checked=false — no verdict — so ssh remains the enforcement and the
// pre-flight can only ever improve an error message, never invent a refusal.
func NewOSKnownHostsChecker() KnownHostsFunc {
	return func(p sshprofile.Profile) (bool, bool) {
		host, port, ok := resolveDestination(p)
		if !ok {
			return false, false
		}
		spec := host
		if port != 0 && port != 22 {
			spec = "[" + host + "]:" + strconv.Itoa(port)
		}
		ctx, cancel := context.WithTimeout(context.Background(), knownHostsProbeTimeout)
		defer cancel()
		// ssh-keygen -F exits 0 when the host has a known_hosts entry and 1
		// when it does not. It understands HASHED entries, which is why we ask
		// it rather than parsing the file.
		cmd := exec.CommandContext(ctx, "ssh-keygen", "-F", spec) // #nosec G204 -- spec derives from `ssh -G` output for an operator-authored, validated profile
		err := cmd.Run()
		if err == nil {
			return true, true
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, true
		}
		return false, false // ssh-keygen missing or errored: no verdict
	}
}

// testRunnerTimeout bounds the whole probe process, on top of TestArgv's own
// baked-in `ConnectTimeout=5` (which only bounds the TCP/handshake phase). A
// generous belt-and-suspenders ceiling so a slow-but-connected exchange still
// reports back honestly instead of hanging the CLI/API caller.
const testRunnerTimeout = 15 * time.Second

// NewOSTestRunner returns the default TestRunnerFunc: run argv as a direct
// child (no shell, matching osSpawner), bounded by testRunnerTimeout, with no
// stdin (BatchMode=yes has nothing to prompt for) and a bounded stderr
// capture.
func NewOSTestRunner() TestRunnerFunc {
	return func(argv []string) (bool, string, error) {
		if len(argv) == 0 {
			return false, "", errors.New("sshforward: empty argv")
		}
		ctx, cancel := context.WithTimeout(context.Background(), testRunnerTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv is sshprofile.TestArgv, composed from operator config, never -L/-R/-D/-w
		cmd.Stdin = nil
		tail := &tailBuffer{}
		cmd.Stdout = nil
		cmd.Stderr = tail
		err := cmd.Run()
		if err == nil {
			return true, tail.String(), nil
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// The probe ran and ssh reported a non-zero exit (auth failure,
			// host-key rejection, unreachable host, etc). That is an honest
			// result, not an error the caller failed to attempt.
			return false, tail.String(), nil
		}
		return false, tail.String(), err
	}
}

// resolveDestination runs `ssh -G` and reads back the effective hostname/port.
func resolveDestination(p sshprofile.Profile) (host string, port int, ok bool) {
	argv, err := sshprofile.ResolveArgv(p)
	if err != nil {
		return "", 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), knownHostsProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv composed by sshprofile from operator config
	out, err := cmd.Output()
	if err != nil {
		return "", 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "hostname":
			host = fields[1]
		case "port":
			if n, convErr := strconv.Atoi(fields[1]); convErr == nil {
				port = n
			}
		}
	}
	if host == "" {
		return "", 0, false
	}
	return host, port, true
}
