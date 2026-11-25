package listenhandover

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// The environment variables of a hand-over. They exist only between the old
// image's execve and the new image's Claim.
const (
	// EnvFD names the inherited descriptor (a decimal number).
	EnvFD = "OBSERVER_PROXY_LISTEN_FD"
	// EnvAddr is the address the socket listens on, as the old image's
	// listener reported it.
	EnvAddr = "OBSERVER_PROXY_LISTEN_ADDR"
)

// ErrUnsupported is a hand-over on an OS without execve.
var ErrUnsupported = errors.New("listenhandover: this operating system cannot pass a listening socket across a re-exec")

// Inherited is a listening socket this process received from the image
// that exec'd it, claimed at process start.
type Inherited struct {
	mu   sync.Mutex
	file *os.File
	// Addr is the address the old image's listener reported.
	Addr string
}

// Take hands the socket to its one consumer (nil when already taken or
// closed).
func (in *Inherited) Take() *os.File {
	if in == nil {
		return nil
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	f := in.file
	in.file = nil
	return f
}

// Close closes the socket when nobody took it, so a port the new image does
// not serve stops listening (a connection then fails at once instead of
// waiting in a backlog nobody accepts). Idempotent.
func (in *Inherited) Close() {
	if f := in.Take(); f != nil {
		_ = f.Close()
	}
}

// claimEnv is Claim's environment and descriptor access, a seam for tests.
type claimEnv struct {
	getenv   func(string) string
	unsetenv func(string) error
	// file turns a descriptor number into a file, marking it
	// close-on-exec; nil when the number names no open descriptor.
	file func(fd int) *os.File
}

// Claim reads the hand-over variables at process start. It must run before
// this process starts any child: the descriptor arrives without
// close-on-exec, so Claim sets it again, and it removes both variables so no
// child sees them. nil when there is no hand-over (or a broken one, whose
// descriptor is then left alone: a number that does not parse names nothing
// this package opened).
func Claim() *Inherited {
	return claimFrom(claimEnv{getenv: os.Getenv, unsetenv: os.Unsetenv, file: inheritedFile})
}

func claimFrom(e claimEnv) *Inherited {
	raw := strings.TrimSpace(e.getenv(EnvFD))
	addr := strings.TrimSpace(e.getenv(EnvAddr))
	if raw == "" && addr == "" {
		return nil
	}
	_ = e.unsetenv(EnvFD)
	_ = e.unsetenv(EnvAddr)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 || addr == "" {
		return nil
	}
	f := e.file(fd)
	if f == nil {
		return nil
	}
	return &Inherited{file: f, Addr: addr}
}

// Listen returns the proxy's listener for addr: the inherited socket when
// it listens on addr (adopted=true), else a fresh bind. An inherited socket
// that does not match (the port changed in the config, or it is no listening
// TCP socket) is closed first, so the bind can take the port.
func Listen(in *Inherited, addr string) (ln net.Listener, adopted bool, err error) {
	if f := in.Take(); f != nil {
		l, ferr := net.FileListener(f)
		_ = f.Close() // FileListener holds its own duplicate
		if ferr == nil {
			if SameAddr(addr, l.Addr().String()) {
				return l, true, nil
			}
			_ = l.Close()
		}
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, false, fmt.Errorf("listenhandover.Listen: %w", err)
	}
	return l, false, nil
}

// SameAddr reports whether a listener at got serves the configured address
// want: the same port, and the same host, where an empty or unspecified
// host in want ("", 0.0.0.0, ::) accepts any host and a name is compared
// after resolving it to its loopback form only for "localhost".
func SameAddr(want, got string) bool {
	wh, wp, err := net.SplitHostPort(want)
	if err != nil {
		return false
	}
	gh, gp, err := net.SplitHostPort(got)
	if err != nil || wp != gp {
		return false
	}
	switch wh {
	case "", "0.0.0.0", "::":
		return true
	case "localhost":
		wh = "127.0.0.1"
	}
	wip, gip := net.ParseIP(wh), net.ParseIP(gh)
	if wip == nil || gip == nil {
		return wh == gh
	}
	return wip.Equal(gip)
}

// fileListener is a listener whose socket can be duplicated.
type fileListener interface {
	File() (*os.File, error)
}

// Prepare duplicates ln's socket for a hand-over. The duplicate keeps the
// socket listening after ln is closed, and keeps close-on-exec (a child
// started before the re-exec never inherits it) until ExecEnv clears it.
func Prepare(ln net.Listener) (*os.File, error) {
	if !Supported() {
		return nil, ErrUnsupported
	}
	if p, ok := ln.(*Pausable); ok {
		ln = p.Listener
	}
	fl, ok := ln.(fileListener)
	if !ok {
		return nil, fmt.Errorf("listenhandover.Prepare: a %T cannot be handed over", ln)
	}
	f, err := fl.File()
	if err != nil {
		return nil, fmt.Errorf("listenhandover.Prepare: %w", err)
	}
	return f, nil
}

// ExecEnv makes f survive the coming execve (it clears close-on-exec) and
// returns env with the hand-over variables naming it and addr, replacing
// any earlier values. Call it right before the execve: from here a child
// started by this process would inherit the socket.
func ExecEnv(f *os.File, addr string, env []string) ([]string, error) {
	if f == nil {
		return env, errors.New("listenhandover.ExecEnv: no socket prepared")
	}
	fd, err := keepOnExec(f)
	if err != nil {
		return env, fmt.Errorf("listenhandover.ExecEnv: %w", err)
	}
	return WithVars(env, fd, addr), nil
}

// WithVars returns env with the hand-over variables set to fd and addr
// (any earlier values removed). Exported for a parent that passes the socket
// to a child as an extra file instead of across execve.
func WithVars(env []string, fd int, addr string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if strings.HasPrefix(kv, EnvFD+"=") || strings.HasPrefix(kv, EnvAddr+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, EnvFD+"="+strconv.Itoa(fd), EnvAddr+"="+addr)
}
