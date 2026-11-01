//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// terminal_sandbox_oci_oob_linux.go is the OOB channel into the container
// (sandbox plan v2 section 5.6, lane SBX-P3C). fd 3 does not cross into a
// container, so the host helper keeps it on the host: it authenticates the
// trusted channel itself (the daemon's own auth secret and correlation
// token, from its own environment) and reports the run's real start and end
// (the container's exit status). The box gets a per-run OOB socket beside
// the relay in the bound socket directory, with a per-run box token: the
// container's init hands that connection to the in-box launcher as its fd 3,
// so the launcher's own OOB code runs unchanged. Everything that arrives on
// it is untrusted: a box Hello or lifecycle frame is dropped (the box cannot
// name another run, nor claim a start or an exit), and a session announce is
// forwarded only as "discovered" (the lowest correlation confidence), never
// as known. Linking still keys on the correlation token (PIDs hidden).
//
// On Linux the helper inherits the daemon's pipe as its own fd 3, so the
// daemon reads the channel where it always does; no sandboxOOBSources entry
// is needed (that registry exists for a PTY child that cannot inherit it).

// The OOB socket's name in the run's socket directory, and the variables
// the box's init reads.
const (
	ociOOBSockName = "oob.sock"
	envOOBBoxSock  = "OBSERVER_OOB_BOXSOCK"
	envOOBBoxAuth  = "OBSERVER_OOB_BOXAUTH"
)

// ociOOBMaxSessions bounds the session announces one run forwards.
const ociOOBMaxSessions = 64

// ociOOBSessionRE is a session id the helper forwards: the shape of the ids
// the launchers announce (UUIDs and rollout ids), nothing else.
var ociOOBSessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ociOOB is one run's channel: the trusted uplink on the helper's fd and
// the box's socket.
type ociOOB struct {
	mu       sync.Mutex
	enc      *termoob.Encoder
	w        io.Closer
	ln       net.Listener
	token    string
	sessions int
	ended    bool
}

// ociOpenOOB opens the run's channel: the trusted uplink when this helper
// was handed one (the daemon's fd and auth in getenv; a CLI launch has
// none, and gets nil), and the box socket in sockDir. It returns the
// variables the box's environment carries.
func ociOpenOOB(getenv func(string) string, sockDir string) (*ociOOB, []string) {
	fdStr, auth := getenv(envOOBFD), getenv(envOOBAuth)
	if fdStr == "" || auth == "" || sockDir == "" {
		return nil, nil
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd < 3 || !isPipeOrSocket(fd) {
		return nil, nil
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "observer-oob")
	if f == nil {
		return nil, nil
	}
	return ociStartOOB(f, termoob.Hello{AuthToken: auth, CorrelationToken: getenv(envOOBCorr), Tool: getenv(envOOBTool), PID: os.Getpid()}, sockDir)
}

// ociStartOOB writes the trusted Hello and the start on up, and serves the
// box socket.
func ociStartOOB(up io.WriteCloser, hello termoob.Hello, sockDir string) (*ociOOB, []string) {
	enc := termoob.NewEncoder(up)
	if err := enc.WriteHello(hello); err != nil {
		_ = up.Close()
		return nil, nil
	}
	_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseLauncherStarted, At: time.Now().UnixNano()})
	o := &ociOOB{enc: enc, w: up}
	token, err := termoob.NewSessionToken()
	if err != nil {
		return o, nil
	}
	p := filepath.Join(sockDir, ociOOBSockName)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return o, nil
	}
	o.ln, o.token = ln, token
	go o.serve()
	return o, []string{envOOBBoxSock + "=" + sandbox.GuestSocketDir + "/" + ociOOBSockName, envOOBBoxAuth + "=" + token}
}

// serve accepts the box's connections until the run ends; each is read
// with the box token, from the same user only.
func (o *ociOOB) serve() {
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		if sandboxrelayd.PeerSameUser(c) != nil {
			_ = c.Close()
			continue
		}
		go o.forward(c)
	}
}

// forward reads one box stream and passes on only its session announces,
// lowered; everything else is dropped.
func (o *ociOOB) forward(c net.Conn) {
	defer func() { _ = c.Close() }()
	dec := termoob.NewDecoder(c, o.token)
	for {
		f, err := dec.Read()
		if err != nil {
			return
		}
		if f.Type == termoob.TypeSession && f.Session != nil {
			o.session(f.Session.SessionID)
		}
	}
}

// session forwards one box-announced id as discovered.
func (o *ociOOB) session(id string) {
	if !ociOOBSessionRE.MatchString(id) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ended || o.sessions >= ociOOBMaxSessions {
		return
	}
	o.sessions++
	_ = o.enc.WriteSession(termoob.Session{SessionID: id, Source: termoob.SessionSourceDiscovered})
}

// end reports the run's end with the container's exit status and closes
// the channel (nil-safe, once).
func (o *ociOOB) end(code int) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ended {
		return
	}
	o.ended = true
	if o.ln != nil {
		_ = o.ln.Close()
	}
	_ = o.enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseToolExecEnd, ExitCode: &code, At: time.Now().UnixNano()})
	_ = o.w.Close()
}

// ---- the box side: the container's init --------------------------------------

// ociInitOOB prepares the init's inner launch when the box has an OOB
// socket: the connection becomes the launcher's fd 3 with the box token as
// its auth, and a guest network command in front of the launcher is served
// by the init itself (its proxy and gateway forwards), so nothing between
// the init and the launcher drops the descriptor. With no socket (or one
// that does not answer) the launch is exactly as planned. The returned stop
// ends the forwards.
func ociInitOOB(argv, environ []string) (run, env []string, extra []*os.File, stop func()) {
	stop = func() {}
	sockPath, auth := "", ""
	var rest []string
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case envOOBBoxSock:
			sockPath = v
		case envOOBBoxAuth:
			auth = v
		case envOOBFD, envOOBAuth:
		default:
			rest = append(rest, kv)
		}
	}
	if sockPath == "" || auth == "" {
		return argv, rest, nil, stop
	}
	c, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return argv, rest, nil, stop
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return argv, rest, nil, stop
	}
	f, err := uc.File()
	_ = uc.Close()
	if err != nil {
		return argv, rest, nil, stop
	}
	ctx, cancel := context.WithCancel(context.Background())
	run, rest, err = ociInitTakeGuest(ctx, argv, rest)
	if err != nil {
		cancel()
		_ = f.Close()
		return argv, rest, nil, stop
	}
	return run, append(rest, envOOBFD+"=3", envOOBAuth+"="+auth), []*os.File{f}, func() {
		cancel()
		_ = f.Close()
	}
}

// ociInitTakeGuest runs a guest network command's forwards in the init and
// returns the launcher it would have run, with the guest's environment,
// through the SAME startGuestForwards over the same guestForwardRows table
// runSandboxGuest uses (ruling P-121: one owner of the forwards); any other
// argv is returned as is.
func ociInitTakeGuest(ctx context.Context, argv, env []string) ([]string, []string, error) {
	if len(argv) < 2 || argv[1] != sandbox.GuestVerb {
		return argv, env, nil
	}
	g, err := sandbox.ParseGuestArgs(argv[2:])
	if err != nil {
		return nil, env, err
	}
	if len(g.Command) == 0 {
		return nil, env, errors.New("the guest command has no launch")
	}
	env, err = startGuestForwards(ctx, g, env)
	if err != nil {
		return nil, env, err
	}
	return g.Command, env, nil
}
