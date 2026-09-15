package sshforward

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sshprofile"
)

// Sentinel errors. Callers map the whole class onto HTTP statuses without
// matching on message text, exactly as termsvc's SSH sentinels are mapped.
var (
	// ErrDisabled — [terminal.ssh].enabled is false, so the surface is hidden.
	ErrDisabled = errors.New("sshforward: remote instances are disabled (set [terminal.ssh].enabled)")
	// ErrUnknownProfile — the requested name is not in the operator-authored
	// profile list. This is THE gate: a name nobody wrote in config.toml can
	// never become a connection.
	ErrUnknownProfile = errors.New("sshforward: no such instance profile")
	// ErrInvalidProfile — the named profile failed re-validation at connect
	// time (e.g. its key file was removed after the daemon started).
	ErrInvalidProfile = errors.New("sshforward: instance profile is not valid")
	// ErrHostKeyUnknown — the host is not in known_hosts, and a -N forward has
	// no terminal on which to accept it. See the package doc.
	ErrHostKeyUnknown = errors.New("sshforward: host key is not in known_hosts")
	// ErrForwardFailed — ssh started but the forward never came up (or the
	// child exited first). The wrapped message carries ssh's own stderr tail.
	ErrForwardFailed = errors.New("sshforward: could not open the port forward")
)

// State is the honest lifecycle of one instance's forward.
type State string

const (
	// StateDisconnected — no child process; nothing is listening locally.
	StateDisconnected State = "disconnected"
	// StateConnecting — a child has been spawned and the readiness probe has
	// not yet decided. Visible to a concurrent List while a Connect is in
	// flight.
	StateConnecting State = "connecting"
	// StateConnected — the local port accepts connections.
	StateConnected State = "connected"
	// StateError — the last attempt failed, or a live forward's child died.
	// Error carries the reason verbatim.
	StateError State = "error"
)

// Instance is one row of the switcher: an operator-configured remote Observer
// install plus the live state of its forward.
//
// Note what is absent: no key path (only the basename hint, like
// SSHProfileInfo), no argv, no pid. The UI needs to recognise a machine and
// know where to point a browser; nothing here discloses more than the existing
// SSH picker already does.
type Instance struct {
	Name string
	// Label is the operator's display name, falling back to Name.
	Label string
	// Target is the "user@host:port" summary line, display-only.
	Target string
	// DashboardPort is the REMOTE port being forwarded to, resolved from the
	// profile (DefaultDashboardPort when unset).
	DashboardPort int
	// HasKey / KeyHint mirror the SSH picker: presence plus BASENAME only.
	HasKey  bool
	KeyHint string
	// Jump is the ProxyJump spec, display-only.
	Jump string

	State State
	// LocalPort is the loopback port the remote dashboard answers on. Non-zero
	// only in StateConnecting/StateConnected.
	LocalPort int
	// URL is the loopback address to open. Non-empty only in StateConnected —
	// a URL is offered when it actually answers, never optimistically.
	URL string
	// Error is the honest failure reason in StateError. Empty otherwise.
	Error string
}

// Spawner starts the composed ssh child. Injected so tests never fork.
type Spawner interface {
	// Spawn starts argv WITHOUT a shell. argv[0] is the program.
	Spawn(argv []string) (Process, error)
}

// Process is the running forward child.
type Process interface {
	// Wait blocks until the child exits and reports its exit error.
	Wait() error
	// Stop terminates the child. Idempotent; safe after exit.
	Stop() error
	// StderrTail returns the last bytes the child wrote to stderr, which is
	// where ssh puts "Host key verification failed" and friends. Bounded.
	StderrTail() string
}

// KnownHostsFunc reports whether a profile's host is already trusted.
//
// The two-value result is deliberate. checked=false means "no verdict" — the
// checker could not run, or could not resolve an alias — and the caller then
// PROCEEDS, letting ssh itself refuse. Only a definite checked=true,
// known=false refuses up front. A pre-flight that guessed would either
// auto-accept unknown hosts (a security regression) or block legitimate ones.
type KnownHostsFunc func(p sshprofile.Profile) (known, checked bool)

// TestRunnerFunc runs a one-shot diagnostic probe: it starts argv, waits for
// it to exit (or its own internal timeout to fire), and reports whether it
// exited zero, the bounded stderr it produced, and a non-nil error only when
// the probe genuinely could not run (e.g. ssh is not on PATH). An
// authentication failure is ok=false with a nil error — that is the probe
// working correctly, not a failure to run it.
type TestRunnerFunc func(argv []string) (ok bool, stderrTail string, err error)

// Options configures a Manager. Every OS-touching field has a default in
// spawn.go, so a test supplies fakes and nothing forks.
type Options struct {
	// Enabled mirrors [terminal.ssh].enabled — the same visibility switch the
	// SSH terminal picker uses. Profiles remain the authority.
	Enabled bool
	// Profiles is the operator-authored allow-list, converted once at the cmd
	// boundary from config.
	Profiles []sshprofile.Profile
	// SSHOptions carries the shared connect-timeout / keepalive knobs.
	SSHOptions sshprofile.Options
	// Spawner starts the ssh child. Nil uses the OS spawner.
	Spawner Spawner
	// AllocPort returns a free loopback port for the LOCAL end of the forward.
	// Nil uses the OS allocator (bind :0, read the port, release).
	AllocPort func() (int, error)
	// Probe reports whether the local port accepts a connection yet. Nil uses
	// a loopback TCP dial.
	Probe func(port int) error
	// KnownHosts is the pre-flight described on KnownHostsFunc. Nil uses the
	// OS checker; a non-nil func that always returns (false,false) disables
	// the pre-flight without weakening anything.
	KnownHosts KnownHostsFunc
	// TestRunner runs the one-shot diagnostic probe argv built by
	// sshprofile.TestArgv (Test). Nil uses the OS runner.
	TestRunner TestRunnerFunc
	// ReadyTimeout bounds the readiness wait. 0 uses DefaultReadyTimeout.
	ReadyTimeout time.Duration
	// ProbeInterval is the readiness poll period. 0 uses DefaultProbeInterval.
	ProbeInterval time.Duration
	// Logger is optional; a nil logger disables logging entirely.
	Logger *slog.Logger
}

// Readiness defaults. The wait must comfortably exceed the ssh connect timeout
// so a slow handshake reports "connected", not a spurious timeout.
const (
	DefaultReadyTimeout  = 20 * time.Second
	DefaultProbeInterval = 100 * time.Millisecond
)

// Manager owns every live forward this daemon has opened. One per daemon.
type Manager struct {
	opts Options

	mu sync.Mutex
	// live is keyed by profile name — at most ONE forward per profile, which
	// is what makes Connect idempotent.
	live map[string]*forward
	// closed is set by Close so a late Connect cannot outlive the daemon.
	closed bool
}

// forward is the in-memory record of one instance's child process.
type forward struct {
	localPort int
	state     State
	errMsg    string
	proc      Process
	// exited closes when the child's Wait returns, so the readiness loop can
	// stop waiting the moment ssh dies instead of burning the full timeout.
	exited chan struct{}
}

// New builds a Manager, filling every unset seam with its OS-backed default.
func New(opts Options) *Manager {
	if opts.Spawner == nil {
		opts.Spawner = NewOSSpawner()
	}
	if opts.AllocPort == nil {
		opts.AllocPort = allocLoopbackPort
	}
	if opts.Probe == nil {
		opts.Probe = probeLoopbackPort
	}
	if opts.KnownHosts == nil {
		opts.KnownHosts = NewOSKnownHostsChecker()
	}
	if opts.TestRunner == nil {
		opts.TestRunner = NewOSTestRunner()
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = DefaultReadyTimeout
	}
	if opts.ProbeInterval <= 0 {
		opts.ProbeInterval = DefaultProbeInterval
	}
	return &Manager{opts: opts, live: make(map[string]*forward)}
}

// Enabled reports the surface-visibility switch.
func (m *Manager) Enabled() bool { return m != nil && m.opts.Enabled }

// List projects every configured profile plus its live forward state. It is a
// READ of the same profile list Connect resolves against (one owner), so the
// switcher can never offer an instance Connect would refuse as unknown.
//
// Nil-safe: a nil Manager lists nothing, which is the honest "feature absent"
// answer rather than a panic.
func (m *Manager) List() []Instance {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Instance, 0, len(m.opts.Profiles))
	for _, p := range m.opts.Profiles {
		out = append(out, m.snapshotLocked(p))
	}
	return out
}

// Get returns one instance row by name.
func (m *Manager) Get(name string) (Instance, bool) {
	if m == nil {
		return Instance{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := sshprofile.Find(m.opts.Profiles, name)
	if !ok {
		return Instance{}, false
	}
	return m.snapshotLocked(p), true
}

// snapshotLocked renders one row. Caller holds m.mu.
func (m *Manager) snapshotLocked(p sshprofile.Profile) Instance {
	inst := Instance{
		Name:          p.Name,
		Label:         p.Display(),
		Target:        p.Target(),
		DashboardPort: p.ResolvedDashboardPort(),
		HasKey:        p.KeyPath != "",
		KeyHint:       p.KeyHint(),
		Jump:          p.Jump,
		State:         StateDisconnected,
	}
	f, ok := m.live[p.Name]
	if !ok {
		return inst
	}
	inst.State = f.state
	inst.Error = f.errMsg
	if f.state == StateConnecting || f.state == StateConnected {
		inst.LocalPort = f.localPort
	}
	if f.state == StateConnected {
		inst.URL = LocalURL(f.localPort)
	}
	return inst
}

// LocalURL renders the loopback address for a forwarded dashboard. Kept in one
// place so the API and the UI can never disagree about the scheme or host.
func LocalURL(localPort int) string {
	return "http://" + sshprofile.ForwardBindAddr + ":" + strconv.Itoa(localPort)
}

// Connect opens (or re-uses) the forward for a named profile and returns the
// resulting row.
//
// IDEMPOTENT: a name already forwarded returns the existing port without
// spawning a second child, so a double-click cannot leak processes. A name
// whose child has died is retried from scratch.
//
// Fail-CLOSED throughout, like handleSSHLaunch: there is no degraded "connect
// anyway" path. The caller named a specific machine, and quietly reaching a
// different one — or reporting a port that answers nothing — would be worse
// than refusing.
func (m *Manager) Connect(name string) (Instance, error) {
	if m == nil || !m.opts.Enabled {
		return Instance{}, ErrDisabled
	}
	profile, ok := sshprofile.Find(m.opts.Profiles, name)
	if !ok {
		return Instance{}, fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
	// TOCTOU re-validation immediately before spawn, mirroring LaunchSSH: a key
	// file removed since daemon start must fail here, not inside ssh.
	if err := profile.ValidateWithFS(); err != nil {
		return Instance{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}

	// Claim the slot under the lock, then do the slow work outside it so a
	// concurrent List still answers (and honestly reports "connecting").
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Instance{}, ErrDisabled
	}
	if f, exists := m.live[profile.Name]; exists {
		switch f.state {
		case StateConnected, StateConnecting:
			inst := m.snapshotLocked(profile)
			m.mu.Unlock()
			return inst, nil
		}
		// A dead or failed forward is replaced, not reused.
		delete(m.live, profile.Name)
	}
	pending := &forward{state: StateConnecting, exited: make(chan struct{})}
	m.live[profile.Name] = pending
	m.mu.Unlock()

	inst, err := m.open(profile, pending)
	if err != nil {
		m.mu.Lock()
		// Only clear the slot if it is still OURS — a concurrent Disconnect or
		// Close may already have replaced or removed it.
		if cur, ok := m.live[profile.Name]; ok && cur == pending {
			delete(m.live, profile.Name)
		}
		m.mu.Unlock()
		return Instance{}, err
	}
	return inst, nil
}

// open does the spawn + readiness wait for an already-claimed slot.
func (m *Manager) open(profile sshprofile.Profile, pending *forward) (Instance, error) {
	if known, checked := m.opts.KnownHosts(profile); checked && !known {
		return Instance{}, fmt.Errorf("%w: %s is not in known_hosts. Open an SSH terminal to this profile once and accept the host key, then connect again",
			ErrHostKeyUnknown, profile.Target())
	}

	localPort, err := m.opts.AllocPort()
	if err != nil {
		return Instance{}, fmt.Errorf("%w: allocate a local port: %w", ErrForwardFailed, err)
	}
	argv, err := sshprofile.ForwardArgv(profile, m.opts.SSHOptions, localPort)
	if err != nil {
		return Instance{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}
	proc, err := m.opts.Spawner.Spawn(argv)
	if err != nil {
		return Instance{}, fmt.Errorf("%w: start ssh: %w", ErrForwardFailed, err)
	}

	m.mu.Lock()
	pending.localPort = localPort
	pending.proc = proc
	m.mu.Unlock()

	// One reaper per child: it is what turns a dead ssh into an honest
	// StateError row instead of a UI that still offers a dead port.
	go m.reap(profile.Name, pending, proc)

	if err := m.awaitReady(localPort, pending); err != nil {
		_ = proc.Stop()
		if tail := trimTail(proc.StderrTail()); tail != "" {
			return Instance{}, fmt.Errorf("%w: %w: %s", ErrForwardFailed, err, tail)
		}
		return Instance{}, fmt.Errorf("%w: %w", ErrForwardFailed, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// The reaper may have won the race (child died the instant it bound). Do
	// not overwrite a terminal state with "connected".
	if pending.state == StateConnecting {
		pending.state = StateConnected
	}
	if m.opts.Logger != nil {
		m.opts.Logger.Info("instance switcher: forward open",
			"profile", profile.Name, "local_port", localPort, "dashboard_port", profile.ResolvedDashboardPort())
	}
	return m.snapshotLocked(profile), nil
}

// awaitReady polls the local port until it answers, the child dies, or the
// deadline passes.
func (m *Manager) awaitReady(localPort int, f *forward) error {
	deadline := time.NewTimer(m.opts.ReadyTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(m.opts.ProbeInterval)
	defer tick.Stop()
	for {
		if err := m.opts.Probe(localPort); err == nil {
			return nil
		}
		select {
		case <-f.exited:
			// One last probe: a child that exited AFTER binding is still a
			// failure for our purposes, but losing a race here would report a
			// misleading reason.
			if err := m.opts.Probe(localPort); err == nil {
				return nil
			}
			return errors.New("ssh exited before the forward came up")
		case <-deadline.C:
			return fmt.Errorf("the forward did not come up within %s", m.opts.ReadyTimeout)
		case <-tick.C:
		}
	}
}

// reap waits for the child and records its death.
func (m *Manager) reap(name string, f *forward, proc Process) {
	err := proc.Wait()
	close(f.exited)
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.live[name]
	if !ok || cur != f {
		return // already disconnected/replaced; nothing to report
	}
	f.state = StateError
	f.errMsg = exitReason(err, proc.StderrTail())
	if m.opts.Logger != nil {
		m.opts.Logger.Warn("instance switcher: forward ended", "profile", name, "reason", f.errMsg)
	}
}

// Disconnect closes a named forward. It is idempotent: disconnecting something
// already disconnected is a success, not an error, so a stale UI cannot produce
// a spurious failure.
func (m *Manager) Disconnect(name string) error {
	if m == nil {
		return ErrDisabled
	}
	if _, ok := sshprofile.Find(m.opts.Profiles, name); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
	m.mu.Lock()
	f, ok := m.live[name]
	delete(m.live, name)
	m.mu.Unlock()
	if !ok || f.proc == nil {
		return nil
	}
	if err := f.proc.Stop(); err != nil {
		return fmt.Errorf("sshforward: stop %q: %w", name, err)
	}
	if m.opts.Logger != nil {
		m.opts.Logger.Info("instance switcher: forward closed", "profile", name)
	}
	return nil
}

// TestResult is the outcome of a diagnostic connection test (Test): a cheap,
// read-only probe distinct from Connect — it opens no lasting forward and
// leaves no live state in the Manager.
type TestResult struct {
	// KnownHostsChecked reports whether the known-hosts pre-flight reached a
	// verdict at all, mirroring KnownHostsFunc's two-value contract.
	// false means "no verdict" (the check could not run or resolve the
	// alias) — it does NOT mean the host is untrusted; see KnownHostsOK.
	KnownHostsChecked bool
	// KnownHostsOK is the verdict when KnownHostsChecked is true: the
	// resolved host already has a known_hosts entry. Meaningless (always
	// false) when KnownHostsChecked is false.
	KnownHostsOK bool
	// AuthOK reports whether the probe (sshprofile.TestArgv: `ssh
	// -o BatchMode=yes ... exit`) exited zero — the operator's key/agent
	// authenticated and the remote command ran.
	AuthOK bool
	// Latency is how long the probe took to return, success or failure.
	Latency time.Duration
	// Stderr is a bounded, trimmed excerpt of the probe's stderr (ssh names
	// host-key and auth failures there — "Permission denied", "Host key
	// verification failed"), for display alongside AuthOK=false. Empty on a
	// clean success.
	Stderr string
}

// Test runs a cheap, read-only diagnostic probe against a named profile: the
// same known-hosts pre-flight Connect uses, plus a one-shot
// `ssh -o BatchMode=yes ... exit` (sshprofile.TestArgv) that authenticates
// and disconnects immediately. It never opens a forward and never touches
// m.live — a Test has no effect on Connect/Disconnect/List.
//
// Unlike Connect, the outer error return is reserved for "could not even
// attempt" failures (disabled, unknown/invalid profile, argv composition, or
// the probe process itself failing to start — e.g. ssh not on PATH). A probe
// that ran but failed to authenticate, or a host that is not yet in
// known_hosts, is not an error: it is the honest, informative TestResult the
// operator is asking for, reported with a nil error.
func (m *Manager) Test(name string) (TestResult, error) {
	if m == nil || !m.opts.Enabled {
		return TestResult{}, ErrDisabled
	}
	profile, ok := sshprofile.Find(m.opts.Profiles, name)
	if !ok {
		return TestResult{}, fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
	if err := profile.ValidateWithFS(); err != nil {
		return TestResult{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}

	var result TestResult
	result.KnownHostsOK, result.KnownHostsChecked = m.opts.KnownHosts(profile)

	argv, err := sshprofile.TestArgv(profile, m.opts.SSHOptions)
	if err != nil {
		return TestResult{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}

	start := time.Now()
	authOK, stderr, runErr := m.opts.TestRunner(argv)
	result.Latency = time.Since(start)
	result.Stderr = trimTail(stderr)
	if runErr != nil {
		return TestResult{}, fmt.Errorf("%w: run test probe: %w", ErrForwardFailed, runErr)
	}
	result.AuthOK = authOK

	if m.opts.Logger != nil {
		m.opts.Logger.Info("instance switcher: test probe",
			"profile", name, "auth_ok", result.AuthOK,
			"known_hosts_checked", result.KnownHostsChecked, "known_hosts_ok", result.KnownHostsOK,
			"latency", result.Latency)
	}
	return result, nil
}

// Close tears down every forward. The daemon calls it on shutdown so an ssh
// child can never outlive the process that opened it.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.closed = true
	live := m.live
	m.live = make(map[string]*forward)
	m.mu.Unlock()
	for name, f := range live {
		if f.proc == nil {
			continue
		}
		if err := f.proc.Stop(); err != nil && m.opts.Logger != nil {
			m.opts.Logger.Warn("instance switcher: stopping forward at shutdown failed", "profile", name, "err", err)
		}
	}
}

// exitReason renders an honest one-line cause for a dead child, preferring
// ssh's own stderr (which names host-key and auth failures precisely) over the
// bare exit status.
func exitReason(waitErr error, stderr string) string {
	if tail := trimTail(stderr); tail != "" {
		return tail
	}
	if waitErr != nil {
		return "ssh exited: " + waitErr.Error()
	}
	return "ssh exited"
}

// trimTail collapses a stderr tail into a single bounded line for display.
func trimTail(s string) string {
	const maxTail = 240
	out := make([]rune, 0, maxTail)
	lastSpace := false
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			if len(out) == 0 || lastSpace {
				continue
			}
			out = append(out, ' ')
			lastSpace = true
			continue
		}
		if r < ' ' || r == 0x7f {
			continue // never let an escape sequence reach a UI
		}
		out = append(out, r)
		lastSpace = false
		if len(out) >= maxTail {
			break
		}
	}
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	return string(out)
}
