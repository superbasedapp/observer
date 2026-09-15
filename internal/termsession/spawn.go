package termsession

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// SpecKind classifies a session by SHAPE so authorization and validation
// branch on the session, not on caller identity (CLAUDE.md #3). SpecAgent is
// the default AI-launcher (BinPath+Subcommand → argv); SpecSetup is a fixed,
// server-derived privileged setup command (SetupArgv verbatim) — e.g. the
// one-time Tailscale operator grant — that is LOCAL-WRITER-ONLY (a paired
// remote principal can never acquire its writer lease; see
// Manager.AcquireWriterRemote).
type SpecKind int

const (
	// SpecAgent is an AI-launcher session (the default, zero value).
	SpecAgent SpecKind = iota
	// SpecSetup is a fixed server-derived local operator setup command. It runs
	// no agent, carries no OOB channel, mints no terminal_run, and is pinned
	// local-writer-only. SetupArgv holds the full argv (argv[0] resolves via
	// PATH).
	SpecSetup
	// SpecShell is a fresh PLAIN SHELL session — no AI agent, no OOB control
	// channel semantics beyond what a normal fresh launch already carries.
	// Unlike SpecSetup it is NOT local-writer-only and is NOT single-flighted
	// — it behaves like SpecAgent for writer-lease/remote-view purposes (each
	// "New terminal → Shell" click spawns a genuinely new PTY). ShellArgv
	// holds the full argv (argv[0] resolves via PATH), server-derived from
	// the child's $SHELL with a /bin/bash / /bin/sh fallback — never
	// client-supplied.
	SpecShell
	// SpecSSH is an outbound SSH remote-system session
	// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md). SSHArgv holds the
	// full, server-derived OpenSSH client argv composed by internal/sshprofile
	// from an OPERATOR-AUTHORED config profile — the client supplies only a
	// profile NAME and can never influence host/user/key/port/jump.
	//
	// It mirrors SpecShell's shape (fixed argv in its own field, not
	// local-writer-only, not single-flighted) with ONE deliberate difference:
	// it IGNORES WrapArgv. A bwrap sandbox blinds $HOME — no known_hosts, no
	// key file, no SSH_AUTH_SOCK — so wrapping an SSH launch produces a
	// confusing failure rather than isolation. See Spec.argv().
	SpecSSH
)

// Spec is the fully server-derived launch specification. The Manager builds
// the launch argv from these fields alone — a caller NEVER passes raw argv,
// paths, or environment overrides sourced from the client. Every field is
// validated at Create.
//
// ARGV CONTRACT: whatever shape argv() produces, argv[0] is the PROGRAM and is
// resolved via PATH by the spawner (resolveSpawnArgv → exec.LookPath) before
// exec. That is true on both platforms: on Windows the lookup is %PATHEXT%-aware
// — needed because CreateProcess itself only ever appends ".exe" — and a
// program that resolves solely in the daemon's own working directory is
// refused, never launched.
type Spec struct {
	// Kind classifies the session (SpecAgent default / SpecSetup). It drives
	// argv() and the local-writer-only pin — server-derived, never from a
	// client.
	Kind SpecKind
	// SetupArgv is the complete, server-derived argv for a SpecSetup session
	// (e.g. tailnet.OperatorGrantArgv). It is non-empty ONLY for SpecSetup and
	// is NEVER client-supplied; argv[0] is the program (resolved via PATH).
	// Ignored for SpecAgent.
	SetupArgv []string
	// SetupLabel is the server-derived KIND tag of a SpecSetup session (e.g.
	// "tailscale-login", "tailscale-install", "tailscale-operator-grant"). It
	// keys the setup single-flight: at most one live setup session per label may
	// exist, so N concurrent requests of the same kind can never spawn two
	// privileged PTYs (Create returns the live handle, or ErrSetupInFlight while
	// a spawn of that label is in flight). It is NEVER part of the argv and is
	// ignored for SpecAgent; an empty label disables single-flight for that
	// setup session.
	SetupLabel string
	// ShellArgv is the complete, server-derived argv for a SpecShell session
	// (the resolved $SHELL / /bin/bash / /bin/sh, with no arguments). Non-empty
	// ONLY for SpecShell and NEVER client-supplied; ignored for every other
	// Kind.
	ShellArgv []string
	// SSHArgv is the complete, server-derived argv for a SpecSSH session (the
	// OpenSSH client invocation internal/sshprofile composed from a validated
	// config profile). Non-empty ONLY for SpecSSH and NEVER client-supplied;
	// ignored for every other Kind. argv[0] is "ssh", resolved via PATH like
	// every other termsession spawn.
	SSHArgv []string
	// BinPath is the observer binary to exec, from os.Executable(),
	// injected by cmd. Never client-supplied.
	BinPath string
	// Subcommand is the observer launcher verb (e.g. "claude", "codex").
	// It comes from the integration registry's LaunchSpec, validated by
	// the dashboard against the launchable capability set.
	Subcommand string
	// ArgvMode selects the SHAPE of the launch argv (see ArgvMode). The zero
	// value (ArgvModeHandoff) is the --continue-from continuation argv — the
	// original default — so a zero-value Spec is unchanged. ArgvModeFresh is the
	// bare `[bin, subcommand]` base a fresh, attach, OR native-resume launch
	// uses (a resume's `--resume <id>` tail rides in ExtraArgs, so it must NOT
	// get the handoff --continue-from prefix — the two are mutually exclusive
	// for the underlying CLI). Server-derived like every other field; the cmd
	// ptyLauncher maps a run KIND onto it through a small table.
	ArgvMode ArgvMode
	// SessionID is the source session to continue from (--continue-from).
	// Required for a handoff launch (ArgvModeHandoff); ignored by an
	// ArgvModeFresh argv (a fresh/attach launch has none; a resume carries the
	// resumed id as SessionID for identity but resumes via its ExtraArgs tail).
	SessionID string
	// Carry is the handoff carry mode (--carry); "" omits the flag so the
	// launcher uses its configured default.
	Carry string
	// FromMessage forks the handover after this 1-based transcript message
	// (--from-message); 0 forks at the last message (the flag is omitted).
	FromMessage int
	// Rows and Cols are the initial PTY window size; 0 lets the OS pick a
	// default (80x24-ish) until the client sends its first resize.
	Rows uint16
	Cols uint16
	// Env is the child environment; nil means inherit the daemon's
	// os.Environ() at spawn time. The dashboard leaves this nil — the
	// spawned launcher needs the daemon's own env (proxy port, HOME, …).
	Env []string
	// Dir is the child's working directory. Empty inherits the daemon's cwd.
	// A fresh launch (F1) sets it to the operator-allow-listed, canonicalized
	// project root; a handoff launch leaves it empty (the launcher resolves
	// the source session's project root itself). Server-derived: for a fresh
	// launch it is validated against [terminal.launch].allowed_project_roots
	// and canonicalized BEFORE reaching here.
	Dir string
	// ExtraFiles are additional open files the spawned launcher inherits
	// (beyond stdio), appearing at fd 3, 4, … in the child — the trusted
	// out-of-band control channel's inherited FD (plan §2.1b / F1). nil for
	// a launch with no OOB channel. termsession only plumbs them onto the
	// spawn; it never reads or writes them (that is cmd/termsvc's job).
	//
	// UNIX ONLY (honest-zero gap): the Windows ConPTY backend does not inherit
	// them — it starts the child with bInheritHandles=false — so on a
	// native-Windows daemon the child sees OBSERVER_OOB_FD=3 with no handle
	// behind it and OOB correlation never fires. See spawn_windows.go for what
	// implementing it would take.
	ExtraFiles []*os.File
	// ExtraArgs are additional, server-derived argv tokens appended to the
	// launch argv AFTER the subcommand (and after any handoff flags). Zero
	// value (nil) leaves the argv unchanged, so fresh/handoff launches are
	// unaffected. The session-attach path (KindAttach → Fresh) uses this to
	// carry the inner launcher's routing escape hatch (`--no-proxy-route`),
	// `--proxy`/`--config` overrides, and the operator's trailing tool args
	// (`-- --model X`) so an attached `observer <tool>` self-configures
	// exactly like a bare launch (session-attach design §6). Like every other
	// Spec field these are SERVER-DERIVED — the attach client supplies only an
	// allow-listed, explicit set (flags observer understands + the `--`
	// remainder), never a blind argv copy.
	ExtraArgs []string
	// WrapArgv is an optional isolation-wrapper argv prefix (e.g. bwrap
	// flags ending in --); when non-empty argv() prepends it before
	// [BinPath, Subcommand]. Empty = no wrapper (unchanged behaviour).
	WrapArgv []string
}

// ArgvMode selects the launch argv SHAPE for a SpecAgent session. It is an
// EXPLICIT enum rather than a bare boolean so a run kind whose argv is
// "fresh-style base + a tool tail" (a native resume) is expressed honestly
// instead of being mislabelled "fresh" (adversarial review 2026-07-19, F2). The
// zero value is ArgvModeHandoff, so a zero-value Spec keeps the original
// --continue-from behaviour.
type ArgvMode uint8

const (
	// ArgvModeHandoff (zero value) builds the --continue-from continuation argv:
	// [bin, subcommand, "--continue-from", SessionID] plus "--carry <c>" /
	// "--from-message <n>" when set, then ExtraArgs. Requires a SessionID.
	ArgvModeHandoff ArgvMode = iota
	// ArgvModeFresh builds the bare base argv [bin, subcommand] + ExtraArgs, with
	// NO --continue-from. Used by fresh launches (no ExtraArgs), attach launches
	// (routing escape-hatch ExtraArgs), AND native-resume launches (whose
	// `--resume <id>` tail rides in ExtraArgs — a fresh base with a resume tail,
	// NOT a handoff). SessionID is ignored by this shape.
	ArgvModeFresh
)

// argv builds the exec argv from the validated Spec. Server-derived only.
// ArgvModeFresh is [bin, subcommand] + ExtraArgs; ArgvModeHandoff is
// [bin, subcommand, "--continue-from", id] plus "--carry <c>" and
// "--from-message <n>" when set, then ExtraArgs. When WrapArgv is non-empty
// it is prepended before EVERYTHING — including BinPath — for SpecAgent and
// SpecShell (a B9 sandbox wrap works for a plain shell for free). SpecSetup
// is exempt: it runs a fixed, server-derived command verbatim and is never
// wrapped.
func (s Spec) argv() []string {
	if s.Kind == SpecSetup {
		// A SpecSetup session runs a fixed, server-derived command verbatim
		// (validated non-empty at Create). Copy so the caller's slice can't be
		// mutated through the returned value.
		return append([]string(nil), s.SetupArgv...)
	}
	if s.Kind == SpecShell {
		// Same copy-on-return discipline as SpecSetup above, with the wrap
		// prefix prepended when present.
		return append(append([]string(nil), s.WrapArgv...), s.ShellArgv...)
	}
	if s.Kind == SpecSSH {
		// Copy-on-return like the two above, but WITHOUT the WrapArgv prefix:
		// an isolation wrapper would blind the very things ssh needs (the
		// operator's known_hosts, key file, and agent socket), so a sandboxed
		// SSH launch is not a narrower launch — it is a broken one. See
		// SpecSSH's doc comment.
		return append([]string(nil), s.SSHArgv...)
	}
	switch s.ArgvMode {
	case ArgvModeFresh:
		a := append([]string(nil), s.WrapArgv...)
		a = append(a, s.BinPath, s.Subcommand)
		return append(a, s.ExtraArgs...)
	default: // ArgvModeHandoff (zero value)
		a := append([]string(nil), s.WrapArgv...)
		a = append(a, s.BinPath, s.Subcommand, "--continue-from", s.SessionID)
		if s.Carry != "" {
			a = append(a, "--carry", s.Carry)
		}
		if s.FromMessage > 0 {
			a = append(a, "--from-message", strconv.Itoa(s.FromMessage))
		}
		return append(a, s.ExtraArgs...)
	}
}

// PTY is a live pseudo-terminal bound to a running process. It is injected
// into the Manager so the lifecycle logic is testable with an in-memory
// stub — the real implementation (unix only) wraps a creack/pty master.
type PTY interface {
	// Read/Write move bytes to/from the terminal (client-visible I/O).
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	// Resize sets the terminal window size.
	Resize(rows, cols uint16) error
	// Wait blocks until the process exits and returns its exit code.
	Wait() (exitCode int, err error)
	// Kill force-reaps the whole process tree (process group on unix) and
	// closes the master fd. It must be idempotent.
	Kill() error
	// Close releases the master fd without necessarily killing the child
	// (used when detaching); Kill is the authoritative teardown.
	Close() error
}

// Spawner turns a validated Spec into a live PTY. The default OS
// implementation is platform-specific (unix: creack/pty; windows:
// unsupported). Tests inject a fake.
type Spawner interface {
	Spawn(spec Spec) (PTY, error)
}

// ProcessReporter is the OPTIONAL extension of [PTY] that reports the OS pid
// of the spawned child. Both real backends implement it (the unix creack/pty
// child and the native-Windows ConPTY child), which is what lets the Manager
// publish a [ProcessEvent] so an injected sink can attribute that process
// subtree. It is deliberately a SEPARATE interface rather than a method on
// PTY: a fake PTY in an existing test keeps compiling untouched, and a
// backend that genuinely cannot report a pid simply doesn't implement it
// (the Manager then reports pid 0 and fires no process event).
type ProcessReporter interface {
	// Pid is the OS process id of the PTY's direct child, or 0 when unknown
	// (e.g. the process failed to start or has been released).
	Pid() int
}

// ptyPID returns the OS pid of a PTY's child when the backend implements
// [ProcessReporter], else 0. Nil-safe.
func ptyPID(p PTY) int {
	if r, ok := p.(ProcessReporter); ok {
		return r.Pid()
	}
	return 0
}

// ErrPlatformUnsupported is returned by the OS spawner on a platform where an
// in-process PTY cannot be created. Since 2026-07-04 a native-Windows daemon
// IS supported (ConPTY), so the only remaining causes are a Windows host older
// than 10 version 1809 (no CreatePseudoConsole in kernel32) and a platform with
// no PTY backend at all. The dashboard surfaces it as an honest terminal
// message, not a hang.
var ErrPlatformUnsupported = errors.New("termsession: embedded terminal is not supported on this OS (Windows before 10 version 1809 has no ConPTY; other platforms need a PTY backend)")

// NewOSSpawner returns the platform's real PTY spawner (creack/pty on
// unix). Injected by cmd into NewManager; tests bypass it with a fake.
func NewOSSpawner() Spawner { return newOSSpawner() }

// PTYSupported reports whether this OS can host the embedded web terminal
// (an in-process PTY). It is true on unix and false on a native-Windows
// daemon. cmd consults it to leave the dashboard launch seam unwired on an
// unsupported OS — hiding the "Launch here" affordance up front instead of
// letting it fail on click — while the platform-independent handoff-doc
// migration ("Write handover doc") remains available everywhere.
func PTYSupported() bool { return ptySupported() }

// secretBytes is the entropy of a session handle (32 bytes → 256 bits,
// base64url-encoded to a 43-char opaque string). The handle is the only
// thing the websocket route authenticates against, so it must be
// unguessable; it is minted only by the Origin-checked launch POST.
const secretBytes = 32

// newToken mints an opaque base64url session identifier from crypto/rand.
func newToken() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("termsession: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
