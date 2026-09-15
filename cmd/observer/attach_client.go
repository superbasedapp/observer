package main

import (
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// attach_client.go holds the PLATFORM-NEUTRAL half of session-attach's CLI
// client (design 2026-07-19, Phase 1): the endpoint/socket-path resolvers, the
// resolved-input struct, the resume-hint composer, and the forwarded-argv
// builder. The interactive client itself — raw-mode terminal handling, signal
// plumbing, the /dev/tty reader, the stdio bridge — is POSIX-only and lives in
// attach_client_unix.go (`//go:build unix`); a `//go:build !unix` stub in
// attach_client_other.go returns an honest error so the tree cross-compiles
// (B2-1, design §6 decision 3). Note the split moved with DI-09 (T9): the
// DAEMON now serves the attach channel on Windows too (attachsock's Transport
// seam gives it a named pipe), so what the stub reports missing is the
// interactive CLIENT, not the channel. Everything a test needs on every
// platform (attachSocketPath / attachEndpoint / attachExtraArgs /
// nativeResumeHint) stays here so those tests keep running under
// Windows/darwin too.
//
// `observer <tool> --attach` becomes a thin PTY-proxy client: instead of
// exec'ing the tool as a child of the user's shell (the bare launcher), it asks
// the running daemon — over the owner-only attach channel (an AF_UNIX socket
// on unix, a named pipe on Windows; see attachsock's Transport seam) — to spawn
// the tool's PTY through the SAME termsession.Manager the dashboard drives. The
// operator's terminal is viewer #1; the dashboard can join as viewer #2 over
// the existing /ws/launch fan-out. Killing this client detaches (the child
// lives on under the daemon); Ctrl-C reaches the agent as a raw byte.

// attachSocketPath returns the ON-DISK attach socket path for a given observer
// DB path: <dir(dbPath)>/attach/attach.sock. It delegates to
// attachsock.SocketPath, which owns the formula, so the daemon and the client
// can never drift.
//
// Two distinct uses, and only one of them is the endpoint:
//
//   - on unix it IS the transport endpoint (the AF_UNIX socket the daemon
//     binds and the client dials), living in its own 0700 directory so the
//     parent-dir permission — not a racy chmod-after-listen — enforces
//     owner-only access (A1);
//   - on EVERY platform its parent is the owner-only attach DIRECTORY, which
//     also holds the durable resume-claim flock (attachsock.AcquireResumeClaim).
//     That is why this stays a filesystem path even on Windows, where the
//     endpoint is a named pipe with no filesystem location at all — use
//     attachEndpoint for the thing to listen on / dial.
func attachSocketPath(dbPath string) string {
	return attachsock.SocketPath(dbPath)
}

// attachEndpoint resolves the attach ENDPOINT for an observer DB path through
// the platform's transport: the AF_UNIX socket path on unix, the hashed
// named-pipe name on Windows. It is what `observer start` listens on and what
// the `--attach` client dials — the single source of truth both sides use, so
// they cannot drift. It fails rather than return an unusable endpoint (e.g. a
// socket path past UNIX_PATH_MAX, DI-09).
func attachEndpoint(dbPath string) (string, error) {
	return attachsock.Endpoint(dbPath)
}

// attachLaunch carries the resolved inputs for an `observer <tool> --attach`
// client session. proxyEnv is the tool-specific proxy-routing env the daemon
// forwards to the attached child ("KEY=VALUE" entries); it is nil/empty when
// the escape hatch (--no-proxy OR [terminal.attach].route_proxy=false) opts out
// OR when the tool routes without env vars (codex, whose inner launcher injects
// `-c openai_base_url`). The subcommand is resolved from the capability
// registry, never passed in.
type attachLaunch struct {
	// tool is the registry tool name (e.g. "claude-code", "codex").
	tool string
	// configPath is the --config override ("" = default).
	configPath string
	// proxyURL is the resolved proxy base URL, for the daemon-unreachable hint.
	proxyURL string
	// proxyEnv is the routing env forwarded to the attached child.
	proxyEnv []string
	// extraArgs are the allow-listed argv tokens forwarded to the inner
	// `observer <sub>` launcher: the routing escape hatch (--no-proxy-route),
	// the --proxy / --config overrides, forwarded wrapper flags (e.g.
	// --claude-path), and the operator's trailing tool args (`-- ...`).
	// Expressed in ARGV because the inner launcher self-routes regardless of
	// env, so an env-only escape hatch is a no-op (B2/B3).
	extraArgs []string
	// stderr receives human-facing status lines (never the child's output).
	stderr io.Writer
}

// nativeResumeHint composes the daemon-exit resume guidance from the tool's
// grounded ResumeSpec (session-attach design §2.4). When native resume is not
// yet grounded — the ResumeNone case that now covers 17 of the 19 attachable
// launchers (attach-all-launchers) — it degrades HONESTLY: for a launchable
// tool it points at the manual `observer <verb> --continue-from <id>` handover
// fork (the real mortality backstop for a daemon-restart-ends-the-session
// tool), and only falls back to the fully-generic phrase when even the launch
// verb is unknown. Dispatch is on the capability SHAPE (ResumeSpec kind +
// Handoff.Launch presence), never a tool-name branch (CLAUDE.md #3). This is
// the ONE seam where the "daemon restart = session over" reality lands for a
// ResumeNone tool — reportAttachResult's daemon-exit / conn-lost / input-stall
// branches interpolate it.
func nativeResumeHint(capab integration.Capability) string {
	if capab.Resume.Kind != integration.ResumeNative || capab.Resume.Subcommand == "" {
		if capab.Handoff.Launch != nil && capab.Handoff.Launch.Subcommand != "" {
			return fmt.Sprintf(
				"start a new session (`observer %s --continue-from <session-id>` carries a distilled handover)",
				capab.Handoff.Launch.Subcommand,
			)
		}
		return "resume it natively to continue"
	}
	switch capab.Resume.IDMechanism {
	case "flag:--resume":
		return fmt.Sprintf("resume it natively with `%s --resume <id>`", capab.Resume.Subcommand)
	case "subcommand:resume":
		return fmt.Sprintf("resume it natively with `%s resume <id>`", capab.Resume.Subcommand)
	case "positional":
		return fmt.Sprintf("resume it natively with `%s <id>`", capab.Resume.Subcommand)
	default:
		// The observer launcher tail is uniformly `--resume <id>` for every
		// ResumeNative tool regardless of the tool's own flag spelling, so
		// the fallback hint can always name the actionable observer form.
		return fmt.Sprintf("resume it natively with `observer %s --resume <id>`", capab.Resume.Subcommand)
	}
}

// attachExtraArgs builds the allow-listed argv the CLI attach client forwards to
// the inner `observer <sub>` launcher (B2/B3). It is deliberately EXPLICIT — a
// fixed set of flags observer understands plus the operator's `--` tool
// remainder — never a blind copy of the outer argv:
//
//   - --no-proxy-route  when the escape hatch is engaged (the inner launcher
//     then skips base-URL / `-c openai_base_url` injection);
//   - <proxyFlag> <url> when the operator overrode the proxy URL — the flag
//     NAME is the inner launcher's own proxy-override spelling (`--proxy` for
//     most, `--proxy-url` for hermes/pi), passed in so shared code never
//     branches on tool identity (CLAUDE.md #3); emitted only when BOTH
//     proxyFlag and proxyOverride are non-empty (a seed-only launcher with no
//     proxy flag passes proxyFlag="" and the override is dropped);
//   - --config <path>   when the outer invocation used a non-default config;
//   - passthrough...    launcher-specific wrapper flags the inner launcher
//     should honor (e.g. --claude-path/--codex-path, --no-app-server-check),
//     enumerated explicitly by each launcher (B2-6);
//   - -- <toolArgs...>  the operator's trailing tool args (`observer codex
//     --attach -- --model X`), so launcher state is not dropped.
func attachExtraArgs(noProxyRoute bool, proxyOverride, proxyFlag, configPath string, passthrough, toolArgs []string) []string {
	var args []string
	if noProxyRoute {
		args = append(args, "--no-proxy-route")
	}
	if proxyOverride != "" && proxyFlag != "" {
		args = append(args, proxyFlag, proxyOverride)
	}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	args = append(args, passthrough...)
	if len(toolArgs) > 0 {
		args = append(args, "--")
		args = append(args, toolArgs...)
	}
	return args
}
