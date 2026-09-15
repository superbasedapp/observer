package attachsock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// transport.go holds the OS-abstraction seam for the attach control channel
// (audit DI-09 full;
// docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §3.5).
//
// The protocol above it is transport-agnostic: framing, Serve and the client's
// Attach speak net.Listener / net.Conn only. What differs per OS is (a) how the
// endpoint is NAMED, (b) how it is created with an owner-only security model,
// and (c) how it is dialed:
//
//   - unix (transport_unix.go): an AF_UNIX socket at <dir(dbPath)>/attach/
//     attach.sock inside a 0700 directory, with a held flock as the
//     live-daemon guard;
//   - windows (transport_windows.go): a named pipe \\.\pipe\observer-attach-
//     <16 hex of sha256(dbPath)> with a protected, owner-only DACL, where the
//     "first pipe instance" semantics ARE the live-daemon guard;
//   - anything else (transport_other.go): honestly unsupported.
//
// Exactly one transport is compiled in per platform and exposed as
// DefaultTransport(). Everything else in the package — and every caller —
// stays free of OS branches (CLAUDE.md #3: branch on capability, never on
// identity).

// Transport names, reported by Describe() for logs and doctor output.
const (
	// TransportUnixSocket is the AF_UNIX socket transport (unix).
	TransportUnixSocket = "unix socket"
	// TransportNamedPipe is the Windows named-pipe transport.
	TransportNamedPipe = "named pipe"
	// TransportNone is the honest placeholder where no transport exists.
	TransportNone = "unsupported"
)

// socketDirName / socketFileName name the on-disk attach directory and its
// AF_UNIX socket. The DIRECTORY exists on every platform (the durable
// resume-claim flock lives beside the socket, see resumeclaim_unix.go); only
// the socket file itself is unix-specific.
const (
	socketDirName  = "attach"
	socketFileName = "attach.sock"
)

// pipeNamePrefix is the Windows named-pipe namespace prefix plus our object
// name stem. The DB path is hashed after it (see pipeEndpoint) so two daemons
// with different DBs never collide and no filesystem path is leaked into the
// global object namespace.
const pipeNamePrefix = `\\.\pipe\observer-attach-`

// pipeNameHexLen is how many hex characters of the sha256 digest go into the
// pipe name (16 hex = the first 8 bytes). Enough to make an accidental
// collision between two of one operator's DB paths a non-event, short enough
// to keep the object name readable.
const pipeNameHexLen = 16

// ErrUnsupported is returned by a platform with no attach transport at all
// (plan9, js/wasm …). It is NEVER returned by unix or Windows: both have a
// real, owner-only transport.
var ErrUnsupported = errors.New("attachsock: no attach transport on this platform")

// ErrSocketLiveDaemon is returned by a transport's Listen when the endpoint is
// already being served by a live daemon. On unix that is detected by a HELD
// listen lock (A3-5) and secondarily by a successful probe-dial (A9); on
// Windows the OS itself refuses a second FIRST_PIPE_INSTANCE create, which is
// a STRONGER guard (no probe, no unlink, no steal window). We never take an
// endpoint away from a running server.
var ErrSocketLiveDaemon = errors.New("attachsock: attach socket already served by a live daemon")

// Transport is one OS's attach channel: how the endpoint is named, listened on
// and dialed. Exactly one implementation is compiled in per platform.
type Transport interface {
	// Endpoint returns the attach endpoint for an observer DB path — the value
	// BOTH the daemon's Listen and the client's Dial use, so the two can never
	// drift. It fails rather than return an unusable endpoint (e.g. a unix
	// socket path past UNIX_PATH_MAX).
	Endpoint(dbPath string) (string, error)
	// Listen creates the endpoint with this platform's owner-only security
	// model and returns the accepting listener. It refuses to take over an
	// endpoint a live daemon is serving (ErrSocketLiveDaemon).
	Listen(endpoint string) (net.Listener, error)
	// Dial connects to endpoint, bounded by timeout and ctx.
	Dial(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error)
	// Describe names the transport for logs and doctor output ("unix socket",
	// "named pipe").
	Describe() string
	// Supported reports whether this platform can actually serve attach.
	Supported() bool
}

// DefaultTransport returns the transport compiled in for this platform.
func DefaultTransport() Transport { return defaultTransport }

// Supported reports whether this OS has an attach transport whose owner-only
// security model actually holds (audit DI-09 §3.5). True on unix (AF_UNIX
// under a 0700 directory) and on Windows (a named pipe with a protected,
// owner-only DACL); false where neither exists. Callers must not serve the
// attach channel when it is false — the channel carries the writer lease and,
// when [terminal.attach].forward_auth_env is on, the caller's own provider
// credentials.
func Supported() bool { return defaultTransport.Supported() }

// Endpoint returns the attach endpoint for dbPath on this platform: the
// AF_UNIX socket path on unix, the named-pipe name on Windows. It is the
// single source of truth the daemon's listener and the `--attach` client both
// resolve.
func Endpoint(dbPath string) (string, error) { return defaultTransport.Endpoint(dbPath) }

// SocketPath returns the ON-DISK attach socket path for an observer DB path:
// <dir(dbPath)>/attach/attach.sock. On unix it IS the transport endpoint; on
// every platform its PARENT is the owner-only attach directory that holds the
// durable resume-claim flock, which is why the formula stays platform-neutral.
func SocketPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), socketDirName, socketFileName)
}

// pipeEndpoint returns the Windows named-pipe name for an observer DB path:
// \\.\pipe\observer-attach-<16 hex of sha256(normalized dbPath)>. Hashing the
// path (rather than embedding it) keeps two daemons with different DBs on
// different pipes while leaking NO filesystem path into the machine-global
// pipe namespace, which every local process can enumerate.
//
// The key is normalized first — cleaned, separators folded to `\`, lowercased
// — so the two spellings of one DB path that Windows treats as the same file
// land on the same pipe, which is what makes the "pipe already exists"
// live-daemon guard actually fire for a second daemon on the same DB. It is
// pure and platform-neutral so the naming can be tested from any host.
func pipeEndpoint(dbPath string) string {
	key := strings.ToLower(strings.ReplaceAll(filepath.Clean(dbPath), "/", `\`))
	sum := sha256.Sum256([]byte(key))
	return pipeNamePrefix + hex.EncodeToString(sum[:])[:pipeNameHexLen]
}

// unixPathMax is UNIX_PATH_MAX: the sun_path buffer's total size in a
// sockaddr_un, INCLUDING the trailing NUL terminator the kernel appends. A
// path of unixPathMax-1 bytes (107) fits with the NUL; unixPathMax bytes (108)
// does not — this is the same 108 on Linux, macOS and (measured, audit DI-09
// §3.5) Windows's AF_UNIX implementation, not a platform-specific constant.
const unixPathMax = 108

// checkSocketPathLength returns an actionable error when path is too long to
// bind as an AF_UNIX socket (DI-09; the raw bind error — "invalid argument" /
// WSAEINVAL — named neither cause nor fix). It guards the UNIX transport only
// (the Windows pipe namespace has no such limit), but it is pure — no
// filesystem access, no OS dependency — so it lives here and every length
// right at and around the boundary is unit-testable from any host.
func checkSocketPathLength(path string) error {
	if n := len(path); n >= unixPathMax {
		return fmt.Errorf(
			"attach socket path is %d bytes; the OS limit is %d — set [observer].db_path to a shorter directory",
			n, unixPathMax-1)
	}
	return nil
}

// ListenSocket creates the attach endpoint through this platform's transport
// and returns the accepting listener. The name is historical (the unix socket
// came first); the endpoint is whatever Endpoint returned for the daemon's DB
// path — an AF_UNIX socket path on unix, a named-pipe name on Windows.
func ListenSocket(endpoint string) (net.Listener, error) {
	return defaultTransport.Listen(endpoint)
}
