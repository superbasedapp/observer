package attachsock

import (
	"path/filepath"
	"strings"
	"testing"
)

// transport_test.go holds the PLATFORM-NEUTRAL transport tests: the endpoint
// naming (both formulas are pure functions, so both are testable from any
// host) and the shared skip helper for tests that exercise AF_UNIX-specific
// behaviour. Windows-only behaviour (the pipe DACL, the first-instance
// live-daemon guard, a pipe round trip) lives in transport_windows_test.go.

// skipUnlessUnixSocketTransport skips a test whose subject is the AF_UNIX
// transport's own behaviour — 0700 parent dirs, 0600 socket modes, the
// stale-socket probe-dial, UNIX_PATH_MAX — when this platform's default
// transport is something else. It dispatches on the transport's SHAPE
// (Describe), never on GOOS (CLAUDE.md #3).
func skipUnlessUnixSocketTransport(t *testing.T) {
	t.Helper()
	if got := DefaultTransport().Describe(); got != TransportUnixSocket {
		t.Skipf("default transport is %q, not %q — this test pins AF_UNIX-socket behaviour", got, TransportUnixSocket)
	}
}

// TestEndpointIsStableAndHashed pins both endpoint formulas at once, from any
// host, because both are pure:
//
//   - the unix endpoint is the on-disk socket path under the DB dir;
//   - the Windows endpoint is a HASH of the DB path — stable for one path,
//     distinct for different paths, and leaking NO component of the path into
//     the machine-global pipe namespace.
func TestEndpointIsStableAndHashed(t *testing.T) {
	const dbA = `C:\Users\someone\.observer\observer.db`
	const dbB = `C:\Users\someone\second\observer.db`

	// Stable: the same DB path always resolves to the same pipe.
	if got, again := pipeEndpoint(dbA), pipeEndpoint(dbA); got != again {
		t.Fatalf("pipeEndpoint is not stable: %q vs %q", got, again)
	}
	// Distinct: two DBs are two channels, never one shared pipe.
	if pipeEndpoint(dbA) == pipeEndpoint(dbB) {
		t.Fatalf("pipeEndpoint(%q) collided with pipeEndpoint(%q)", dbA, dbB)
	}
	// Case/separator-insensitive, because Windows treats those spellings as
	// the same file — otherwise a second daemon on the same DB would get its
	// own pipe and the live-daemon guard would never fire.
	if pipeEndpoint(dbA) != pipeEndpoint(strings.ToUpper(dbA)) {
		t.Fatalf("pipeEndpoint is case-sensitive; %q and its upper-case spelling differ", dbA)
	}
	if pipeEndpoint(dbA) != pipeEndpoint(strings.ReplaceAll(dbA, `\`, "/")) {
		t.Fatalf("pipeEndpoint is separator-sensitive for %q", dbA)
	}

	// Shape: prefix + exactly pipeNameHexLen lower-case hex characters.
	ep := pipeEndpoint(dbA)
	if !strings.HasPrefix(ep, pipeNamePrefix) {
		t.Fatalf("pipeEndpoint = %q, want prefix %q", ep, pipeNamePrefix)
	}
	hexPart := strings.TrimPrefix(ep, pipeNamePrefix)
	if len(hexPart) != pipeNameHexLen {
		t.Fatalf("pipeEndpoint hash part = %q (%d chars), want %d", hexPart, len(hexPart), pipeNameHexLen)
	}
	for _, r := range hexPart {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("pipeEndpoint hash part %q contains a non-hex character %q", hexPart, r)
		}
	}

	// No path component of the DB path may appear in the pipe name — the pipe
	// namespace is machine-global and enumerable by every local process.
	for _, leak := range []string{"someone", "observer.db", ".observer", "Users", "C:"} {
		if strings.Contains(strings.ToLower(ep), strings.ToLower(leak)) {
			t.Fatalf("pipeEndpoint %q leaks the DB path component %q", ep, leak)
		}
	}
}

// TestSocketPathFormula pins the on-disk attach path both the daemon and the
// client derive (and whose PARENT is the owner-only attach directory that
// holds the durable resume-claim flock on every platform).
func TestSocketPathFormula(t *testing.T) {
	cases := []struct {
		dbPath string
		want   string
	}{
		{filepath.Join("/home/u/.observer", "observer.db"), filepath.Join("/home/u/.observer", "attach", "attach.sock")},
		{filepath.Join("/var/lib/observer", "observer.db"), filepath.Join("/var/lib/observer", "attach", "attach.sock")},
		{"observer.db", filepath.Join("attach", "attach.sock")},
	}
	for _, tc := range cases {
		if got := SocketPath(tc.dbPath); got != tc.want {
			t.Errorf("SocketPath(%q) = %q, want %q", tc.dbPath, got, tc.want)
		}
	}
}

// TestEndpointMatchesTransport pins the ONE endpoint both sides resolve: on
// the unix transport it is exactly SocketPath (so a daemon that listened on it
// and a client that dials it can never drift); on the pipe transport it is the
// hashed pipe name, which is deliberately NOT a filesystem path.
func TestEndpointMatchesTransport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	ep, err := Endpoint(dbPath)
	if err != nil {
		t.Fatalf("Endpoint(%q): %v", dbPath, err)
	}
	switch DefaultTransport().Describe() {
	case TransportUnixSocket:
		if want := SocketPath(dbPath); ep != want {
			t.Fatalf("Endpoint = %q, want the socket path %q", ep, want)
		}
	case TransportNamedPipe:
		if want := pipeEndpoint(dbPath); ep != want {
			t.Fatalf("Endpoint = %q, want the pipe name %q", ep, want)
		}
		if ep == SocketPath(dbPath) {
			t.Fatal("Endpoint returned a filesystem path on the named-pipe transport")
		}
	default:
		t.Skipf("no transport on this platform (%q)", DefaultTransport().Describe())
	}
}
