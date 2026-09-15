package attachsock

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAttachSockPathLengthGuard pins the DI-09 interim guard (audit DI-09;
// docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §3.5,
// §6.7): a path of exactly unixPathMax-1 (107) bytes is fine, one of
// unixPathMax (108) bytes is refused with an actionable message naming both
// the actual length and the limit. checkSocketPathLength is a pure length
// check — no filesystem touched — so every case here is constructed by exact
// byte length, independent of t.TempDir()'s own (host-dependent) length.
func TestAttachSockPathLengthGuard(t *testing.T) {
	// pathOfLen builds an absolute-looking path of exactly n bytes using a
	// repeated filler component, so the boundary is exact regardless of the
	// path separator convention on the host running the test.
	pathOfLen := func(n int) string {
		if n <= 0 {
			return ""
		}
		s := strings.Repeat("a", n)
		return s
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "empty path", path: "", wantErr: false},
		{name: "well under the limit", path: pathOfLen(43), wantErr: false},
		{name: "exactly 107 bytes (fits with the NUL)", path: pathOfLen(107), wantErr: false},
		{name: "exactly 108 bytes (UNIX_PATH_MAX, no room for the NUL)", path: pathOfLen(108), wantErr: true},
		{name: "well over the limit", path: pathOfLen(200), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSocketPathLength(tt.path)
			if tt.wantErr && err == nil {
				t.Fatalf("checkSocketPathLength(%d bytes) = nil, want an error", len(tt.path))
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("checkSocketPathLength(%d bytes) = %v, want nil", len(tt.path), err)
			}
			if err != nil {
				msg := err.Error()
				for _, want := range []string{"attach socket path is", "107", "[observer].db_path", "shorter directory"} {
					if !strings.Contains(msg, want) {
						t.Errorf("error %q missing expected substring %q", msg, want)
					}
				}
			}
		})
	}
}

// TestListenSocketRejectsOverlongPathEarly confirms the unix transport's
// Listen surfaces the actionable guard (not the bare, causeless "bind: invalid
// argument" a real net.Listen would eventually return) — and does so WITHOUT
// creating the parent directory, i.e. genuinely early. It is skipped where the
// default transport is not the AF_UNIX socket: UNIX_PATH_MAX is a property of
// sockaddr_un, and the Windows pipe namespace has no equivalent limit.
func TestListenSocketRejectsOverlongPathEarly(t *testing.T) {
	skipUnlessUnixSocketTransport(t)
	dir := t.TempDir()
	// Build a path clearly at/over the 108-byte limit regardless of how long
	// t.TempDir() itself is, by padding a deeply nested filler component.
	longName := strings.Repeat("x", 200)
	sockPath := filepath.Join(dir, longName, "attach.sock")

	if _, err := ListenSocket(sockPath); err == nil {
		t.Fatal("expected ListenSocket to refuse an over-limit path")
	} else if !strings.Contains(err.Error(), "the OS limit is 107") {
		t.Fatalf("ListenSocket error = %v, want the actionable path-length message", err)
	}
	// The guard must fire before any directory creation (genuinely early).
	if _, statErr := os.Stat(filepath.Join(dir, longName)); statErr == nil {
		t.Fatal("ListenSocket created the parent dir before checking the path length")
	}
}

// TestSupportedIsTrueWhereTransportExists pins Supported() to the TRANSPORT,
// not to a platform allow-list (audit DI-09 full, §3.5): it is true exactly
// where a real owner-only transport is compiled in — the AF_UNIX socket on
// unix, the named pipe on Windows — and false only on a platform that has
// neither. This supersedes the T7 interim, where Windows was false because no
// pipe transport existed yet.
func TestSupportedIsTrueWhereTransportExists(t *testing.T) {
	tr := DefaultTransport()
	if got, want := Supported(), tr.Supported(); got != want {
		t.Fatalf("Supported() = %v but DefaultTransport().Supported() = %v — the two must not drift", got, want)
	}
	switch runtime.GOOS {
	case "windows":
		if !Supported() {
			t.Fatal("Supported() = false on windows, want true (the named-pipe transport exists)")
		}
		if got := tr.Describe(); got != TransportNamedPipe {
			t.Fatalf("Describe() = %q on windows, want %q", got, TransportNamedPipe)
		}
	case "plan9", "js", "wasip1", "ios":
		// No transport compiled in for these; Supported() must be honest.
		if Supported() {
			t.Fatalf("Supported() = true on GOOS=%s, want false", runtime.GOOS)
		}
	default:
		// Everything else in this repo's build matrix is unix.
		if !Supported() {
			t.Fatalf("Supported() = false on GOOS=%s, want true (the unix socket transport exists)", runtime.GOOS)
		}
		if got := tr.Describe(); got != TransportUnixSocket {
			t.Fatalf("Describe() = %q on GOOS=%s, want %q", got, runtime.GOOS, TransportUnixSocket)
		}
	}
}
