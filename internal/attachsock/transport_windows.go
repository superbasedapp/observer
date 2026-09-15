//go:build windows

package attachsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// transport_windows.go is the Windows named-pipe transport (audit DI-09 full;
// docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §3.5).
//
// Why a pipe and not the AF_UNIX socket Go can bind here: net.Listen("unix",…)
// DOES work on Windows, but the security model the unix transport relies on
// does NOT. os.Chmod writes no ACL (Perm() reads back 0777 whatever we set),
// Windows AF_UNIX does not enforce file permissions on connect, and there is
// no flock for the live-daemon guard — so a socket bound that way is readable
// and dialable by ANY local process. The attach channel carries the writer
// lease and, when [terminal.attach].forward_auth_env is on, the caller's own
// provider credentials, so serving it that way would be a privilege downgrade.
//
// A named pipe restores every property the socket had, through the mechanisms
// Windows actually enforces:
//
//   - Owner-only access: a PROTECTED DACL naming exactly the calling user's
//     SID and SYSTEM (see ownerOnlySDDL). Kernel-enforced at connect, with no
//     racy chmod-after-create step — the DACL is supplied AT creation.
//   - Off-box unreachability: a named pipe is reachable over SMB as
//     \\host\pipe\<name> where an AF_UNIX socket is not, so the DACL leads
//     with an explicit DENY for the NETWORK well-known group (S-1-5-2). Local
//     access is untouched; anything arriving over the network is refused by
//     the kernel before it reaches Serve.
//   - Live-daemon guard: winio creates the listener with
//     FILE_FLAG_FIRST_PIPE_INSTANCE, so a SECOND create on a name that already
//     exists fails with ERROR_ACCESS_DENIED. That is STRONGER than the unix
//     probe-dial: there is no stale object to reclaim, no unlink, and no steal
//     window at all (measured 2026-09-03 on Windows 11).
//
// The endpoint name embeds a HASH of the DB path (pipeEndpoint), never the
// path itself: the pipe namespace is machine-global and enumerable by every
// local process.

// pipeBufferSize is the kernel in/out buffer size hint for the pipe. The
// protocol's largest frame is a 64 KiB control frame (dataFrameMax is 32 KiB
// for stdin/output), so a 64 KiB buffer holds any single frame without forcing
// a partial write round-trip. It is a hint, not a limit — the pipe is a byte
// stream (MessageMode false), matching the length-prefixed framing.
const pipeBufferSize = 64 * 1024

// pipeDirectory is the Windows named-pipe filesystem namespace. Listing it is
// how we tell "the name is taken by a live daemon" from any other
// ERROR_ACCESS_DENIED, WITHOUT connecting to the pipe (a connect would consume
// a listening instance of the other daemon's pipe and leave it waiting out a
// handshake timeout).
const pipeDirectory = `\\.\pipe\`

// pipeTransport serves the attach channel over a Windows named pipe.
type pipeTransport struct{}

// defaultTransport is the named-pipe transport on this platform.
var defaultTransport Transport = pipeTransport{}

// Describe implements Transport.
func (pipeTransport) Describe() string { return TransportNamedPipe }

// Supported implements Transport: Windows serves attach over a named pipe
// whose protected, owner-only DACL is kernel-enforced (see ownerOnlySDDL).
func (pipeTransport) Supported() bool { return true }

// Endpoint implements Transport: the hashed named-pipe name for this DB path.
func (pipeTransport) Endpoint(dbPath string) (string, error) {
	if strings.TrimSpace(dbPath) == "" {
		return "", errors.New("attachsock.Endpoint: empty observer DB path")
	}
	return pipeEndpoint(dbPath), nil
}

// Dial implements Transport: connect to the pipe, bounded by timeout and ctx.
// The ErrDaemonUnreachable wrapping belongs to the package-level Dial, so this
// returns the raw dial error (a missing pipe surfaces as ERROR_FILE_NOT_FOUND,
// the "daemon is not running" case).
func (pipeTransport) Dial(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return winio.DialPipeContext(dctx, endpoint)
}

// Listen implements Transport: create the pipe with an owner-only protected
// DACL and return the accepting listener. A name a live daemon already holds
// is refused as ErrSocketLiveDaemon — never taken over.
func (pipeTransport) Listen(endpoint string) (net.Listener, error) {
	sddl, err := ownerOnlySDDL()
	if err != nil {
		// No SID, no owner-only DACL — refuse rather than fall back to a
		// looser descriptor (which is exactly the privilege downgrade this
		// transport exists to avoid).
		return nil, fmt.Errorf("attachsock.ListenSocket: resolve owner SID for the pipe DACL: %w", err)
	}
	ln, err := winio.ListenPipe(endpoint, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		MessageMode:        false,
		InputBufferSize:    pipeBufferSize,
		OutputBufferSize:   pipeBufferSize,
	})
	if err != nil {
		// FILE_FLAG_FIRST_PIPE_INSTANCE turns "the name already exists" into
		// ERROR_ACCESS_DENIED. That errno alone is ambiguous (a genuinely
		// inaccessible object would give it too), so confirm by ENUMERATING
		// the pipe namespace rather than connecting.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && pipeNameExists(endpoint) {
			return nil, fmt.Errorf(
				"attachsock.ListenSocket: %w at %q — another observer daemon is serving the attach channel for this DB",
				ErrSocketLiveDaemon, endpoint)
		}
		return nil, fmt.Errorf("attachsock.ListenSocket: listen pipe %q: %w", endpoint, err)
	}
	return ln, nil
}

// ownerOnlySDDL builds the pipe's security descriptor: a PROTECTED DACL (no
// inheritance from the namespace) that denies the NETWORK group and grants
// generic-all to exactly the calling user's SID and to SYSTEM —
//
//	D:P(D;;GA;;;NU)(A;;GA;;;<user SID>)(A;;GA;;;SY)
//
// Two deliberate choices, both measured on Windows 11 (2026-09-03):
//
//   - The user's SID is RESOLVED from the process token rather than written as
//     the OWNER RIGHTS well-known SID (`OW`, S-1-3-4). `OW` does apply — the
//     kernel accepts it and the ACE lands — but it grants access to whoever
//     the object's OWNER turns out to be, and an ELEVATED process's default
//     token owner is BUILTIN\Administrators, which would silently widen the
//     grant from "this user" to "any local administrator". The resolved SID is
//     unambiguous, unaffected by elevation, and assertable in a test.
//   - The DENY for NETWORK (S-1-5-2) closes the one way a pipe is weaker than
//     an AF_UNIX socket: pipes are reachable over SMB as \\host\pipe\<name>.
//     A deny ACE is placed first (canonical order) and never affects a local
//     logon session.
//
// GA (generic all) is mapped by the kernel to FILE_ALL_ACCESS (0x1F01FF) on
// the created object; the DACL test asserts the applied form, not the string.
func ownerOnlySDDL() (string, error) {
	// GetCurrentProcessToken returns a TOKEN_QUERY pseudo-handle — enough for
	// GetTokenUser and, being a pseudo-handle, never closed.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get token user: %w", err)
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return "", errors.New("token user SID is empty")
	}
	return fmt.Sprintf("D:P(D;;GA;;;NU)(A;;GA;;;%s)(A;;GA;;;SY)", sid), nil
}

// pipeNameExists reports whether a named pipe with this endpoint's name is
// currently present in the machine's pipe namespace. It ENUMERATES the
// namespace (which is a directory listing, no handle to the pipe itself) so a
// live daemon's pipe is never connected to just to answer the question. A
// listing failure returns false — the caller then reports the raw create
// error, which is the honest degradation.
func pipeNameExists(endpoint string) bool {
	name := strings.TrimPrefix(endpoint, pipeDirectory)
	if name == "" || name == endpoint {
		return false // not a \\.\pipe\ name — nothing to enumerate
	}
	entries, err := os.ReadDir(pipeDirectory)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), name) {
			return true
		}
	}
	return false
}
