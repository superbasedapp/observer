// Package attachsock implements the owner-only control+stdio protocol that
// backs `observer <tool> --attach` (session-attach design 2026-07-19, Phase 1).
//
// It is a transport-pure package: it speaks net.Conn, encoding/json and io
// only. It imports none of the daemon's subsystems (termsession, termsvc,
// config, store) — both sides are defined against small local interfaces (Host,
// Session, ClientIO) that the cmd layer adapts to the real PTY registry. Types
// never leak past the seam.
//
// # Roles
//
//   - Server (daemon side): Serve accepts connections on the owner-only
//     endpoint, reads a spawn control frame, asks the Host to launch a daemon-owned
//     PTY, then bridges the PTY's output to the client and the client's stdin to
//     the PTY. A dropped client detaches (releases the writer + unsubscribes)
//     WITHOUT killing the child — the child lives on for the dashboard and other
//     viewers.
//   - Client (`observer <tool> --attach`): Attach dials the endpoint, sends the
//     spawn request, then pumps the operator's terminal stdin/stdout and window
//     resizes across the connection. TTY raw-mode and SIGWINCH handling belong to
//     the cmd layer, which feeds the Resize channel.
//
// # Wire format
//
// Each frame is a 4-byte big-endian payload length, a 1-byte frame type, then
// the payload. Control frames (type 1) carry JSON and are capped at 64 KiB; data
// frames (stdin type 2, output type 3) carry raw bytes and are capped at 32 KiB
// (larger writes are chunked). A malformed or oversized frame fails the
// connection with a protocol error. Control ops: client→server spawn/resize/
// detach; server→client spawned/exit/error.
//
// # Transport
//
// The endpoint itself is OS-specific and lives behind the Transport seam
// (transport.go): an AF_UNIX socket in a 0700 directory under the operator's
// ~/.observer/ on unix, a named pipe with a protected owner-only DACL on
// Windows (audit DI-09;
// docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §3.5).
// Both are owner-only and neither is reachable off-box — the unix socket is
// never bound to a network interface, and the Windows DACL denies the NETWORK
// group so the pipe's SMB reachability (\\host\pipe\…) is closed at the kernel
// (design §3.3). Framing, Serve and Attach speak net.Listener / net.Conn only
// and never branch on the platform.
package attachsock
