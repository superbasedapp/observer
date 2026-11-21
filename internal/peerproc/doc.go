// Package peerproc finds the local process at the other end of a TCP
// connection the daemon accepted, and that process's ancestry (security
// ledger LAUNCH-1, lane callerid). It is the I/O half of the loopback
// caller check; internal/callerid holds the pure decision and the parsers.
//
//   - Linux: the client socket's inode from /proc/self/net/tcp and tcp6
//     (the daemon's own network namespace, which a box that reaches its
//     loopback shares), the process holding it from /proc/<pid>/fd, the
//     ancestry from /proc/<pid>/stat.
//   - Windows: the owning process from GetExtendedTcpTable (iphlpapi), the
//     ancestry from a process snapshot, each parent checked to have started
//     no later than its child, so a reused parent pid ends the walk.
//   - Elsewhere (macOS): not offered (ErrUnsupported). No macOS box reaches
//     the host's loopback: Seatbelt refuses the host tier and the Apple
//     container row has its own network.
//
// StartToken names one start of one process (Linux: the boot id and the
// start time in ticks; Windows: the creation time; macOS: the start time
// from sysctl kern.proc.pid), so a pid recorded earlier is not mistaken
// for a later process that reused it.
package peerproc
