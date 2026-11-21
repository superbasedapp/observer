// Package callerid decides whether a local caller of the loopback dashboard
// runs inside an Observer sandbox box (security ledger LAUNCH-1, lane
// callerid). The loopback dashboard cannot tell the owner's browser from a
// process in a box that shares the host's network or loopback (bwrap's
// egress = "host", the MXC rows): any token the page can fetch, the box
// can fetch too (SR27-SBX-1 (b)). What it can do is identify the process at
// the other end of the TCP connection and ask whether that process
// descends from a live box.
//
// The package holds the pure part: the ordered decision table (Decide), the
// ancestry walk over an injected parent lookup (Ancestors, InBox), and the
// parsers of the Linux procfs records the identification reads
// (ParseProcNetTCP, ParseStat). It reads no file, opens no socket and
// imports no os, net, net/http, database/sql, os/exec or fsnotify
// (imports_test.go); internal/peerproc does the per-platform I/O and
// cmd/observer wires both into the dashboard's request path.
package callerid
