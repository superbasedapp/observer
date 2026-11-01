// Package secipc is the security pillar's quick-scan request channel
// (security pillar plan section 4.8, revision 2.4 [JSP-11, JSP-2]): the
// hook process asks the daemon for the commit quick scan over the
// owner-only local IPC transport internal/localipc (an AF_UNIX socket
// under a 0700 directory on unix, a named pipe with an owner-only DACL on
// Windows), never TCP loopback and with no token. One request line, one
// response line, both size-capped and deadline-bounded.
//
// The package carries the wire shape, the client and a server that calls
// an injected scanner; it runs no scan itself (security Phase C supplies
// the scanner). It belongs to the `security` module root and is compiled
// out with sbo_omit_security.
package secipc
