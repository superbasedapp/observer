// Package secask is the install gate's ask channel, the `security.ask`
// local egress lane (security pillar plan section 8.3 "The hook path",
// spike JSP-11): on an online-cache miss for a package name, the hook asks
// the daemon over the owner-only local IPC transport internal/localipc (a
// unix socket under a 0700 directory, or a named pipe with an owner-only
// DACL), never TCP loopback and with no token, and waits at most the
// install-gate budget. One JSON line each way, strict decoding, a 16 KiB
// answer cap, an answer must name the package asked about, and one deadline
// covers dial, write and read. A daemon that is down, slow or wrong is an
// error the gate records as online_unknown, never as a clean answer.
//
// The package carries the wire shape, the client and a server that calls
// an injected answer function; it does no lookup itself. It belongs to the
// security.deps component and is compiled out with sbo_omit_security_deps.
package secask
