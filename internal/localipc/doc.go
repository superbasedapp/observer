// Package localipc is the owner-only local IPC transport (lane MP-L1K,
// T-715): an AF_UNIX socket under a 0700 directory on unix, a named pipe
// with a protected owner-only DACL on Windows, honestly unsupported
// elsewhere. It moved out of internal/attachsock (which still re-exports the
// few names its callers use) so the MCP relay's IPC (internal/mcprelay) and
// the terminals component's attach channel share one transport, and a build
// without terminals keeps the relay's IPC. The endpoint naming is unchanged;
// the errors now name this package.
package localipc
