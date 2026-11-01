// Package hostfile is the one member-level editor for a HOST application's
// own config file (surface-gap lane w8-writers: Zed's settings.json, Visual
// Studio's user .mcp.json, a JetBrains IDE's mcp.json, AiderDesk's
// mcp-servers.json): files Observer did not create, that hold the user's own
// settings and sometimes a credential, and that a host app rewrites itself.
//
// One edit is one member (a path of object keys) set or removed through
// internal/credfile.SetMember, which keeps every other byte, comment and
// member order and verifies the result value for value before it is
// returned. Around that this package owns the I/O rules every such writer
// follows:
//
//   - the file's directory must already exist as a real directory (the host
//     app created it); Observer never creates a host's config directory;
//   - neither the directory nor the file may be a symbolic link, so an edit
//     never follows a link out of the host's tree;
//   - the read is the bounded regular-file read (internal/regularfile);
//   - the prior bytes are kept as a displaced copy, a bounded backup ring
//     beside the file (internal/fsatomic.KeepDisplacedCopy), unless the
//     caller sets NoBackup for a file that may hold a credential (the
//     credential-file rule is no copy beside it);
//   - the write is atomic and durable (internal/fsatomic.WriteFile), keeps
//     the file's permission bits, and is refused under a test binary outside
//     its temp root (internal/testwriteguard);
//   - no value read from the file reaches an error message.
//
// It holds no table of hosts and no policy: the callers (internal/mcpregister,
// internal/proxyroute) own which file, which member and the live-check gate.
package hostfile
