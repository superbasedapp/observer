// Package filehash hashes a file's bytes. SHA256 is the one whole-file
// SHA-256 helper the cmd binaries share (observer's update and sandbox setup
// paths, observer-org's and observer-mcpgw's agent-access doctors); before it
// each kept its own copy.
//
// It reads the file it is given and nothing else: no path checks, no symlink
// policy, no size cap. A caller that needs those (a capped or no-follow read)
// does them first. Errors from opening or reading the file are returned
// unwrapped, so each caller keeps its own wording.
package filehash
