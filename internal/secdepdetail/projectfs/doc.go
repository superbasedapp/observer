// Package projectfs is the contained lockfile read for the view-time
// dependency detail (internal/secdepdetail): it reads one project-relative
// file under a project root, refusing a path that climbs out of the root
// (a "..", an absolute path, a volume name, a symlink escape) and a file
// over the size cap. It is the I/O half secdepdetail leaves to its caller
// (secdepdetail stays pure); the MCP tool get_security_findings injects it
// as its ReadFile. Errors are secdepdetail's own (ErrOutsideProject,
// ErrFileTooLarge) so Build maps them onto a reason.
package projectfs
