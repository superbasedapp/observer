// Package projectmatch is the PURE node half of the project audience on the
// guard bundle rail (security plan section 7.11, spike JSP-10, lane sec-p):
// where the org's project envelopes, the signed mapping and the daemon's match
// records live on disk (Layout), the v3 accept gate (AcceptDelivery), and the
// match of one directory's identity hashes against the org-signed mapping
// (SignalsFor, Index, Resolve).
//
// The node never asserts a project. It computes its own identity hashes from
// the repository's git files (git.ResolveIdentity on the main repository's
// identity, so a linked worktree matches its main project; never an exec on
// this path) plus a root commit the store already cached, and looks them up in
// data the org signed. Several matches give the strictest of all: every
// matched project's envelope is loaded.
//
// It imports no database, HTTP, process or file-watching package
// (imports_test.go). Callers read and write the files; this package decides
// what they mean.
package projectmatch
