// Package standin finds, for tests, a native executable that does one job
// under whatever name it is run as.
//
// The process-intervention and launcher tests copy a real ELF under a
// vendor's name (kilo, goose, codex, muse-bin-1.2.3, a "node" interpreter):
// the install manifest refuses a shell launcher, so a script cannot stand in,
// and the copy must keep running as that vendor's process. A multi-call
// coreutils picks its program from its own name instead. Ubuntu 25.10 and
// later ship uutils, where /bin/mkdir, /bin/sleep and /usr/bin/yes are hard
// links to one binary that prints "unknown program 'kilo'" and exits 1 under
// any other name (busybox behaves the same), so a copy of it exits at once
// and the test sees no process to bind.
//
// SingleProgramBinary tries each candidate, copies it under a foreign name
// and runs it once, and returns the first one that did its job there; Ubuntu
// keeps the GNU single-program binaries as gnu<util>. With none it skips the
// test and names the host limit.
//
// The finder is Linux-only (the callers are Linux process tests). The package
// imports only the standard library and is imported only from _test.go files
// (tests/invariant/vendormock_boundary_test.go).
package standin
