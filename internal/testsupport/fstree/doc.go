// Package fstree writes small file trees for tests: a map of slash-separated
// paths, relative to a root, to file bodies. Each file's parent directories
// are created first. Any error fails the test at once (t.Fatal).
//
// It replaces the same "write map[string]string under a temp dir" helper
// that the security scanning tests had copied into seven files.
//
// TEST SUPPORT ONLY: no production command or package may import it
// (tests/invariant/vendormock_boundary_test.go).
package fstree
