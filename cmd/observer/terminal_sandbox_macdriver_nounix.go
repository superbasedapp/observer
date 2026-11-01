//go:build !unix && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "io/fs"

// ownedByMe has no owner to read here; the macOS drivers' helpers refuse to
// run on this platform anyway.
func ownedByMe(fs.FileInfo) bool { return false }
