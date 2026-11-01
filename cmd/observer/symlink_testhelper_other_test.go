//go:build !windows

package main

// symlinkPrivilegeMissing is false off Windows: making a link needs no
// privilege there.
func symlinkPrivilegeMissing(error) bool { return false }
