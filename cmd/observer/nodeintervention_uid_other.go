//go:build !windows

package main

import "os"

// nodeInterventionAuthorityUID is the OS user id every caller passes to the
// node intervention authority: the daemon user's uid.
func nodeInterventionAuthorityUID() int { return os.Getuid() }
