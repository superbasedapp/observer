//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
)

// securityLocalOSVLookup answers "database not installed": the OSV store
// belongs to security.deps, which is not in this build.
func securityLocalOSVLookup(string) func(eco, id string) ([]byte, error) {
	return func(string, string) ([]byte, error) { return nil, secdepdetail.ErrDatabaseNotInstalled }
}

// securityLocalExploitLookup is nil: the exploit data lives in the OSV store,
// so every finding reads "exploit data unavailable".
func securityLocalExploitLookup(string) func(ids []string) secexploit.Exploit { return nil }
