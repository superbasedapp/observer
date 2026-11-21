//go:build !sbo_omit_security && sbo_omit_security_deps

package dashboard

import (
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
)

// securityOSVLookup answers "database not installed": the OSV store
// belongs to security.deps, which is not in this build, so the drawer
// still shows the package and its lockfile location but no advisory.
func (s *Server) securityOSVLookup() func(eco, id string) ([]byte, error) {
	return func(string, string) ([]byte, error) { return nil, secdepdetail.ErrDatabaseNotInstalled }
}

// securityExploitLookup is nil: the KEV and EPSS data live in the OSV
// store, so every dependency finding reads "exploit data unavailable".
func (s *Server) securityExploitLookup() func(ids []string) secexploit.Exploit { return nil }
