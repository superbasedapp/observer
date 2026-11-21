//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_depdetail_osv.go is the drawer's OSV store read (a
// feature-owned file of security.deps: with sbo_omit_security_deps
// security_depdetail_osv_omit.go answers "database not installed" and
// "exploit data unavailable"). It reads the node's LOCAL OSV store only:
// records through osvdb.DetailLookup (the one lookup the MCP tool and
// `explain --fix` use too) and the installed KEV and EPSS data through
// osvdb.ExploitLookup; there is no network path.

// securityOSVDir is the node's OSV store directory, "" when the config path
// cannot be resolved.
func (s *Server) securityOSVDir() string {
	resolved, err := config.ResolveGlobalPath(s.opts.ConfigPath)
	dir := secposture.LayoutFor(resolved).Dir
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "osv")
}

// securityOSVLookup returns the record lookup the dependency detail
// injects, its errors mapped onto secdepdetail's.
func (s *Server) securityOSVLookup() func(eco, id string) ([]byte, error) {
	return osvdb.DetailLookup(s.securityOSVDir())
}

// securityExploitLookup returns the KEV and EPSS lookup over the exploit
// data installed in the OSV store (verified against its records and the
// age floor; anything else answers "unavailable").
func (s *Server) securityExploitLookup() func(ids []string) secexploit.Exploit {
	return osvdb.ExploitLookup(s.securityOSVDir())
}
