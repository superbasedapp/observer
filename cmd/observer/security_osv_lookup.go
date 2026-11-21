//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_osv_lookup.go is the OSV record read of get_security_findings and
// of `observer security explain --fix`: osvdb.DetailLookup over the LOCAL
// store the dashboard's dependency drawer reads (<config dir>/security/osv).
// There is no network path. Only the record's ranges, ids and aliases feed
// fixed_version and the exploit lookup; its prose never reaches the MCP
// answer. The exploit lookup (securityLocalExploitLookup) reads the KEV and
// EPSS data installed in the same store (osvdb.ExploitLookup). With
// sbo_omit_security_deps the store is not in the build
// (security_osv_lookup_omit.go).

// securityLocalOSVDir is the OSV store beside configPath ("": the default
// config path), "" when it cannot be resolved.
func securityLocalOSVDir(configPath string) string {
	resolved, err := config.ResolveGlobalPath(configPath)
	dir := secposture.LayoutFor(resolved).Dir
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "osv")
}

// securityLocalOSVLookup returns the record lookup for the OSV store beside
// configPath ("": the default config path).
func securityLocalOSVLookup(configPath string) func(eco, id string) ([]byte, error) {
	return osvdb.DetailLookup(securityLocalOSVDir(configPath))
}

// securityLocalExploitLookup returns the KEV and EPSS lookup of the OSV
// store beside configPath: installed, verified files only, no request.
func securityLocalExploitLookup(configPath string) func(ids []string) secexploit.Exploit {
	return osvdb.ExploitLookup(securityLocalOSVDir(configPath))
}
