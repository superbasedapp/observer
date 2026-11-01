//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// security_managedpull_deps.go binds the managed pull's disclosure check to
// the package-checks child's own record (security_deps_daemon.go): the pull
// may switch the online check on only after the plan 8.3 disclosure was shown
// on this node.
func init() {
	securityDisclosureShown = func(configPath string) bool {
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return false
		}
		return readDepsDisclosure(secposture.LayoutFor(resolved).Dir).Shown()
	}
}
