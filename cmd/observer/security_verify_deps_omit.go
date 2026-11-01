//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// verifyDependencyCheck without the security.deps component: the install
// index cannot be read in this build.
func verifyDependencyCheck(string) (secverify.DependencyCheck, error) {
	return nil, errors.New("the install index is not in this build (security.deps omitted)")
}
