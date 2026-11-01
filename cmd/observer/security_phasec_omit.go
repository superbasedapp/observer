//go:build sbo_omit_security

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_phasec_omit.go stands in for security_phasec.go without the
// security module: the commit scanner gets no secret step. The Phase C
// children (security.secrets, security.code) leave with their root, which
// security_module_omit.go marks omitted.

// newSecurityCommitAfterScan adds no step: the module is not in this build.
func newSecurityCommitAfterScan(*store.Store) func(context.Context, commitscan.Root, commitscan.Result) {
	return nil
}
