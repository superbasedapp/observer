//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// startSecurityDeps starts nothing: security.deps is not in this build.
func startSecurityDeps(context.Context, *gatedGroup, string, componentstate.Snapshot) {}
