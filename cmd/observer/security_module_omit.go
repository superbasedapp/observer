//go:build sbo_omit_security

package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// security_module_omit.go stands in for security_module.go in a build
// without the security module (-tags sbo_omit_security): none of the
// pillar's packages is linked, no loop starts and no rule is composed. The
// core residue (the guard posture's signed "inactive" state, the posture
// reader, the vocabularies, the tables) stays.
func init() { components.MarkOmitted("security") }

// securityPackRules composes nothing: the module is not in this build.
func securityPackRules(func(string) bool, *slog.Logger) []policy.Rule { return nil }

// startSecurityModule starts nothing: the module is not in this build.
func startSecurityModule(context.Context, *gatedGroup, string, componentstate.Snapshot) {}
