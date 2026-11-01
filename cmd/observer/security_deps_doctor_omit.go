//go:build sbo_omit_security || sbo_omit_security_deps

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// securityDepsDoctorCheck: security.deps is not in this build.
func securityDepsDoctorCheck(context.Context, string) diag.Check {
	return diag.Check{Name: "security.deps", Status: diag.StatusOK, Message: "Package checks: not in this build"}
}
