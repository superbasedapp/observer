//go:build sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/dashapi"

// securityOrgShareDash is nil without the security module: the notice
// stays hidden.
func securityOrgShareDash(string) dashapi.SecurityOrgShareFunc { return nil }
