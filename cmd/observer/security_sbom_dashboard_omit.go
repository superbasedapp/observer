//go:build sbo_omit_security || sbo_omit_security_deps

package main

import "github.com/marmutapp/superbased-observer/internal/dashapi"

// securityProjectSBOMDash is nil: the dependency inventory is not in this
// build.
func securityProjectSBOMDash(string) dashapi.SecurityProjectSBOM { return nil }
