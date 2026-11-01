//go:build sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// securityNotApplicableKeys reports nothing without the security module.
func securityNotApplicableKeys() []orgcontract.FamilyKeyNotApplicable { return nil }
