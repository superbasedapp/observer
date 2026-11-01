//go:build sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/store"

// security_orgpush_omit.go: a build without the security module binds no
// security wire seam, so the push carries no security row.

func bindSecurityOrgProviders(*store.Store, bool) {}
