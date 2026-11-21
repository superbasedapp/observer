//go:build sbo_omit_security

package main

import "testing"

// unbindSecurityFloors is the omit-build twin of the seam helper in
// security_floors_seam_test.go: a build without the security module has no
// floors' seam to leave unbound, so a shared test that calls it compiles and
// does nothing.
func unbindSecurityFloors(t *testing.T) { t.Helper() }
