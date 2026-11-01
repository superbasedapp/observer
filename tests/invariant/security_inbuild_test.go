//go:build !sbo_omit_security

package invariant

// securityInBuild reports whether the security module is compiled into this
// test binary; the security wire canaries need its sec_* reads.
const securityInBuild = true
