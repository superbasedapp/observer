//go:build sbo_omit_security

package invariant

// securityInBuild is false: the security module is compiled out, so the store
// reads no sec_* table and no security row can be composed at all.
const securityInBuild = false
