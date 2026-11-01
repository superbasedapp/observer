//go:build sbo_omit_security || sbo_omit_org_security

package policyfam

// securityScanningInBuild is false: a security omit tag leaves
// family_securityscanning.go out, so security.scanning answers
// ErrFamilyNotLinked.
const securityScanningInBuild = false
