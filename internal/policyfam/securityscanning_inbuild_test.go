//go:build !sbo_omit_security && !sbo_omit_org_security

package policyfam

// securityScanningInBuild mirrors family_securityscanning.go's build line
// (securityscanning_inbuild_omit_test.go holds the other side).
const securityScanningInBuild = true
