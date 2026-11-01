//go:build !unix && !windows

package hook

// readIBMBobPolicyOS: Bob has no policy source Observer reads on this OS.
func readIBMBobPolicyOS() IBMBobPolicy { return IBMBobPolicy{} }

// readIBMBobPolicyDomainsOS: no preferences domain on this OS.
func readIBMBobPolicyDomainsOS(string, bool) IBMBobPolicyDomains { return IBMBobPolicyDomains{} }
