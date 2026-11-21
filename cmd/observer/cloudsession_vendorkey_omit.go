//go:build sbo_omit_org_update

package main

// cloudSessionVendorKeys in a build without the update module carries no
// key, so `observer cloud-session init` refuses to write a setup script (it
// would install an unverified binary).
func cloudSessionVendorKeys() []string { return nil }
