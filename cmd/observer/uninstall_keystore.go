package main

import (
	"fmt"
	"io"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// uninstall_keystore.go removes this Observer home's OS keychain entries on
// `observer uninstall --all` (Windows 11 Pro rerun 2026-10-25, D2): before,
// every key stayed in the user's keychain (Windows Credential Manager,
// macOS Keychain, the Secret Service) after an uninstall. Only this home's
// entries go (keystore.Namespace): another Observer home's are untouched.

// observerKeystoreServices is every OS keychain service this binary writes,
// read from the one table in internal/keystore (literals there, so it compiles
// in every omit-tag build; the dashboard You page reads it too). The org
// enrolment's configured service (`[org_client].keychain_id`) is added at
// run time, and the sandbox rows' services by staticKeystoreServices.
// TestObserverKeystoreServicesAreListed keeps the list whole.
var observerKeystoreServices = keystore.ServiceNames()

// sandboxKeystoreServices returns the keychain services the sandbox
// backend rows declare (their KeystoreServices capability field). It is a
// seam: nil in an edition built without the sandbox, filled by
// uninstall_keystore_sandbox.go where the sandbox is built, so this file,
// built in every edition, imports no sandbox package (the
// terminals.sandbox component's L1 absence) and names no driver.
var sandboxKeystoreServices func() []string

// staticKeystoreServices is observerKeystoreServices plus the sandbox
// rows' services, so a sandbox driver's keychain entries are removed
// whenever the sandbox is built, the driver itself compiled in or not.
func staticKeystoreServices() []string {
	svcs := append([]string(nil), observerKeystoreServices...)
	if sandboxKeystoreServices == nil {
		return svcs
	}
	for _, s := range sandboxKeystoreServices() {
		if !slices.Contains(svcs, s) {
			svcs = append(svcs, s)
		}
	}
	return svcs
}

// uninstallKeystoreServices is staticKeystoreServices plus the configured
// org keychain id when it differs.
func uninstallKeystoreServices() []string {
	svcs := staticKeystoreServices()
	if cfg, err := config.Load(config.LoadOptions{}); err == nil && cfg.OrgClient.KeychainID != "" && !slices.Contains(svcs, cfg.OrgClient.KeychainID) {
		svcs = append(svcs, cfg.OrgClient.KeychainID)
	}
	return svcs
}

// removeKeystoreEntries removes (or, on a dry run, names) this home's
// keychain entries; it reports whether it failed.
func removeKeystoreEntries(out io.Writer, dryRun bool) bool {
	svcs := uninstallKeystoreServices()
	where := "this home's entries"
	if tag := keystore.HomeTag(); tag != "" {
		where = "this home's entries (namespace " + tag + ")"
	}
	if dryRun {
		fmt.Fprintf(out, "%-12s keychain would remove %s of %d services\n", "observer", where, len(svcs))
		return false
	}
	done, err := keystore.RemoveHomeEntries(svcs)
	if err != nil {
		fmt.Fprintf(out, "%-12s keychain ✗ %v\n", "observer", err)
		return true
	}
	fmt.Fprintf(out, "%-12s keychain removed %s of %d services\n", "observer", where, len(done))
	return false
}
