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
// as literals so the list compiles in every omit-tag build. The org
// enrolment's configured service (`[org_client].keychain_id`) is added at
// run time. TestObserverKeystoreServicesAreListed keeps the list whole.
var observerKeystoreServices = []string{
	"sbo-change-record-v1",    // security provenance signing keys
	"sbo-exec-evidence-v1",    // execution evidence seal key
	"sbo-cloud-credential-v1", // Cloud Intelligence sign-in and device key
	"sbo-delivery-v1",         // delivery tokens
	"sbo-sandbox-cred-v1",     // sandbox provider credentials
	"sbo-plans-v1",            // Plans and limits provider keys
	"sbo-sandbox-e2b-v1",      // hosted sandbox: E2B
	"sbo-sandbox-modal-v1",    // hosted sandbox: Modal
	"sbo-sandbox-vercel-v1",   // hosted sandbox: Vercel
	"sbo-org-bearer-v1",       // the org enrolment's default keychain id
}

// uninstallKeystoreServices is observerKeystoreServices plus the configured
// org keychain id when it differs.
func uninstallKeystoreServices() []string {
	svcs := append([]string(nil), observerKeystoreServices...)
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
