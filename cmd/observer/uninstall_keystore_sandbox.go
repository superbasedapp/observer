//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/sandboxbackend"

// uninstall_keystore_sandbox.go fills uninstall's sandbox keystore seam
// (uninstall_keystore.go) from the sandbox backend rows' KeystoreServices
// capability field, only in an edition that builds the sandbox.

func init() { sandboxKeystoreServices = sandboxbackend.KeystoreServices }
