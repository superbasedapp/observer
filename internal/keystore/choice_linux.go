//go:build linux

package keystore

import ss "github.com/zalando/go-keyring/secret_service"

// keychainFirst is false on Linux: the 0600 file store is the default there
// (see choice.go).
const keychainFirst = false

// keyringHolds reports whether the Secret Service's login collection holds
// any item of the namespaced service ns. It searches by attribute, which
// needs no unlock and opens no prompt; any failure (no session bus, no Secret
// Service, no login collection) is false.
func keyringHolds(ns string) bool {
	svc, err := ss.NewSecretService()
	if err != nil {
		return false
	}
	items, err := svc.SearchItems(svc.GetLoginCollection(), map[string]string{"service": ns})
	return err == nil && len(items) > 0
}
