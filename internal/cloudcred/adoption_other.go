//go:build !unix

package cloudcred

// Legacy adoption refuses on these platforms. Ordinary keychain operations
// retain their existing per-item atomicity and need no migration lock.
func withCredentialLock(_ string, fn func() error) error { return fn() }
