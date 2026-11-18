//go:build !linux

package keystore

// keychainFirst is true off Linux: the OS keychain stays first (see
// choice.go).
const keychainFirst = true

// keyringHolds is never consulted off Linux.
func keyringHolds(string) bool { return false }
