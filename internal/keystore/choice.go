package keystore

import (
	"errors"
	"os"
	"strings"
	"sync"
)

// On Linux the OS keyring is the Secret Service, and a first write to it can
// open a desktop prompt (create or unlock a "login" keyring with a password)
// before the person has done anything with Observer beyond signing in. That
// prompt is not needed there: the hardened 0600 file store is the documented
// fallback and the file is readable only by the account. So on Linux the file
// store is the default, and the keyring is used only when the person opts in
// (EnvOSKeychain) or when the keyring already holds this service's entries
// from an earlier install (they stay where they are, so nobody has to sign in
// or enrol again). Windows and macOS are unchanged: the OS keychain stays
// first there (Windows has no secure file fallback, and macOS does not prompt
// for an app's own items). Ledger row KEYSTORE-LINUX-1 (L-142).

// EnvOSKeychain chooses the OS keyring on a platform where the file store is
// the default (Linux): "1", "true", "yes" or "on" uses the keyring; "0",
// "false", "no" or "off" uses the file store even where the keyring already
// holds entries. Any other value is ignored. It has no effect on Windows or
// macOS.
const EnvOSKeychain = "OBSERVER_OS_KEYCHAIN"

// ReasonKeychainNotChosen: the file store is this machine's default and the
// OS keyring was not chosen (not a failure; nothing is degraded by accident).
const ReasonKeychainNotChosen = "keychain_not_chosen"

// ErrKeychainNotChosen is the probe's answer where the OS keyring is not
// chosen for a service (KeychainChosen is false).
var ErrKeychainNotChosen = errors.New("keystore: this machine keeps credentials in the 0600 file store; the OS keyring is not used (set " + EnvOSKeychain + "=1 to use it)")

// chooseKeychain is the decision, rows top-down: the platform puts the OS
// keychain first; the person opted in; the person opted out; the keyring
// already holds this service's entries.
func chooseKeychain(keychainFirst bool, env string, holds func() bool) bool {
	switch v := strings.ToLower(strings.TrimSpace(env)); {
	case keychainFirst:
		return true
	case v == "1" || v == "true" || v == "yes" || v == "on":
		return true
	case v == "0" || v == "false" || v == "no" || v == "off":
		return false
	default:
		return holds()
	}
}

// chosen caches KeychainChosen per service for the life of the process.
var chosen sync.Map // service -> bool

// KeychainChosen reports whether this process uses the OS keychain for
// service. It is true on Windows and macOS, and in a process on the
// in-memory keyring (tests, EnvTestKeystore). On Linux it is true only when
// EnvOSKeychain opts in or the keyring already holds an entry of
// Namespace(service); that check searches the keyring without unlocking it,
// so it never opens a prompt. A service may be passed with or without its
// namespace; it is namespaced once.
func KeychainChosen(service string) bool {
	if keychainFirst || !osKeyringActive {
		return true
	}
	if v, ok := chosen.Load(service); ok {
		return v.(bool)
	}
	c := chooseKeychain(keychainFirst, os.Getenv(EnvOSKeychain), func() bool { return keyringHolds(Namespace(service)) })
	chosen.Store(service, c)
	return c
}
