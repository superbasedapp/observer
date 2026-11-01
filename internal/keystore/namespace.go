package keystore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// namespace.go keeps one Observer home's OS keychain entries apart from
// another's (Windows 11 Pro rerun 2026-10-25, D2). Observer resolves ~ from
// HOME or USERPROFILE, so a second Observer home (an isolated test home, a
// kit, a scratch HOME) shares the user's OS keychain: before, every such
// home's daemon added its own change-record key to the real user's store,
// and the cloud and execution-evidence keys were shared across homes.
//
// Every keychain service name goes through Namespace: the account's own
// Observer home (HOME or USERPROFILE equal to the home the account database
// names) keeps the unsuffixed name, so an existing install reads its
// entries as before and nothing is migrated; any other home gets
// "<service>.h<10 hex of sha256(absolute Observer home)>". On Windows the
// target is "<service>.h<tag>:<record>".
//
// Under `go test` (testing.Testing()) the OS keychain is never reached: the
// keyring is go-keyring's in-memory provider for the whole test binary, so
// no test can write to the user's real store
// (tests/invariant/keystore_test.go pins it). A test that runs a BUILT
// observer binary sets EnvTestKeystore in that process's environment, and
// the binary then uses the same in-memory provider (WINFIX2 audit finding
// 10); any other value of the variable refuses the OS keychain rather than
// reach it, so a misspelt switch fails loudly instead of writing to the
// real store.

// homeTagLen is the hex length of a home tag.
const homeTagLen = 10

// EnvTestKeystore is the switch a test harness sets on a built observer
// binary it runs: "memory" puts the whole process on the in-memory keyring.
// The value is fixed; any other non-empty value makes the OS keychain
// unavailable (ErrTestKeystoreSwitch), never reached.
const EnvTestKeystore = "SBO_TEST_KEYSTORE"

// TestKeystoreMemory is the one value of EnvTestKeystore that selects the
// in-memory keyring.
const TestKeystoreMemory = "memory"

// ErrTestKeystoreSwitch is the error of every keychain call in a process
// whose EnvTestKeystore names an unknown value.
var ErrTestKeystoreSwitch = errors.New("keystore: " + EnvTestKeystore + " is set to an unknown value; the OS keychain is not used (set it to \"" + TestKeystoreMemory + "\" or unset it)")

// keystoreMode is the process's keyring decision, a table on two inputs:
// whether this is a test binary and the value of EnvTestKeystore.
type keystoreMode int

const (
	modeOS keystoreMode = iota
	modeMemory
	modeRefused
)

// modeFor decides the keyring of a process (the rows top-down).
func modeFor(testBinary bool, switchValue string) keystoreMode {
	switch {
	case testBinary:
		return modeMemory
	case switchValue == TestKeystoreMemory:
		return modeMemory
	case switchValue != "":
		return modeRefused
	default:
		return modeOS
	}
}

// osKeyringActive is false in a test binary and under EnvTestKeystore.
var osKeyringActive = true

func init() {
	switch modeFor(testing.Testing(), os.Getenv(EnvTestKeystore)) {
	case modeMemory:
		keyring.MockInit()
		osKeyringActive = false
	case modeRefused:
		keyring.MockInitWithError(ErrTestKeystoreSwitch)
		osKeyringActive = false
	}
}

// The test-only keyring reset lives in internal/keystore/keystoretest
// (WINFIX4 audit finding 7), so no product package carries it.

// OSKeyringActive reports whether this process reaches the real OS
// keychain: false in every test binary and in a binary a test harness
// started with EnvTestKeystore.
func OSKeyringActive() bool { return osKeyringActive }

// envObserverHome is the Observer home this process resolves (~/.observer
// from HOME or USERPROFILE). A var so tests substitute it.
var envObserverHome = func() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return ""
	}
	return filepath.Join(h, ".observer")
}

// accountObserverHome is the account's own Observer home, from the account
// database (the token's profile on Windows, the password database on
// unix), never from HOME or USERPROFILE. A var so tests substitute it.
var accountObserverHome = func() string {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return ""
	}
	return filepath.Join(u.HomeDir, ".observer")
}

// HomeTag is this process's Observer home tag: "" for the account's own
// home (or when either home cannot be resolved), else "h" and the first 10
// hex digits of the sha256 of the home's canonical path (normPath: links,
// junctions and short names resolved; lower-cased on Windows and macOS,
// whose paths compare case-insensitively).
func HomeTag() string {
	env, acct := envObserverHome(), accountObserverHome()
	if env == "" || acct == "" {
		return ""
	}
	if samePath(env, acct) {
		return ""
	}
	sum := sha256.Sum256([]byte(normPath(env)))
	return "h" + hex.EncodeToString(sum[:])[:homeTagLen]
}

// Namespace is the keychain service name service has in this process's
// Observer home.
func Namespace(service string) string {
	if tag := HomeTag(); tag != "" {
		return service + "." + tag
	}
	return service
}

// normPath is a home's canonical spelling, the one that is compared and
// hashed (WINFIX2 audit finding 6): absolute and clean, with the deepest
// part of it that exists resolved (canonicalPath: symbolic links and, on
// Windows, junctions and 8.3 short names), lower-cased on Windows and
// macOS. Two spellings of one folder therefore get one tag, so a HOME that
// is a symlink or a short-name spelling of the account's home keeps the
// unsuffixed names.
func normPath(p string) string {
	p = canonicalPath(p)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		p = strings.ToLower(p)
	}
	return p
}

// canonicalPath is p made absolute and clean with its deepest existing
// ancestor (p itself when it exists) resolved by resolveExisting and the
// rest joined back; a path no part of which resolves is returned clean.
func canonicalPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	p = filepath.Clean(p)
	dir, rest := p, ""
	for {
		if r, ok := resolveExisting(dir); ok {
			return filepath.Clean(filepath.Join(r, rest))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

func samePath(a, b string) bool { return normPath(a) == normPath(b) }

// ErrKeyringNotFound is the keyring's absent-record error, for callers that
// reach the keyring through KeyringGet and friends.
var ErrKeyringNotFound = keyring.ErrNotFound

// KeyringSet stores value under (Namespace(service), record).
func KeyringSet(service, record, value string) error {
	return keyring.Set(Namespace(service), record, value)
}

// KeyringGet reads (Namespace(service), record); ErrKeyringNotFound when
// absent.
func KeyringGet(service, record string) (string, error) {
	return keyring.Get(Namespace(service), record)
}

// KeyringDelete removes (Namespace(service), record); absence is
// ErrKeyringNotFound.
func KeyringDelete(service, record string) error {
	return keyring.Delete(Namespace(service), record)
}

// KeyringDeleteAll removes every record of Namespace(service): every entry
// of the service in this Observer home and none of another home's.
func KeyringDeleteAll(service string) error {
	err := keyring.DeleteAll(Namespace(service))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// RemoveHomeEntries deletes every keychain entry of each service in this
// process's Observer home (Namespace), for `observer uninstall --all`. It
// returns the namespaced names it cleared and the errors joined; a service
// with nothing stored is not an error.
func RemoveHomeEntries(services []string) ([]string, error) {
	var done []string
	var errs []error
	for _, svc := range services {
		if svc == "" {
			continue
		}
		ns := Namespace(svc)
		if err := keyring.DeleteAll(ns); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		done = append(done, ns)
	}
	return done, errors.Join(errs...)
}
