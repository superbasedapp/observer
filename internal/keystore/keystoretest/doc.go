// Package keystoretest holds the test-only helpers of internal/keystore
// (WINFIX4 audit finding 7): the in-memory keyring reset a test uses to
// start on an empty keyring. Only _test.go files import it; a product
// package never does, so no product binary carries a function that clears
// the keyring.
package keystoretest
