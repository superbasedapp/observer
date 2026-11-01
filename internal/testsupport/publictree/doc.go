// Package publictree is the one answer, for tests, to "is this the stripped
// public tree?".
//
// scripts/release.sh publishes a sanitized copy of this repository: it
// strips the private-only paths (the org server, web2/, docs/, deploy/
// except the sandbox image recipes, ...) before it builds, vets and tests
// the result. A test that reads one of those paths has nothing to check
// there and would fail on a missing file, so it calls Skip, which skips only
// on the public tree. The private tree always carries cmd/observer-org, so
// such a test keeps full strength where the private code lives.
//
// tests/invariant's skipInPublicTree delegates here, so both suites share
// one definition. The package imports only the standard library and is
// imported only from _test.go files.
package publictree
