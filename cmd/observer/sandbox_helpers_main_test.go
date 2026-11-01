//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation

package main

// The test binary stands in for the observer binary as a sandbox network
// helper: the live sandbox tests plan the host/guest helper verbs against
// os.Executable() (this binary), exactly as the daemon plans them against
// itself, so argv[1] naming a helper verb must run the helper, not the test
// suite. TestMain (testmain_test.go) asks this hook first. It is registered
// here because the helper verbs exist only where the sandbox module is
// compiled in.
func init() { testMainHelperDispatch = sandboxHelperDispatch }
