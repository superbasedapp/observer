//go:build !unix

package host

// TrampolineDispatch is a no-op where there is no trampoline: Windows
// starts the program suspended inside its job object instead, which holds
// every cap from the first instruction without one. It never reports a
// trampoline start.
func TrampolineDispatch([]string) (int, bool) { return 0, false }
