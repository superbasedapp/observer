//go:build !windows

package supervisor

// serviceExists is the Windows service lookup; there is none elsewhere.
func serviceExists(string) bool { return false }
