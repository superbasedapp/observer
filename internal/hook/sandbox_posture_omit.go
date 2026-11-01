//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation

package hook

// sandboxedChild is the off side of sandbox_posture.go: a `-tags
// sbo_omit_terminals_sandbox` build cannot start a sandboxed terminal, so no
// hook it runs is inside one of its sandboxes, and the hook package does not
// import internal/sandbox (modular packaging plan 5.1, lane MP-L1B).
func sandboxedChild() bool { return false }
