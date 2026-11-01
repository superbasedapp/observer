//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package policyfam

// terminalsIsolationInBuild mirrors family_terminalsisolation.go's build
// line (the sandbox module omitted).
const terminalsIsolationInBuild = false
