//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

// guardRulesDocPacksOmitted reports whether a build tag removed a rule pack
// whose rows docs/guard-rules.md carries (the security module or its
// security.deps pack, S-741 to S-749). The doc is generated from the full
// build, so TestGuardRulesDocInSync skips when this is true (lane SEC-DEPS3
// item 7).
const guardRulesDocPacksOmitted = false
