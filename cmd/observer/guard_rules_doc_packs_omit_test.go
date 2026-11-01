//go:build sbo_omit_security || sbo_omit_security_deps

package main

// guardRulesDocPacksOmitted: this build has no security.deps rule pack, so
// its catalog lacks the S-74x rows the generated docs/guard-rules.md
// carries (lane SEC-DEPS3 item 7).
const guardRulesDocPacksOmitted = true
