//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

// security_feedback_deps.go adds the package checks' row to the feedback
// rule table (feedbackRuleTables, audit finding F5, lane sec-polish): built
// only with the security.deps module. An advisory id from the OSV database
// (pack "osv") has no row: it is not one of Observer's compiled rules, so
// its line names the category.

func init() {
	feedbackRuleTables[securityDepsComponent] = func(id string) bool { return id == depsCommitRule }
}
