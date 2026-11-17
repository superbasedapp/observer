// Package planlint is the plan-name lint (plan 06 5.8.4; 17.1 rule 4 "no
// plan-name literals"): it finds the string literals of a Go file that
// hard-code a plan name from the internal/entitlements vocabulary. The
// structural rule S7 (tools/structcheck) runs it over the org server.
//
// It is a separate package so the AST walker never links into a runtime
// binary that imports internal/entitlements. Pure: go/ast and the
// vocabulary, nothing else (imports_test.go).
package planlint
