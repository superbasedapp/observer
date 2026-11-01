//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "testing"

// TestMXCRunDocumentWin32kFollowsTheRow (WINFIX2 audit finding 4): the run's
// document drops MXC's Win32k mitigation only when the plan, filled from
// the tool row's NeedsWin32k, says the tool needs user32.dll; before, every
// run dropped it.
func TestMXCRunDocumentWin32kFollowsTheRow(t *testing.T) {
	box := `C:\Users\w\AppData\Local\Temp\observer-sbx-w32`
	inner := []string{`C:\o\observer.exe`, "claude"}
	for _, needs := range []bool{false, true} {
		plan := mxcPlanFile{RunID: "w32", Workspace: `C:\w`, ReadWrite: []string{`C:\w`}, Tier: "internet", NeedsWin32k: needs}
		doc, err := mxcRunDocument(plan, box, box+`\tmp`, inner, []string{`SystemRoot=C:\Windows`}, 4321, false)
		if err != nil {
			t.Fatal(err)
		}
		if doc.UI == nil || doc.UI.Disable == needs {
			t.Fatalf("NeedsWin32k=%v: ui = %+v", needs, doc.UI)
		}
	}
}
