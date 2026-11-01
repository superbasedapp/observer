package dimcode

import (
	"fmt"
	"testing"
)

func TestZZDump(t *testing.T) {
	for _, f := range []string{"fixture-probe-wsl.sql", "fixture-probe-win.sql"} {
		res, _ := parseAll(t, f)
		fmt.Println("=====", f)
		for _, e := range res.ToolEvents {
			md := ""
			if e.Metadata != nil {
				md = fmt.Sprintf("perm=%s eff=%s collab=%s sub=%v parent=%s int=%v", e.Metadata.PermissionMode, e.Metadata.EffortLevel, e.Metadata.CollaborationMode, e.Metadata.IsSubagent, e.Metadata.ParentSessionID, e.Metadata.IsInterrupt)
			}
			fmt.Printf("%-34s %-16s side=%v ok=%v %q err=%q raw=%s %s\n", e.SessionID, e.ActionType, e.IsSidechain, e.Success, e.Target, e.ErrorMessage, e.RawToolName, md)
		}
		for _, e := range res.TokenEvents {
			fmt.Println("tok", e.SessionID, e.SourceEventID, e.IsSidechain, e.InputTokens, e.OutputTokens)
		}
		fmt.Println("lineages", res.SessionLineages)
		fmt.Println("versions", res.SessionToolVersions)
	}
}
