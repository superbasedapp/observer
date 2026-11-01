//go:build !sbo_omit_adapter_cursor

package hook

// The Cursor stop-debug log joins the FU-102 forensic log guard only when
// the Cursor adapter is compiled in (RB1: the sbo_omit_adapter_cursor vet
// failed on the untagged test calling it).
func init() {
	forensicLogProbes = append(forensicLogProbes, struct {
		name  string
		write func()
	}{"cursor-stop-debug.jsonl", func() {
		dumpCursorStopReject([]byte(`{"session_id":"fu102"}`), "fu102-probe")
	}})
}
