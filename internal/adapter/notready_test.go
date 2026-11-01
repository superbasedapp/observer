package adapter

import "testing"

func TestNotReadyResult_WarnsOncePerFile(t *testing.T) {
	const tool = "test-tool"
	a, b := "/x/one.db", "/x/two.db"
	t.Cleanup(func() { ClearNotReady(tool, a); ClearNotReady(tool, b) })

	tests := []struct {
		name      string
		path      string
		clear     bool
		wantWarns int
	}{
		{"first sight of a warns", a, false, 1},
		{"a again is quiet", a, false, 0},
		{"another file warns on its own", b, false, 1},
		{"a after it parsed again warns again", a, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.clear {
				ClearNotReady(tool, tt.path)
			}
			res := NotReadyResult(tool, tt.path, 7, "not ready")
			if res.NewOffset != 7 {
				t.Errorf("NewOffset = %d, want the unchanged cursor 7", res.NewOffset)
			}
			if len(res.Warnings) != tt.wantWarns {
				t.Errorf("warnings = %v, want %d", res.Warnings, tt.wantWarns)
			}
			if len(res.ToolEvents)+len(res.TokenEvents) != 0 || res.RetrySuggested {
				t.Errorf("not-ready result must carry no rows and no retry hint")
			}
		})
	}
}
