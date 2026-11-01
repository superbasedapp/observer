package hook

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestOperandListArgvElements: Cline's run_commands may carry argv
// elements (lists of words) beside strings and objects; each element is
// judged on its own (security plan section 4.7 item 4).
func TestOperandListArgvElements(t *testing.T) {
	in := map[string]any{"commands": []any{
		"ls",
		[]any{"git", "commit", "-m", "two words"},
		map[string]any{"command": "git push"},
		[]any{"git", 1},
	}}
	got := operandList(tooltax.OperandCommand, in)
	want := []string{"ls", "git commit -m 'two words'", "git push"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("operandList = %q, want %q", got, want)
	}
	if got := operandList(tooltax.OperandFilePath, map[string]any{"files": []any{[]any{"a"}}}); got != nil {
		t.Fatalf("argv element read as a path: %q", got)
	}
}
