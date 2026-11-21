package termchart

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImportsPure pins termchart pure (CLAUDE.md rule 1): it draws
// strings from numbers the caller hands it. No database, HTTP, filesystem
// watch, process, os or syscall access; the only third-party imports are
// the colour and width libraries already in go.mod.
func TestPackageImportsPure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:      []string{"os", "syscall", "unsafe"},
		ForbiddenTrees: []string{"database/sql", "net", "github.com/fsnotify/fsnotify", "os/exec"},
		Custom: func(_, p string) string {
			switch p {
			case "github.com/fatih/color", "github.com/mattn/go-runewidth":
				return ""
			}
			if len(p) > 0 && containsDot(p) {
				return "third-party import; termchart may use only fatih/color and go-runewidth"
			}
			return ""
		},
		Reason: "termchart is pure",
	})
}

func containsDot(p string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] == '.' {
			return true
		}
	}
	return false
}
