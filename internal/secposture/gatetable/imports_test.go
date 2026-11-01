package gatetable

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPureImports pins the table as pure: the rule tables import it.
func TestPureImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os", "os/exec", "net", "net/http", "database/sql", "github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/fsatomic", "github.com/marmutapp/superbased-observer/internal/secposture",
		},
		Reason: "the decision table is pure data the rule tables read (internal/secrules imports pure packages only)",
	})
}
