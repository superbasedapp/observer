package cloudresult

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins cloudresult pure and importable by both
// cloud-intelligence rails (INV-2): stdlib plus cloudcontract and scrub only,
// and no file, network, database or process surface.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os",
			"io/fs",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") && p != "github.com/marmutapp/superbased-observer/internal/cloudcontract" && p != "github.com/marmutapp/superbased-observer/internal/scrub" {
				return "cloudresult may import only cloudcontract and scrub"
			}
			return ""
		},
		Reason: "cloudresult must stay pure so both cloud-intelligence rails can import it",
	})
}
