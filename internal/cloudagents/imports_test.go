package cloudagents

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/cloudagents as pure logic (plan 5.1,
// CA-D5): the egress is internal/cloudagentsnet, the store and keychain are
// reached only through internal/cloudagentssvc.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"net/url",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/keystore",
			"github.com/marmutapp/superbased-observer/internal/cloudagentsnet",
			"github.com/marmutapp/superbased-observer/internal/cloudagentssvc",
		},
		Reason: "internal/cloudagents must stay pure",
	})
}
