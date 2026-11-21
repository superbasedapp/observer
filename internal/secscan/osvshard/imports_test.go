package osvshard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secscan/osvshard free of the network
// and of every sibling subsystem but the key owner and the OSV record
// rules (CLAUDE.md "Module Boundaries" rule 1): the network side is the
// injected Fetcher, whose one production implementation is the
// security.scan.osv.shards lane (shardnet), so a scan that links this
// package alone can never reach a host.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"net/url",
			"crypto/tls",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/",
		},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey",
			"github.com/marmutapp/superbased-observer/internal/secscan/osvdb",
		},
		Reason: "internal/secscan/osvshard opens no connection and links no sibling subsystem: the lane is shardnet, injected as a Fetcher",
	})
}
