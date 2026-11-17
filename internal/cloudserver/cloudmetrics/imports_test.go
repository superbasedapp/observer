package cloudmetrics

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure (CLAUDE.md #1): it counts
// closed label values and renders text, with no SQL, HTTP, fsnotify,
// subprocess, Prometheus client or other internal package. The listener is
// internal/cloudserver/cloudmetricshttp.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/prometheus/client_golang/prometheus",
			"github.com/prometheus/client_golang/prometheus/promhttp",
			"github.com/prometheus/common/expfmt",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "internal/cloudserver/cloudmetrics counts closed label values and must stay pure",
	})
}
