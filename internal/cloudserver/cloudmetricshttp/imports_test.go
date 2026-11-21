package cloudmetricshttp

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins the listener package to the standard library and
// the pure counter package: it serves cloudmetrics' bytes and owns nothing
// else (no SQL, no subprocess, no Prometheus client, no other internal
// package; lane cloud.metricshttp is listen-only).
func TestBoundaryImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"},
		Forbidden:  []string{"database/sql", "os/exec", "net/http/httputil", "net/smtp"},
		Reason:     "internal/cloudserver/cloudmetricshttp serves the counter registry and nothing else",
	})
}
