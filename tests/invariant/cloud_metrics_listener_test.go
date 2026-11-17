package invariant

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetricshttp"
)

// cloud_metrics_listener_test.go pins the hosted cloud service's Prometheus
// listener (lane cloud.metricshttp in cloud_server_egress_lanes_test.go;
// docs/saas-monitoring.md "Cloud metrics"; docs/security.md AUDITRL-1's
// neighbour CLOUDMET-1):
//
//   - OFF by default: an empty SBCI_METRICS_LISTEN opens nothing.
//   - Never on the public mux: the api package (the public listener's only
//     handler) neither imports the listener package nor registers any
//     /metrics path, and only cmd/observer-cloud's metrics.go starts it.
//   - Never the public address: a metrics address equal to the public
//     listen address refuses to start.

func TestCloudMetricsListenerOffByDefault(t *testing.T) {
	listen, err := cloudmetricshttp.ParseListen("", ":8090")
	if err != nil || listen != "" {
		t.Fatalf("empty SBCI_METRICS_LISTEN: %q, %v; want off", listen, err)
	}
	if cloudmetricshttp.NewServer(listen, cloudmetrics.New(cloudmetrics.ProcessAPI)) != nil {
		t.Fatal("an empty listen address must not build a server")
	}
	if _, err := cloudmetricshttp.ParseListen("0.0.0.0:8090", ":8090"); err == nil {
		t.Fatal("the metrics listener must refuse the public API's address")
	}
}

// rootMetricsPath matches a root /metrics route literal ("/metrics" or
// "GET /metrics", with or without a trailing path); the portal's own
// /portal/api/community/metrics product route is not one.
var rootMetricsPath = regexp.MustCompile(`"(?:[A-Z]+ )?/metrics(?:/[^"]*)?"`)

func TestCloudMetricsNeverOnThePublicMux(t *testing.T) {
	root := repoRoot(t)
	const listenerPkg = modulePath + "internal/cloudserver/cloudmetricshttp"
	apiDir := filepath.Join(root, "internal", "cloudserver", "api")
	files, err := filepath.Glob(filepath.Join(apiDir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("api sources: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == listenerPkg {
				t.Errorf("%s imports %s: the metrics listener must never be mounted on the public API", filepath.Base(f), listenerPkg)
			}
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := rootMetricsPath.FindString(string(raw)); m != "" {
			t.Errorf("%s names the root path %s: the public API serves no Prometheus route", filepath.Base(f), m)
		}
	}

	// Only cmd/observer-cloud/metrics.go starts the listener.
	cmdFiles, err := filepath.Glob(filepath.Join(root, "cmd", "observer-cloud", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range cmdFiles {
		if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "metrics.go" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), listenerPkg) {
			t.Errorf("%s imports the metrics listener; only metrics.go may start it", filepath.Base(f))
		}
	}
}
