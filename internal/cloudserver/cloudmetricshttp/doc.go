// Package cloudmetricshttp is the hosted cloud service's SEPARATE Prometheus
// listener (FR-4 follow-up; docs/saas-monitoring.md "Cloud metrics"). It is a
// listen-only egress lane (tests/invariant/cloud_server_egress_lanes_test.go
// row cloud.metricshttp): it serves GET /metrics from a
// cloudmetrics.Registry and dials nothing.
//
// The listener is OFF by default: SBCI_METRICS_LISTEN empty means no socket
// is opened. It is never mounted on the public API mux (the api package
// serves no /metrics route; tests/invariant/cloud_metrics_listener_test.go
// pins both). The fixed port contract with the deploy kit is cloud-api 9470
// and cloud-worker 9471, published on the monitoring address only, like the
// org server's `[metrics] listen`.
package cloudmetricshttp
