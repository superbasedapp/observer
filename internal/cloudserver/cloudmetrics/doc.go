// Package cloudmetrics is the hosted cloud service's Prometheus text
// exposition (FR-4 follow-up, lead decisions L-132..L-135; operator reference
// docs/saas-monitoring.md "Cloud metrics").
//
// It is a PURE package: no client library, no database/sql, no net/http, no
// fsnotify, no os/exec (pinned by imports_test.go). The serve and worker
// processes each own ONE *Registry; the api package's audit() seam and its
// Paddle webhook wrapper, and the worker's deletion driver loop, feed it; the
// listen-only package internal/cloudserver/cloudmetricshttp serves Render's
// bytes on the separate SBCI_METRICS_LISTEN listener, never on the public mux.
//
// Every label value is drawn from a CLOSED table in this package (vocab.go):
// the audit event names the api package writes, the Paddle webhook results
// and reasons, the binding refusal reasons and the deletion block kinds and
// reasons. A value outside its table is counted under "unlisted" (audit
// events) or "other" (everything else), never as the caller's string, so no
// request, provider or database value can grow a series. Every series of a
// process's families is rendered from zero at the first scrape, so an
// alert's increase() sees the very first event.
//
// The exposition shape mirrors internal/orgserver/metrics: one HELP/TYPE
// preamble per metric, label values escaped in one place, integral values
// rendered without a decimal point, series in a stable order.
package cloudmetrics
