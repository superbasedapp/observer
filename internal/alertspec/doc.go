// Package alertspec is the alert dialect shared by the node evaluator
// (internal/obs/alert) and the org evaluator (internal/orgserver/obsalert):
// the four rule dimensions (model, user, tag, service) with their bounds, and
// the Slack incoming-webhook channel (URL check and message body).
//
// It sits outside internal/obs on purpose: the org server may not import
// internal/obs (tests/invariant/obs_boundary_test.go), and one dialect must not
// be defined twice (plan of record principle 2, CLAUDE.md rule 4).
//
// Pure (CLAUDE.md rule 1): no database/sql, net/http or fsnotify. The HTTP POST
// to Slack lives at each side's boundary (the org's guarded webhook client, the
// node's alert loop). Pinned by imports_test.go.
package alertspec
