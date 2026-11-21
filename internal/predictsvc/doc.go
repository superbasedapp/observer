// Package predictsvc assembles the run-out projection of one session (the
// `projection` half of GET /api/session/<id>/predict and of `observer predict
// --json`, docs/cost-predictor.md "Run-out projection").
//
// It is the boundary between the pure math in internal/predict and the seams
// that own its inputs: the session's limit gauge (internal/sessiongauge's
// ladder over the store), the Plans & limits page model (planlimitssvc), the
// node's own [guard.budget] caps with the spend the guard budget surface
// measures, the org windows the daemon composed (budget-status.json through
// internal/budgetwarnfile) and the captured usage (store.LoadUsageRows).
//
// It exists so the dashboard handler and the CLI print ONE derivation: both
// are thin adapters that fill Deps and call Build. It lives outside the
// dashboard package because the CLI must not link the dashboard (the
// sbo_omit_ui_dashboard build drops it).
//
// Zero network calls. Every load error degrades to "no projection for that
// window", never an error.
package predictsvc
