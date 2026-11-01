// Package sectrustitem is the ONE mapping from the repository trust check's
// reasons (internal/sectrust) to the store items the accept table records
// (internal/store sec_config_baseline): every surface that records or
// accepts (the launch row, `observer security trust`, the dashboard) maps
// through FromReasons, so the scope and field choices cannot drift.
//
// It is its own package so internal/store never imports internal/sectrust:
// only the files built with the security.trust module import this one, and
// a build without the module links neither (plans decision log P-022 item f).
package sectrustitem
