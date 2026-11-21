//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_ui_dashboard

package main

import "github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"

// sandbox_readopt_attach_dash_linux.go registers the re-adoption check with
// the dashboard's "Re-attach in a terminal" route (dashboard CLI parity plan
// item B-G3). It is its own file so a build without the dashboard
// (sbo_omit_ui_dashboard) does not link the dashboard package through the
// re-adoption verbs.
func init() { dashboard.SetSandboxReadoptCheck(readoptAttachCheck) }
