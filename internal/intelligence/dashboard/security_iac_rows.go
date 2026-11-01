//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import "net/http"

// security_iac_rows.go adds the IaC engines' rows (lane GATES-SEC) to the
// Scanners card, which is built with the dependency scanners
// (security_scanners.go carries the same tags).

// iacScannerRows are the IaC engines' Scanners card rows.
func (s *Server) iacScannerRows(r *http.Request) []securityScannerRow {
	iac := s.opts.IaC
	if iac == nil || iac.Rows == nil {
		return nil
	}
	var out []securityScannerRow
	for _, row := range iac.Rows(r.Context()) {
		labels := row.Labels
		if labels == nil {
			labels = []string{}
		}
		out = append(out, securityScannerRow{
			Component: row.Component, Driver: row.Driver, Kind: row.Kind, Compiled: row.Compiled,
			Platform: row.Platform, Beta: row.Beta, Note: row.Note, Labels: labels, Selected: row.Selected,
		})
	}
	return out
}
