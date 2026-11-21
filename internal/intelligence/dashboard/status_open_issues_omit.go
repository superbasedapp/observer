//go:build sbo_omit_security

package dashboard

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// status_open_issues_omit.go is the off side of status_open_issues.go:
// without the security module there are no issues to count, so
// /api/status omits open_issues and the sidebar's "Code security" badge
// (whose page is not in this build either) stays hidden.

// statusOpenIssues answers nil: security is not in this build.
func (s *Server) statusOpenIssues(context.Context, *sql.DB) *diag.OpenIssueCounts {
	return nil
}
