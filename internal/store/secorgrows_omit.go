//go:build sbo_omit_security

package store

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// secorgrows_omit.go: a build without the security module reads no sec_*
// table; the cmd layer binds no security seam there, so these are never
// called by the daemon. They keep the API for callers compiled in every
// build.

// SelectSecurityFindingRows reads nothing without the security module.
func (s *Store) SelectSecurityFindingRows(context.Context, int, SecurityScope) ([]orgcontract.SecurityFindingRow, error) {
	return nil, nil
}

// SecurityPostureFacts reads nothing without the security module.
func (s *Store) SecurityPostureFacts(_ context.Context, day string, _ time.Time, _ SecurityScope) (orgcontract.SecurityPostureRow, error) {
	return orgcontract.SecurityPostureRow{Day: day}, nil
}

// probeSecFindings is constant without the security module.
func (s *Store) probeSecFindings(context.Context) (string, error) { return "omitted", nil }

// probeSecPosture is constant without the security module.
func (s *Store) probeSecPosture(context.Context) (string, error) { return "omitted", nil }

// SelectChangeRecordRows reads nothing without the security module.
func (s *Store) SelectChangeRecordRows(context.Context, int, SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
	return nil, nil
}

// probeSecChangeRecords is constant without the security module.
func (s *Store) probeSecChangeRecords(context.Context) (string, error) { return "omitted", nil }
