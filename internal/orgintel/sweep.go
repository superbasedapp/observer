package orgintel

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Node defaults for the background sweep, used when the org's requirement
// document does not name a bound (a server that predates parity phase 4, or a
// zero value). They are the personal auto-enrich sweep's shape.
const (
	DefaultSweepQuiet      = 30 * time.Minute
	DefaultSweepMaxAge     = 7 * 24 * time.Hour
	DefaultSweepMinActions = 3
)

// Sweep is what the node's background submission reads from the org's terms
// (parity phase 4): whether it runs at all, and which sessions it picks.
type Sweep struct {
	// On is false when the org runs enrichment on demand only for this
	// member: nothing is submitted in the background, while Enrich now still
	// works (the server refuses a background submission the same way).
	On         bool
	Quiet      time.Duration
	MinActions int
	MaxAge     time.Duration
}

// SweepFor resolves the sweep from a requirement body. A nil body, or an
// absent field, keeps the node's defaults: the fields are additive on the
// wire, so an older server changes nothing here.
func SweepFor(req *orgcontract.IntelRequirementBody) Sweep {
	s := Sweep{On: true, Quiet: DefaultSweepQuiet, MinActions: DefaultSweepMinActions, MaxAge: DefaultSweepMaxAge}
	if req == nil {
		return s
	}
	if req.Background != nil {
		s.On = *req.Background
	}
	if req.QuietMinutes > 0 {
		s.Quiet = time.Duration(req.QuietMinutes) * time.Minute
	}
	if req.MinActions > 0 {
		s.MinActions = req.MinActions
	}
	if req.MaxAgeDays > 0 {
		s.MaxAge = time.Duration(req.MaxAgeDays) * 24 * time.Hour
	}
	return s
}

// EvidenceSettingsFor is the excerpt selection an org envelope at level is
// built with: the org's selection (the contract's defaults when it sent none)
// narrowed to what the level carries, so a titles-level build never reads an
// excerpt class the org widened for a higher level. nil when the org sent no
// selection, which keeps the builder's own defaults.
func EvidenceSettingsFor(req *orgcontract.IntelRequirementBody, level cloudcontract.EvidenceLevel) *cloudcontract.EvidenceSettings {
	if req == nil || req.EvidenceSettings == nil {
		return nil
	}
	es := req.EvidenceSettings.ForEvidenceLevel(level)
	return &es
}

// SweepSince is the oldest session start the background sweep may pick:
// now-maxAge.
//
// Which ORG a session belongs to is not decided here. The candidates query
// (store.ListOrgIntelSubmitCandidates) selects only sessions whose
// sessions.authority_org_key is the org enrolled now (agent migration 250,
// managed SaaS plan M8.1, operator ruling D-43), so a session captured under
// a previous org is never offered to the next one. That key replaced the
// enrolment-start floor this function used to apply (fix lane B6), so one
// mechanism remains, and a re-enrolment into the SAME org no longer skips
// that org's earlier sessions.
func SweepSince(now time.Time, maxAge time.Duration) time.Time {
	return now.Add(-maxAge)
}
