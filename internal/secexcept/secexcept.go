package secexcept

import (
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Reason is why a finding is excepted: the closed reason picker.
type Reason string

// The Reason values.
const (
	ReasonFalsePositive Reason = "false_positive"
	ReasonAcceptedRisk  Reason = "accepted_risk"
	ReasonTestFixture   Reason = "test_fixture"
)

// ReasonRow is one row of the reason picker: the status the finding takes
// while the exception applies, and the label every surface shows.
type ReasonRow struct {
	ID     Reason
	Status policy.FindingStatus
	Label  string
}

// Reasons is the reason picker (section 6.3), in display order.
var Reasons = []ReasonRow{
	{ReasonFalsePositive, policy.FindingStatusFalsePositive, "Not a real problem (false positive)"},
	{ReasonTestFixture, policy.FindingStatusSuppressed, "Test fixture or example data"},
	{ReasonAcceptedRisk, policy.FindingStatusAcceptedRisk, "Real, risk accepted for now"},
}

// ReasonFor returns the picker row of id.
func ReasonFor(id string) (ReasonRow, bool) {
	for _, r := range Reasons {
		if string(r.ID) == id {
			return r, true
		}
	}
	return ReasonRow{}, false
}

// Expiry is when an exception stops applying: the closed expiry picker.
// Every exception expires; there is no perpetual choice on a node.
type Expiry string

// The Expiry values.
const (
	Expiry1Day        Expiry = "1d"
	Expiry7Days       Expiry = "7d"
	Expiry30Days      Expiry = "30d"
	ExpiryUntilChange Expiry = "until_change"
)

// UntilChangeCeiling is the longest an "until the file changes" exception
// applies when the file never changes: an exception is never perpetual on
// a node (section 6.3; a perpetual one is an org super-admin's, with a
// 90-day re-review, D-080).
const UntilChangeCeiling = 90 * 24 * time.Hour

// ExpiryRow is one row of the expiry picker.
type ExpiryRow struct {
	ID Expiry
	// After is how long a dated exception applies; for until_change it is
	// the ceiling.
	After time.Duration
	// UntilChange ends the exception when the finding's file changes.
	UntilChange bool
	Label       string
}

// Expiries is the expiry picker (section 6.3), in display order.
var Expiries = []ExpiryRow{
	{Expiry1Day, 24 * time.Hour, false, "1 day"},
	{Expiry7Days, 7 * 24 * time.Hour, false, "7 days"},
	{Expiry30Days, 30 * 24 * time.Hour, false, "30 days"},
	{ExpiryUntilChange, UntilChangeCeiling, true, "Until the file changes (at most 90 days)"},
}

// ExpiryFor returns the picker row of id.
func ExpiryFor(id string) (ExpiryRow, bool) {
	for _, e := range Expiries {
		if string(e.ID) == id {
			return e, true
		}
	}
	return ExpiryRow{}, false
}

// Origin is where a grant was made. Only a local owner grants: the CLI on
// this machine or the owner-local dashboard route. A repository file, a
// project policy layer or an agent is never an origin (X8, R-165).
type Origin string

// The Origin values.
const (
	OriginCLI       Origin = "cli"
	OriginDashboard Origin = "dashboard"
	// OriginOrg marks an exception applied from an org finding_exception
	// grant (security plan 7.5, lane SEC-E3). It is never a Request origin
	// (Plan refuses it): the grant is decided on the org server, under its
	// own rules, and applied by internal/secsvc.SyncOrgExceptions, which
	// records granted_by as "org:<grant id>".
	OriginOrg Origin = "org"
)

// Request is one grant request.
type Request struct {
	FindingID string
	Reason    string
	Expiry    string
	Origin    Origin
}

// FindingFacts is what the caller read about the finding before the grant.
type FindingFacts struct {
	// Found reports that the finding exists in the store.
	Found  bool
	Status policy.FindingStatus
	// FileHash is the sha256 hex of the finding's file now, "" when the
	// file could not be read (the project is not on this machine, the file
	// is gone or over the cap). Read only for until_change.
	FileHash string
}

// Grant is a planned exception.
type Grant struct {
	Reason ReasonRow
	Expiry ExpiryRow
	// ExpiresAt is when the exception ends at the latest.
	ExpiresAt time.Time
	// FileHash is the fingerprint an until_change exception watches.
	FileHash string
}

// Refusal is why a grant is refused.
type Refusal string

// The Refusal values.
const (
	RefuseNoFinding  Refusal = "no_finding"
	RefuseNotOpen    Refusal = "not_open"
	RefuseReason     Refusal = "unknown_reason"
	RefuseExpiry     Refusal = "unknown_expiry"
	RefuseOrigin     Refusal = "not_a_local_owner"
	RefuseNoFileHash Refusal = "file_not_readable"
)

// RefusalError is a refused grant.
type RefusalError struct {
	Refusal Refusal
	Message string
}

func (e *RefusalError) Error() string { return e.Message }

// AsRefusal returns the refusal behind err.
func AsRefusal(err error) (*RefusalError, bool) {
	var r *RefusalError
	ok := errors.As(err, &r)
	return r, ok
}

// refusalRow is one row of the grant refusal table, walked top to bottom;
// the first match refuses (CLAUDE.md module rule 5).
type refusalRow struct {
	when    func(req Request, f FindingFacts) bool
	refusal Refusal
	message string
}

var refusalTable = []refusalRow{
	{
		func(r Request, _ FindingFacts) bool { return r.Origin != OriginCLI && r.Origin != OriginDashboard }, RefuseOrigin,
		"an exception is granted only by the developer, from the CLI or the dashboard",
	},
	{func(_ Request, f FindingFacts) bool { return !f.Found }, RefuseNoFinding, "no such finding"},
	{
		func(_ Request, f FindingFacts) bool { return f.Status != policy.FindingStatusOpen }, RefuseNotOpen,
		"only an open finding can be excepted; this one is not open",
	},
	{
		func(r Request, _ FindingFacts) bool { _, ok := ReasonFor(r.Reason); return !ok }, RefuseReason,
		"pick a reason: false_positive, test_fixture or accepted_risk",
	},
	{
		func(r Request, _ FindingFacts) bool { _, ok := ExpiryFor(r.Expiry); return !ok }, RefuseExpiry,
		"pick an expiry: 1d, 7d, 30d or until_change",
	},
	{func(r Request, f FindingFacts) bool {
		e, _ := ExpiryFor(r.Expiry)
		return e.UntilChange && f.FileHash == ""
	}, RefuseNoFileHash, "the finding's file cannot be read on this machine, so \"until the file changes\" cannot be watched; pick a dated expiry"},
}

// Plan checks one grant request against what the caller read and returns
// the exception to record, or a *RefusalError.
func Plan(req Request, f FindingFacts, now time.Time) (Grant, error) {
	for _, row := range refusalTable {
		if row.when(req, f) {
			return Grant{}, &RefusalError{Refusal: row.refusal, Message: row.message}
		}
	}
	reason, _ := ReasonFor(req.Reason)
	exp, _ := ExpiryFor(req.Expiry)
	g := Grant{Reason: reason, Expiry: exp, ExpiresAt: now.Add(exp.After).UTC()}
	if exp.UntilChange {
		g.FileHash = f.FileHash
	}
	return g, nil
}

// Exception is a recorded exception as Judge reads it.
type Exception struct {
	Expiry    Expiry
	ExpiresAt time.Time
	FileHash  string
}

// Observed is what the caller can see of the exception's file now.
type Observed struct {
	// FileKnown reports that the caller could look at the file (its
	// project root is on this machine); FileHash is then its sha256 hex,
	// "" when it is gone or unreadable.
	FileKnown bool
	FileHash  string
}

// Outcome is an exception's state now.
type Outcome string

// The Outcome values.
const (
	OutcomeActive      Outcome = "active"
	OutcomeExpired     Outcome = "expired"
	OutcomeFileChanged Outcome = "file_changed"
)

type judgeRow struct {
	when    func(e Exception, now time.Time, o Observed) bool
	outcome Outcome
}

var judgeTable = []judgeRow{
	// Every exception ends at its expiry (until_change at the ceiling).
	{func(e Exception, now time.Time, _ Observed) bool {
		return e.ExpiresAt.IsZero() || !now.Before(e.ExpiresAt)
	}, OutcomeExpired},
	// until_change: a file that differs from the grant's fingerprint (or is
	// gone) ends it. A file the caller cannot look at keeps it until the
	// expiry above: no evidence of a change is not a change.
	{func(e Exception, _ time.Time, o Observed) bool {
		return e.Expiry == ExpiryUntilChange && o.FileKnown && o.FileHash != e.FileHash
	}, OutcomeFileChanged},
	{func(Exception, time.Time, Observed) bool { return true }, OutcomeActive},
}

// Judge returns an open exception's state now.
func Judge(e Exception, now time.Time, o Observed) Outcome {
	for _, row := range judgeTable {
		if row.when(e, now, o) {
			return row.outcome
		}
	}
	return OutcomeActive
}
