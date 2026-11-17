package hostapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// The usage pull (design 4.6 "Usage"; M6.0 Q11: "M6.4 pulls usage, M7b.2
// stores it"). Once per reconciliation pass the client asks each host that
// serves at least one org for its signed daily usage report
// (GET /platform/v1/usage?day=YYYY-MM-DD), for the receipt days UsageDays
// names, and hands every accepted tenant entry to the store
// (store.RecordOrgUsageDay, which merges a day pulled twice so a later
// partial pull never lowers a reported seat). This file is the pure half:
// the request, the reading of a verified answer and the acceptance rules.

// DefaultUsageDays is how many receipt days one pass pulls: yesterday (so
// the last pull of a day happens after it closed) and today (the partial
// day, merged upward on every later pass).
const DefaultUsageDays = 2

// UsageDays returns the receipt days (UTC, YYYY-MM-DD) one pass pulls at
// now, oldest first: today and the n-1 days before it. n < 1 means
// DefaultUsageDays.
func UsageDays(now time.Time, n int) []string {
	if n < 1 {
		n = DefaultUsageDays
	}
	day := now.UTC().Truncate(24 * time.Hour)
	out := make([]string, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, day.AddDate(0, 0, -i).Format(time.DateOnly))
	}
	return out
}

// UsageProbe is the usage request for one receipt day.
func UsageProbe(day string) (Request, error) {
	if err := (pc.UsageRequest{Day: day}).Validate(); err != nil {
		return Request{}, fmt.Errorf("hostapi.UsageProbe: %w: %w", ErrBadIntent, err)
	}
	// A valid day is digits and dashes only, so it needs no escaping.
	return Request{Method: methodGet, Path: pc.PathUsage, RawQuery: "day=" + day}, nil
}

// UsageReport is a verified usage answer: the report and the SHA-256 (hex)
// of the exact signed body it came from, kept with every stored row.
type UsageReport struct {
	Report pc.UsageResponse
	Digest string
}

// ReadUsage returns the report when a is a verified success whose body is a
// usage answer for day; ok is false for anything else (an unverified answer,
// a refusal, another day, a malformed body), which is never trusted.
func ReadUsage(a Answer, day string) (UsageReport, bool) {
	if a.Kind != AnswerVerified {
		return UsageReport{}, false
	}
	if ref, err := splitBody(a.Body); err != nil || ref != nil {
		return UsageReport{}, false
	}
	var r pc.UsageResponse
	if err := json.Unmarshal(a.Body, &r); err != nil || r.Day != day || !pc.ValidDay(r.Day) {
		return UsageReport{}, false
	}
	sum := sha256.Sum256(a.Body)
	return UsageReport{Report: r, Digest: hex.EncodeToString(sum[:])}, true
}

// UsageVerdict is what happens to one tenant entry of a host's report.
type UsageVerdict string

// Usage verdicts.
const (
	// UsageRecord: the entry is stored for its org and day.
	UsageRecord UsageVerdict = "record"
	// UsageDropMalformed: the entry is not a well-formed tenant usage.
	UsageDropMalformed UsageVerdict = "malformed"
	// UsageDropNotPlaced: the control plane did not place that org on this
	// host (or knows no such org); a host never reports usage that bills
	// another host's tenant.
	UsageDropNotPlaced UsageVerdict = "not_placed_here"
	// UsageDropDuplicate: a second entry for the same tenant in one report;
	// only the first counts.
	UsageDropDuplicate UsageVerdict = "duplicate"
)

// UsageEntry is one tenant entry read once, before the rules are walked.
type UsageEntry struct {
	// Usage is the entry.
	Usage pc.TenantUsage
	// PlacedHere is true when the control plane placed Usage.TenantID on
	// the host that sent the report.
	PlacedHere bool
	// SeenBefore is true when an earlier entry of the same report named the
	// same tenant.
	SeenBefore bool
}

// maxUsageSeatMembers bounds one entry's seat list (the store's own bound).
const maxUsageSeatMembers = 100000

// usageRules decides each entry, walked top-down, first match wins; the last
// row matches everything. One test case per row (usage_test.go).
var usageRules = []struct {
	name    string
	match   func(e UsageEntry) bool
	verdict UsageVerdict
}{
	{name: "malformed", match: func(e UsageEntry) bool { return !wellFormedUsage(e.Usage) }, verdict: UsageDropMalformed},
	{name: "not_placed_here", match: func(e UsageEntry) bool { return !e.PlacedHere }, verdict: UsageDropNotPlaced},
	{name: "duplicate", match: func(e UsageEntry) bool { return e.SeenBefore }, verdict: UsageDropDuplicate},
	{name: "record", match: func(UsageEntry) bool { return true }, verdict: UsageRecord},
}

// JudgeUsage decides one tenant entry.
func JudgeUsage(e UsageEntry) UsageVerdict {
	for _, r := range usageRules {
		if r.match(e) {
			return r.verdict
		}
	}
	return UsageDropMalformed // unreachable: the last row matches everything
}

// wellFormedUsage reports whether u can be stored: a path-safe tenant id,
// non-negative counts and a bounded list of non-empty seat member ids.
func wellFormedUsage(u pc.TenantUsage) bool {
	if !validPathID(u.TenantID) || u.MachineIdentities < 0 || u.Sessions < 0 || u.Members < 0 {
		return false
	}
	if len(u.ActiveSeatMemberIDs) > maxUsageSeatMembers {
		return false
	}
	for _, m := range u.ActiveSeatMemberIDs {
		if m == "" || len(m) > 128 {
			return false
		}
	}
	return true
}
