package delivery

import (
	"fmt"
	"sort"
	"time"
)

// summary.go is the funnel and metric math the Projects page and the org
// wire share (plan section 8). Two rules protect every number:
//
//   - Unknown is unknown. A rate whose denominator is empty, or a PR metric
//     with no provider connected, is Known=false with a reason; it is never
//     reported as zero.
//   - Every metric carries its caveat on its face, as a plain sentence.

// Caveats shown next to the metrics (plan section 8, verbatim where the plan
// gives the words).
const (
	CaveatAcceptedWork = "Work still in flight is left out of both sides and shown next to the rate. " +
		"Landed means on the default branch as of your last fetch. Squash and rebase merges count via patch matching."
	CaveatLandedShare   = "Includes work still in review, so it rises over time."
	CaveatPRMergeRate   = "A PR closed and replaced by another PR reads as closed unmerged."
	CaveatMergeProvider = "From the PR's opened time to its merged time, as the code host reports them."
	CaveatMergeLocal    = "First commit to first seen on the default branch; depends on how often you fetch."
	CaveatPromptFunnel  = "A prompt counts as landed when any commit that carried its files landed. " +
		"File-level reach, not line survival."

	// UnknownNoProvider is the reason a provider-only metric is unknown.
	UnknownNoProvider = "connect a provider to see this"
	// UnknownNoDenominator is the reason a rate with nothing to divide by
	// is unknown.
	UnknownNoDenominator = "nothing to measure yet"
)

// Fetch age buckets (orgcontract.DeliveryDayRow.FetchAgeBucket), a closed set.
const (
	AgeUnder1h  = "<1h"
	AgeUnder24h = "<24h"
	AgeUnder7d  = "<7d"
	AgeStale    = "stale"
	AgeUnknown  = "unknown"
)

// ageBucket is one row of ageBuckets.
type ageBucket struct {
	bucket string
	under  time.Duration
}

// ageBuckets is the ordered freshness table; an age at or past the last
// bound is stale.
var ageBuckets = []ageBucket{
	{AgeUnder1h, time.Hour},
	{AgeUnder24h, 24 * time.Hour},
	{AgeUnder7d, 7 * 24 * time.Hour},
}

// FetchAgeBucket buckets how old the evidence is: zero at is unknown.
func FetchAgeBucket(at, now time.Time) string {
	if at.IsZero() {
		return AgeUnknown
	}
	age := now.Sub(at)
	for _, b := range ageBuckets {
		if age < b.under {
			return b.bucket
		}
	}
	return AgeStale
}

// StaleCaveat is the sentence a rate tile carries when the evidence is older
// than seven days ("based on a fetch 9 days old"); "" otherwise.
func StaleCaveat(at, now time.Time) string {
	if at.IsZero() || FetchAgeBucket(at, now) != AgeStale {
		return ""
	}
	days := int(now.Sub(at).Hours() / 24)
	return fmt.Sprintf("based on a fetch %d days old", days)
}

// PromptDelivery is one prompt with AI edits and the commits that carried
// its files (projectroi.Link's output). An empty list means edited but not
// committed.
type PromptDelivery struct {
	CommitIDs []int64
}

// SummaryInput is everything Summarise reads: plain values the caller has
// already windowed (commits committed in the window, PRs closed or open in
// the window).
type SummaryInput struct {
	Landings []Landing
	// CommittedAt maps commit id to committed time, for the local
	// time-to-merge approximation.
	CommittedAt map[int64]time.Time
	// PRs are the PRs that hold at least one AI-touched commit.
	PRs               []PullRequest
	ProviderConnected bool
	// Prompts feed the prompt funnel; nil leaves the funnel unknown.
	Prompts []PromptDelivery
	// EvidenceAt is when the local evidence was last refreshed (the user's
	// FETCH_HEAD mtime, or the Observer mirror's last refresh); zero is
	// unknown.
	EvidenceAt time.Time
	// CountLikely mirrors [delivery].count_likely. RESERVED: rule L5 (the
	// only source of likely_landed) is not implemented, and until it ships
	// likely_landed is never counted as landed, whatever this says.
	CountLikely bool
	Now         time.Time
}

// Rate is a ratio metric. Known=false carries UnknownReason; Value is then 0
// and must not be shown.
type Rate struct {
	Known         bool
	Value         float64
	Num, Den      int64
	Caveat        string
	UnknownReason string
}

// Count is a count metric that can be unknown (provider-only counts).
type Count struct {
	Known         bool
	Value         int64
	UnknownReason string
}

// MergeTime is the time-to-merge metric: p50 and p75 over Samples, from the
// provider (exact) or local evidence (approximate), named in Source.
type MergeTime struct {
	Known         bool
	P50, P75      time.Duration
	Samples       int64
	Source        EvidenceSource
	Caveat        string
	UnknownReason string
}

// Funnel is the prompt delivery funnel: AI-edited prompts, committed, pushed
// (or further), in a PR (or landed through a known PR), landed.
type Funnel struct {
	Known         bool
	EditedPrompts int64
	Committed     int64
	Pushed        int64
	InPR          int64
	Landed        int64
	Caveat        string
}

// Summary is one project window's delivery picture.
type Summary struct {
	AICommits int64
	ByStatus  map[LandingStatus]int64
	// Landed commits by how they landed: exact (exact sha, merge commit),
	// patch (patch id, rebase), squash (squash, squash with changed files).
	// A landing whose kind is unknown counts in AICommitsLanded only.
	LandedExact  int64
	LandedPatch  int64
	LandedSquash int64

	AcceptedWorkRate Rate
	LandedShare      Rate
	PRMergeRate      Rate
	OpenMergeable    Count
	// BlockedBacklog counts BLOCKED open PRs by their blocking readiness
	// (PRBucket's open_blocked: never ready, never unknown); empty and
	// BlockedKnown=false without a provider.
	BlockedBacklog map[Readiness]int64
	BlockedKnown   bool
	// OpenUnknown counts open PRs whose readiness is unknown (neither
	// mergeable nor blocked); zero without a provider.
	OpenUnknown int64
	TimeToMerge MergeTime
	Funnel      Funnel
	FetchAge    string
	StaleCaveat string
}

// landedKindBucket maps a landing kind to its summary bucket (0 exact, 1
// patch, 2 squash, -1 none).
var landedKindBucket = map[LandingKind]int{
	KindExactSHA:    0,
	KindMerge:       0,
	KindPatchID:     1,
	KindRebase:      1,
	KindSquash:      2,
	KindSquashFiles: 2,
}

// countsAsLanded reports whether a landing counts on the landed side of the
// headline numbers: landed only. likely_landed (rule L5) stays reserved and
// is never counted, even with count_likely set (operator ruling, D-689);
// SummaryInput.CountLikely is wired here when L5 ships.
func countsAsLanded(s LandingStatus) bool {
	return s == StatusLanded
}

// Summarise computes the funnel and metrics of plan section 8.
func Summarise(in SummaryInput) Summary {
	out := Summary{
		ByStatus:       map[LandingStatus]int64{},
		BlockedBacklog: map[Readiness]int64{},
		FetchAge:       FetchAgeBucket(in.EvidenceAt, in.Now),
		StaleCaveat:    StaleCaveat(in.EvidenceAt, in.Now),
	}
	byCommit := map[int64]Landing{}
	var landed, abandoned int64
	for _, l := range in.Landings {
		byCommit[l.CommitID] = l
		out.AICommits++
		out.ByStatus[l.Status]++
		if countsAsLanded(l.Status) {
			landed++
			if b, ok := landedKindBucket[l.Kind]; ok {
				*[]*int64{&out.LandedExact, &out.LandedPatch, &out.LandedSquash}[b]++
			}
		}
		if l.Status == StatusAbandoned {
			abandoned++
		}
	}
	out.AcceptedWorkRate = rate(landed, landed+abandoned, CaveatAcceptedWork, true, "")
	out.LandedShare = rate(landed, out.AICommits, CaveatLandedShare, true, "")

	var merged, closed, openReady int64
	var mergeDurations []time.Duration
	var openUnknown int64
	for _, p := range in.PRs {
		switch PRBucket(p.State, p.Readiness) {
		case BucketMerged:
			merged++
			if !p.CreatedAt.IsZero() && !p.MergedAt.IsZero() && !p.MergedAt.Before(p.CreatedAt) {
				mergeDurations = append(mergeDurations, p.MergedAt.Sub(p.CreatedAt))
			}
		case BucketClosedUnmerged:
			closed++
		case BucketOpenReady:
			openReady++
		case BucketOpenBlocked:
			out.BlockedBacklog[p.Readiness]++
		case BucketOpenUnknown:
			openUnknown++
		}
	}
	out.PRMergeRate = rate(merged, merged+closed, CaveatPRMergeRate, in.ProviderConnected, UnknownNoProvider)
	if in.ProviderConnected {
		out.OpenMergeable = Count{Known: true, Value: openReady}
		out.BlockedKnown = true
		out.OpenUnknown = openUnknown
	} else {
		out.OpenMergeable = Count{UnknownReason: UnknownNoProvider}
		out.BlockedBacklog = map[Readiness]int64{}
	}

	out.TimeToMerge = mergeTime(in, mergeDurations)
	out.Funnel = funnel(in, byCommit)
	return out
}

// rate builds a Rate; known=false (or an empty denominator) makes it unknown.
func rate(num, den int64, caveat string, known bool, unknownReason string) Rate {
	r := Rate{Num: num, Den: den, Caveat: caveat}
	switch {
	case !known:
		r.UnknownReason = unknownReason
	case den <= 0:
		r.UnknownReason = UnknownNoDenominator
	default:
		r.Known = true
		r.Value = float64(num) / float64(den)
	}
	return r
}

// mergeTime picks the provider's PR durations when there are any, else the
// local approximation (committed to first seen landed) over local landings.
func mergeTime(in SummaryInput, provider []time.Duration) MergeTime {
	if in.ProviderConnected && len(provider) > 0 {
		p50, p75 := Percentiles(provider)
		return MergeTime{Known: true, P50: p50, P75: p75, Samples: int64(len(provider)), Source: SourceProvider, Caveat: CaveatMergeProvider}
	}
	var local []time.Duration
	for _, l := range in.Landings {
		if l.Status != StatusLanded || l.LandedAt.IsZero() || l.LandedAtSource == LandedAtProvider {
			continue
		}
		at, ok := in.CommittedAt[l.CommitID]
		if !ok || at.IsZero() || l.LandedAt.Before(at) {
			continue
		}
		local = append(local, l.LandedAt.Sub(at))
	}
	if len(local) == 0 {
		return MergeTime{UnknownReason: UnknownNoDenominator, Caveat: CaveatMergeLocal}
	}
	p50, p75 := Percentiles(local)
	return MergeTime{Known: true, P50: p50, P75: p75, Samples: int64(len(local)), Source: SourceUserRefs, Caveat: CaveatMergeLocal}
}

// Percentiles returns the nearest-rank p50 and p75 of ds (zero for an empty
// input; callers check the sample count first).
func Percentiles(ds []time.Duration) (p50, p75 time.Duration) {
	if len(ds) == 0 {
		return 0, 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return nearestRank(s, 50), nearestRank(s, 75)
}

// nearestRank is the nearest-rank percentile of an ascending slice.
func nearestRank(sorted []time.Duration, pct int) time.Duration {
	rank := (pct*len(sorted) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

// funnelStep is one row of funnelSteps: a prompt reaches the step when any
// carrying commit's landing satisfies reached.
type funnelStep struct {
	field   func(f *Funnel) *int64
	reached func(l Landing) bool
}

// funnelSteps are the steps after "committed", each a predicate over a
// carrying commit's landing.
var funnelSteps = []funnelStep{
	{func(f *Funnel) *int64 { return &f.Pushed }, func(l Landing) bool {
		switch l.Status {
		case StatusPushed, StatusInPR, StatusLanded, StatusLandingLost, StatusLikelyLanded:
			return true
		}
		return false
	}},
	{func(f *Funnel) *int64 { return &f.InPR }, func(l Landing) bool {
		return l.Status == StatusInPR || (l.Status == StatusLanded && (l.PRID > 0 || l.PRNumber > 0))
	}},
	{func(f *Funnel) *int64 { return &f.Landed }, func(l Landing) bool { return l.Status == StatusLanded }},
}

// funnel computes the prompt funnel; nil prompts leave it unknown.
func funnel(in SummaryInput, byCommit map[int64]Landing) Funnel {
	f := Funnel{Caveat: CaveatPromptFunnel}
	if in.Prompts == nil {
		return f
	}
	f.Known = true
	for _, p := range in.Prompts {
		f.EditedPrompts++
		if len(p.CommitIDs) == 0 {
			continue
		}
		f.Committed++
		for _, step := range funnelSteps {
			for _, id := range p.CommitIDs {
				if l, ok := byCommit[id]; ok && step.reached(l) {
					*step.field(&f)++
					break
				}
			}
		}
	}
	return f
}
