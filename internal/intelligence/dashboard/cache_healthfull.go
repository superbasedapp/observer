package dashboard

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// The Cache page's "Full report" (lane L5 B-R1,
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the per-session and
// per-event detail `observer cache-health` prints, served by GET
// /api/cache/health?full=1 from the SAME single read of cache_events the
// slim summary makes (loadCacheHealth), so the tile, the banner and the
// report can never disagree. The four thresholds are the command's flags
// as query parameters.

// CacheHealthThresholds are the cache-health command's four tunables: the
// gate's minimum graded events and maximum mispredict rate, and the two
// informational checks' read:write ratio and dominant-cause share.
type CacheHealthThresholds struct {
	MinEvents           int
	MaxRate             float64
	MaxRewriteReadRatio float64
	MaxCauseShare       float64
}

// defaultCacheHealthThresholds are the command's flag defaults (the P0 gate).
func defaultCacheHealthThresholds() CacheHealthThresholds {
	return CacheHealthThresholds{MinEvents: 200, MaxRate: 0.05, MaxRewriteReadRatio: 3.0, MaxCauseShare: 0.80}
}

// cacheHealthParamRule is one query parameter of the full report: its
// name, its valid range, and where it lands. A table, so the parsing is
// one loop and one test row per parameter.
type cacheHealthParamRule struct {
	key    string
	lo, hi float64
	set    func(*CacheHealthThresholds, float64)
}

var cacheHealthParamRules = []cacheHealthParamRule{
	{"min_events", 1, 1_000_000, func(t *CacheHealthThresholds, v float64) { t.MinEvents = int(v) }},
	{"max_rate", 0, 1, func(t *CacheHealthThresholds, v float64) { t.MaxRate = v }},
	{"max_rewrite_read_ratio", 0.1, 1000, func(t *CacheHealthThresholds, v float64) { t.MaxRewriteReadRatio = v }},
	{"max_cause_share", 0, 1, func(t *CacheHealthThresholds, v float64) { t.MaxCauseShare = v }},
}

// cacheHealthThresholdsFrom reads the thresholds from the query, keeping
// the default for a missing or unparsable value and clamping an out-of-range
// one (the intArg convention).
func cacheHealthThresholdsFrom(r *http.Request) CacheHealthThresholds {
	thr := defaultCacheHealthThresholds()
	q := r.URL.Query()
	for _, rule := range cacheHealthParamRules {
		raw := strings.TrimSpace(q.Get(rule.key))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(v) {
			continue
		}
		if v < rule.lo {
			v = rule.lo
		}
		if v > rule.hi {
			v = rule.hi
		}
		rule.set(&thr, v)
	}
	return thr
}

// boolArgTrue reports whether a query flag is set ("1" or "true").
func boolArgTrue(r *http.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// rewriteInconsistent is the read:write consistency rule: a rewrite whose
// tokens_read exceeds ratio x tokens_written hit a warm prefix, so its
// invalidation label is mechanically inconsistent.
func rewriteInconsistent(read, written int64, ratio float64) bool {
	return read > 0 && read > int64(ratio*float64(written))
}

// CacheHealthCauseCount is one (cause, count) row over all cache events.
type CacheHealthCauseCount struct {
	Cause string `json:"cause"`
	Count int    `json:"count"`
}

// sortedCauseCounts folds the cause tally into rows, largest first, ties
// by cause name, so every reader walks the same order.
func sortedCauseCounts(counts map[string]int) []CacheHealthCauseCount {
	out := make([]CacheHealthCauseCount, 0, len(counts))
	for c, n := range counts {
		out = append(out, CacheHealthCauseCount{Cause: c, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Cause < out[j].Cause
	})
	return out
}

// baselineCauses never trip the cause-concentration warning:
// suffix_growth is the healthy baseline and handoff_rehydration the
// by-design cold write on a handoff target's first turn.
var baselineCauses = map[string]bool{
	string(cachetrack.CauseSuffixGrowth):       true,
	string(cachetrack.CauseHandoffRehydration): true,
}

// dominantCacheCause returns the largest non-baseline cause whose share of
// graded events exceeds maxShare, or nil (nothing graded, the check off at
// maxShare <= 0, or no cause over the line).
func dominantCacheCause(breakdown []CacheHealthCauseCount, graded int, maxShare float64) *CacheHealthDominantCause {
	if graded <= 0 || maxShare <= 0 {
		return nil
	}
	for _, c := range breakdown {
		if baselineCauses[c.Cause] {
			continue
		}
		if share := float64(c.Count) / float64(graded); share > maxShare {
			return &CacheHealthDominantCause{Cause: c.Cause, Count: c.Count, Share: share}
		}
	}
	return nil
}

// cacheHealthListCap bounds each per-event and per-session list in the
// full report; the *_total fields say how many there were.
const cacheHealthListCap = 200

// CacheHealthFull is the full cache-health report behind the summary.
type CacheHealthFull struct {
	// PerSession is one row per session, worst first (most mispredicts,
	// then highest rate), capped at cacheHealthListCap.
	PerSession      []CacheHealthSessionRow `json:"per_session"`
	PerSessionTotal int                     `json:"per_session_total"`
	// CauseBreakdown is every cause, largest first.
	CauseBreakdown []CacheHealthCauseCount `json:"cause_breakdown"`
	// MispredictEvents are the mispredict events, newest last (zero-usage
	// ones flagged: they are listed but not counted against the rate).
	MispredictEvents      []CacheHealthMispredictEvent `json:"mispredict_events"`
	MispredictEventsTotal int                          `json:"mispredict_events_total"`
	// InconsistentRewriteEvents are the rewrites whose read:write shape
	// contradicts a real invalidation.
	InconsistentRewriteEvents      []CacheHealthRewriteEvent `json:"inconsistent_rewrite_events"`
	InconsistentRewriteEventsTotal int                       `json:"inconsistent_rewrite_events_total"`
	// BucketMispredictsPerSession breaks the bucket-mismatch count down by
	// session, worst first.
	BucketMispredictsPerSession []CacheHealthSessionBucket `json:"bucket_mispredicts_per_session"`
	// The two informational thresholds actually used (the gate's two are
	// the summary's min_events_threshold / max_rate_threshold).
	MaxRewriteReadRatio float64 `json:"max_rewrite_read_ratio_threshold"`
	MaxCauseShare       float64 `json:"max_cause_share_threshold"`
}

// CacheHealthSessionRow is one session's grading.
type CacheHealthSessionRow struct {
	SessionID    string  `json:"session_id"`
	GradedEvents int     `json:"graded_events"`
	Mispredicts  int     `json:"mispredicts"`
	Rate         float64 `json:"mispredict_rate"`
}

// CacheHealthSessionBucket is one session's bucket-mismatch count.
type CacheHealthSessionBucket struct {
	SessionID         string `json:"session_id"`
	BucketMispredicts int    `json:"bucket_mispredicts"`
}

// CacheHealthMispredictEvent is one mispredict event.
type CacheHealthMispredictEvent struct {
	SessionID     string `json:"session_id"`
	Timestamp     string `json:"timestamp"`
	Model         string `json:"model"`
	Cause         string `json:"cause"`
	PredictedKind string `json:"predicted_kind"`
	ZeroUsage     bool   `json:"zero_usage,omitempty"`
}

// CacheHealthRewriteEvent is one inconsistent rewrite event.
type CacheHealthRewriteEvent struct {
	SessionID     string  `json:"session_id"`
	Timestamp     string  `json:"timestamp"`
	Model         string  `json:"model"`
	Kind          string  `json:"kind"`
	Cause         string  `json:"cause"`
	TokensRead    int64   `json:"tokens_read"`
	TokensWritten int64   `json:"tokens_written"`
	Ratio         float64 `json:"ratio"`
}

// cacheHealthRow is one cache_events row as the collector reads it.
type cacheHealthRow struct {
	SessionID, Timestamp, Model string
	Kind                        cachetrack.Kind
	Cause                       string
	Predicted                   cachetrack.Kind
	Read, Written               int64
}

// cacheHealthSession accumulates one session's kind and token streams.
type cacheHealthSession struct {
	kinds         []cachetrack.Kind
	read, written []int64
	bucket        int
}

// cacheHealthCollector builds the full report from the rows
// loadCacheHealth already reads. It owns no SQL.
type cacheHealthCollector struct {
	thr       CacheHealthThresholds
	sessions  map[string]*cacheHealthSession
	misp      []CacheHealthMispredictEvent
	mispTotal int
	rew       []CacheHealthRewriteEvent
	rewTotal  int
}

func newCacheHealthCollector(thr CacheHealthThresholds) *cacheHealthCollector {
	return &cacheHealthCollector{thr: thr, sessions: map[string]*cacheHealthSession{}}
}

// add folds one row in.
func (c *cacheHealthCollector) add(row cacheHealthRow) {
	acc := c.sessions[row.SessionID]
	if acc == nil {
		acc = &cacheHealthSession{}
		c.sessions[row.SessionID] = acc
	}
	acc.kinds = append(acc.kinds, row.Kind)
	acc.read = append(acc.read, row.Read)
	acc.written = append(acc.written, row.Written)
	if row.Predicted != "" && cachetrack.BucketMismatch(row.Predicted, row.Kind) {
		acc.bucket++
	}
	if row.Kind == cachetrack.KindMispredict {
		c.mispTotal++
		if len(c.misp) < cacheHealthListCap {
			c.misp = append(c.misp, CacheHealthMispredictEvent{
				SessionID: row.SessionID, Timestamp: row.Timestamp, Model: row.Model,
				Cause: row.Cause, PredictedKind: string(row.Predicted),
				ZeroUsage: row.Read == 0 && row.Written == 0,
			})
		}
	}
	if isRewriteKindLocal(row.Kind) && rewriteInconsistent(row.Read, row.Written, c.thr.MaxRewriteReadRatio) {
		c.rewTotal++
		if len(c.rew) < cacheHealthListCap {
			ratio := 0.0
			if row.Written > 0 {
				ratio = float64(row.Read) / float64(row.Written)
			}
			c.rew = append(c.rew, CacheHealthRewriteEvent{
				SessionID: row.SessionID, Timestamp: row.Timestamp, Model: row.Model,
				Kind: string(row.Kind), Cause: row.Cause,
				TokensRead: row.Read, TokensWritten: row.Written, Ratio: ratio,
			})
		}
	}
}

// report finishes the full report; breakdown is the sorted cause tally.
func (c *cacheHealthCollector) report(breakdown []CacheHealthCauseCount) *CacheHealthFull {
	out := &CacheHealthFull{
		CauseBreakdown:            breakdown,
		MispredictEvents:          c.misp,
		MispredictEventsTotal:     c.mispTotal,
		InconsistentRewriteEvents: c.rew,
		MaxRewriteReadRatio:       c.thr.MaxRewriteReadRatio,
		MaxCauseShare:             c.thr.MaxCauseShare,
	}
	out.InconsistentRewriteEventsTotal = c.rewTotal
	for sid, acc := range c.sessions {
		rate, graded := cachetrack.MispredictRateGraded(acc.kinds, acc.read, acc.written)
		misp := 0
		for i, k := range acc.kinds {
			if k == cachetrack.KindMispredict && !zeroUsageAt(i, acc.read, acc.written) {
				misp++
			}
		}
		out.PerSession = append(out.PerSession, CacheHealthSessionRow{
			SessionID: sid, GradedEvents: graded, Mispredicts: misp, Rate: rate,
		})
		if acc.bucket > 0 {
			out.BucketMispredictsPerSession = append(out.BucketMispredictsPerSession,
				CacheHealthSessionBucket{SessionID: sid, BucketMispredicts: acc.bucket})
		}
	}
	sort.Slice(out.PerSession, func(i, j int) bool {
		a, b := out.PerSession[i], out.PerSession[j]
		if a.Mispredicts != b.Mispredicts {
			return a.Mispredicts > b.Mispredicts
		}
		if a.Rate != b.Rate {
			return a.Rate > b.Rate
		}
		return a.SessionID < b.SessionID
	})
	out.PerSessionTotal = len(out.PerSession)
	if len(out.PerSession) > cacheHealthListCap {
		out.PerSession = out.PerSession[:cacheHealthListCap]
	}
	sort.Slice(out.BucketMispredictsPerSession, func(i, j int) bool {
		a, b := out.BucketMispredictsPerSession[i], out.BucketMispredictsPerSession[j]
		if a.BucketMispredicts != b.BucketMispredicts {
			return a.BucketMispredicts > b.BucketMispredicts
		}
		return a.SessionID < b.SessionID
	})
	if len(out.BucketMispredictsPerSession) > cacheHealthListCap {
		out.BucketMispredictsPerSession = out.BucketMispredictsPerSession[:cacheHealthListCap]
	}
	// Non-nil slices so the page never has to guard a JSON null.
	if out.MispredictEvents == nil {
		out.MispredictEvents = []CacheHealthMispredictEvent{}
	}
	if out.InconsistentRewriteEvents == nil {
		out.InconsistentRewriteEvents = []CacheHealthRewriteEvent{}
	}
	if out.PerSession == nil {
		out.PerSession = []CacheHealthSessionRow{}
	}
	if out.BucketMispredictsPerSession == nil {
		out.BucketMispredictsPerSession = []CacheHealthSessionBucket{}
	}
	if out.CauseBreakdown == nil {
		out.CauseBreakdown = []CacheHealthCauseCount{}
	}
	return out
}
