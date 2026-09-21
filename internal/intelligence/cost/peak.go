package cost

import (
	"strconv"
	"strings"
	"time"
)

// RateSet is a complete token-rate set: the base rates PLUS an optional
// long-context sub-tier (size-selected). Both the base Pricing and a peak
// variant are expressed as one of these, so peak×long-context is fully
// defined. Rates are USD per 1M tokens, matching Pricing.
type RateSet struct {
	Input           float64 `json:"input"`
	Output          float64 `json:"output"`
	CacheRead       float64 `json:"cache_read"`
	CacheCreation   float64 `json:"cache_creation"`
	CacheCreation1h float64 `json:"cache_creation_1h"`

	LongContextThreshold       int64   `json:"long_context_threshold,omitempty"`
	LongContextInput           float64 `json:"long_context_input,omitempty"`
	LongContextOutput          float64 `json:"long_context_output,omitempty"`
	LongContextCacheRead       float64 `json:"long_context_cache_read,omitempty"`
	LongContextCacheCreation   float64 `json:"long_context_cache_creation,omitempty"`
	LongContextCacheCreation1h float64 `json:"long_context_cache_creation_1h,omitempty"`
}

// PeakWindow is one recurring UTC time window on the given weekdays. The
// time bounds are "HH:MM" (24h, UTC), half-open [StartUTC, EndUTC): a turn
// AT exactly StartUTC is peak, a turn AT exactly EndUTC is off-peak. v1 is
// within-day only (StartUTC < EndUTC); a window that wraps midnight is
// authored as two windows.
type PeakWindow struct {
	Days     []time.Weekday `json:"days"`
	StartUTC string         `json:"start_utc"`
	EndUTC   string         `json:"end_utc"`
}

// PeakSchedule is an ordered set of windows. Contains(at) is true iff at's
// UTC weekday and UTC time-of-day fall inside some window.
type PeakSchedule struct {
	Windows []PeakWindow `json:"windows"`
}

// PeakRates is the peak (expensive-window) rate set plus the schedule that
// selects it. Nil on a Pricing ⇒ the model has no peak variant (base rates
// apply at every instant). The schedule travels with the rates.
type PeakRates struct {
	RateSet
	Schedule PeakSchedule `json:"schedule"`
}

// parseHHMM parses a "HH:MM" 24-hour clock string into a seconds-of-day
// count (hh*3600 + mm*60). ok is false when the string is not exactly two
// colon-separated integer fields, or when hours/minutes are out of the
// [0,23]/[0,59] range — a malformed bound the caller SKIPS rather than
// erroring, because pricing never fails closed.
func parseHHMM(s string) (int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, false
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil || hh < 0 || hh > 23 {
		return 0, false
	}
	mm, err := strconv.Atoi(parts[1])
	if err != nil || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*3600 + mm*60, true
}

// Contains reports whether `at` falls inside any window in the schedule.
//
// `at` is normalized to UTC; a window matches when its Days contains at's
// UTC weekday AND at's seconds-of-day is in the half-open interval
// [parse(StartUTC), parse(EndUTC)) — a turn AT exactly StartUTC is inside,
// a turn AT exactly EndUTC is outside. A window whose bounds fail to parse
// or are not Start<End is SKIPPED (pricing never fails closed — no error).
// An empty schedule is never peak. A zero `at` is handled by the caller;
// Contains on a zero time simply does not match any real window, which is
// harmless.
func (s PeakSchedule) Contains(at time.Time) bool {
	at = at.UTC()
	wd := at.Weekday()
	sod := at.Hour()*3600 + at.Minute()*60 + at.Second()
	for _, w := range s.Windows {
		start, ok := parseHHMM(w.StartUTC)
		if !ok {
			continue
		}
		end, ok := parseHHMM(w.EndUTC)
		if !ok || start >= end {
			continue
		}
		if sod < start || sod >= end {
			continue
		}
		for _, d := range w.Days {
			if d == wd {
				return true
			}
		}
	}
	return false
}

// peakAdjusted returns the Pricing to bill with at instant `at`, applying
// a model's peak variant when `at` falls inside a peak window.
//
// When the model has no peak variant (p.Peak == nil), when `at` is the
// zero time (no usable timestamp — the non-At Lookup path stays
// peak-BLIND, so live insert-time pricing bills at base rates), or when
// `at` falls outside every peak window, p is returned UNCHANGED. This
// preserves p.Peak on the way through so display surfaces can read the
// peak variant off a plain (zero-`at`) lookup.
//
// Otherwise the peak RateSet is overlaid: all five base rates and all six
// long-context rates are REPLACED by the peak RateSet's values (the peak
// RateSet is a complete rate set, not a delta — a zero field in it means
// "zero at peak", not "inherit base"). WebSearchPerRequest and
// FastMultiplier are NOT carried by a RateSet, so they are preserved from
// p unchanged — a flat per-request search fee and a fast-tier multiplier
// are the same in and out of a peak window. The p.Peak field is ALWAYS
// preserved on the output regardless of `at`, so the peak variant stays
// readable.
//
// This runs BEFORE fillDefaults / applyCacheWriteRule (which ignore Peak)
// and BEFORE ComputeBreakdown's lcAdjusted, so peak×long-context resolves
// through the peak RateSet's own long-context sub-tier.
func peakAdjusted(p Pricing, at time.Time) Pricing {
	if p.Peak == nil || at.IsZero() || !p.Peak.Schedule.Contains(at) {
		return p
	}
	rs := p.Peak.RateSet
	p.Input = rs.Input
	p.Output = rs.Output
	p.CacheRead = rs.CacheRead
	p.CacheCreation = rs.CacheCreation
	p.CacheCreation1h = rs.CacheCreation1h
	p.LongContextThreshold = rs.LongContextThreshold
	p.LongContextInput = rs.LongContextInput
	p.LongContextOutput = rs.LongContextOutput
	p.LongContextCacheRead = rs.LongContextCacheRead
	p.LongContextCacheCreation = rs.LongContextCacheCreation
	p.LongContextCacheCreation1h = rs.LongContextCacheCreation1h
	// p.WebSearchPerRequest, p.FastMultiplier and p.Peak are deliberately
	// left as they were on p.
	return p
}
