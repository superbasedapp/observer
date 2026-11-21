package main

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// guardAnchorDefaultRadius is the default `repair-anchors --radius`: 4,194,304
// ids around each hint. Measured on the operator's node (2026-11-02, 82,899
// candidates, ceiling 15.7M): the farthest anchor from its best hint lay just
// over 2.1M away (2M left 2 rows unproven, 1M left 1,490), and 4M proved all
// of them; each id is tried at most once per row, so an unprovable row never
// costs more than one walk over the whole range (docs/guard.md).
const guardAnchorDefaultRadius = 1 << 22

// formatGuardAnchorProgress is one stderr progress line of
// `observer guard repair-anchors`.
func formatGuardAnchorProgress(p store.GuardAnchorProgress) string {
	line := fmt.Sprintf("repair-anchors: %d/%d row(s) searched, %d proven, %d unproven",
		p.Done, p.Candidates, p.Proven, p.Unproven)
	if secs := p.Elapsed.Seconds(); secs > 0 {
		line += ", " + humanCount(float64(p.Hashed)/secs) + " hashes/s"
	}
	if p.Done > 0 && p.Done < p.Candidates {
		eta := time.Duration(float64(p.Elapsed) / float64(p.Done) * float64(p.Candidates-p.Done))
		line += ", ETA " + eta.Round(time.Second).String()
	}
	return line + ", " + p.Elapsed.Round(time.Second).String() + " elapsed"
}

// humanCount renders n with a k / M / G suffix and one decimal.
func humanCount(n float64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fG", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", n/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", n/1e3)
	default:
		return fmt.Sprintf("%.0f", n)
	}
}

// guardAnchorDistanceLabels names the store.GuardAnchorDistanceBuckets
// buckets: "0", "1-10", ..., ">1000000".
func guardAnchorDistanceLabels() []string {
	bounds := store.GuardAnchorDistanceBuckets
	labels := make([]string, 0, len(bounds)+1)
	lo := int64(0)
	for _, hi := range bounds {
		if hi == lo {
			labels = append(labels, strconv.FormatInt(lo, 10))
		} else {
			labels = append(labels, fmt.Sprintf("%d-%d", lo, hi))
		}
		lo = hi + 1
	}
	return append(labels, ">"+strconv.FormatInt(bounds[len(bounds)-1], 10))
}

// guardAnchorHintOrder is the report's hint rules in the store's rule order,
// then any other name sorted.
func guardAnchorHintOrder(distances map[string][]int) []string {
	known := []string{
		store.GuardAnchorHintContent, store.GuardAnchorHintSession,
		store.GuardAnchorHintPrevious, store.GuardAnchorHintNext, store.GuardAnchorHintFirst,
	}
	var order, rest []string
	for _, rule := range known {
		if _, ok := distances[rule]; ok {
			order = append(order, rule)
		}
	}
	for rule := range distances {
		if !slices.Contains(known, rule) {
			rest = append(rest, rule)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}

// writeGuardAnchorReport prints a repair-anchors report, complete or
// interrupted, to out.
func writeGuardAnchorReport(out io.Writer, r store.GuardAnchorRepairReport) {
	scope := fmt.Sprintf("within %d of each row's hint", r.Radius)
	if r.Radius <= 0 {
		scope = "the whole range"
	}
	if r.Interrupted {
		fmt.Fprintf(out, "interrupted after %d of %d candidate row(s): partial report, nothing written\n",
			r.Proven+r.UnprovenCount, r.Candidates)
	}
	fmt.Fprintf(out, "%d row(s) fail as rewritten with no action id; %d proven (action ids 1-%d, %s; %d id(s) tried, %d hash(es) on %d worker(s) in %s)\n",
		r.Candidates, r.Proven, r.Ceiling, scope, r.Tries, r.Hashed, r.Workers, r.Elapsed.Round(time.Millisecond))
	if r.Proven > 0 {
		fmt.Fprintln(out, "proven, by the hint that found them and the distance from it:")
		labels := guardAnchorDistanceLabels()
		for _, rule := range guardAnchorHintOrder(r.Distances) {
			parts := make([]string, 0, len(labels))
			for i, n := range r.Distances[rule] {
				if i < len(labels) && n > 0 {
					parts = append(parts, fmt.Sprintf("%s: %d", labels[i], n))
				}
			}
			fmt.Fprintf(out, "  %s: %s\n", rule, strings.Join(parts, ", "))
		}
	}
	if r.UnprovenCount == 0 {
		return
	}
	fmt.Fprintf(out, "%d not proven (left as reported):\n", r.UnprovenCount)
	reasons := make([]string, 0, len(r.UnprovenByReason))
	for reason := range r.UnprovenByReason {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		fmt.Fprintf(out, "  %d: %s\n", r.UnprovenByReason[reason], reason)
	}
	fmt.Fprintf(out, "the first %d:\n", len(r.Unproven))
	for _, u := range r.Unproven {
		if u.Hi == 0 {
			fmt.Fprintf(out, "  id %d: %s\n", u.ID, u.Reason)
			continue
		}
		more := ""
		if u.Windows > 1 {
			more = fmt.Sprintf(" and %d more window(s)", u.Windows-1)
		}
		fmt.Fprintf(out, "  id %d: searched %d-%d around %d%s: %s\n", u.ID, u.Lo, u.Hi, u.Hint, more, u.Reason)
	}
	if r.UnprovenByReason[store.GuardAnchorOutsideRadius] > 0 {
		fmt.Fprintln(out, "a wider --radius (0 = every id up to the ceiling) searches those rows further")
	}
}
