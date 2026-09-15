package loc

import "strings"

// DiffFallbackLines is the line count above which Diff degrades to plain
// counting. Above it Diff emits one OpDelete over every old line and one
// OpInsert over every new line and never runs an alignment search, so a
// pathological input costs O(1) work instead of O(N*D).
const DiffFallbackLines = 20000

// myersMaxEditDistance bounds the greedy Myers search inside one
// alignment problem.
//
// The greedy algorithm keeps one V-band snapshot per edit-distance step
// so the script can be backtracked, which costs O(D^2) machine words. The
// cap keeps that peak bounded (~8 MB) no matter what a tool hands us. An
// alignment that needs more than this many edits is a wholesale rewrite;
// when the cap is hit the sub-problem degrades to "delete everything,
// insert everything", which is still a correct tiling and, after the
// min(deleted, inserted) pairing in Count, gives almost the same buckets.
const myersMaxEditDistance = 1000

// SplitLines splits text into lines, tolerating CRLF and not emitting a
// trailing empty line for a text ending in a newline.
//
// SplitLines("") returns nil, so an absent before- or after-image is an
// empty sequence rather than a one-blank-line sequence. A lone "\n" is
// one empty line, because the text really does contain one (empty) line.
func SplitLines(text string) []string {
	if text == "" {
		return nil
	}
	trimmed := strings.TrimSuffix(text, "\n")
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// normalizeWS collapses every run of whitespace in line to a single
// space and trims the leading and trailing runs. Two lines with the same
// normalization differ only in indentation, alignment padding or trailing
// space — the whitespace bucket, never the modified bucket.
func normalizeWS(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// DiffDegraded reports whether Diff would fall back to plain counting for
// these inputs. Callers use it to drop a result's Confidence, because a
// degenerate alignment cannot tell a modified line from a delete plus an
// add.
func DiffDegraded(oldLines, newLines []string) bool {
	return len(oldLines) > DiffFallbackLines || len(newLines) > DiffFallbackLines
}

// Diff aligns two line sequences in two passes and returns the hunks in
// order.
//
// Pass 1 runs a Myers shortest-edit-script over the WHITESPACE-NORMALIZED
// lines (see normalizeWS). Every pair the script matches becomes an
// OpEqual hunk; Count later decides from the RAW text whether such a pair
// is untouched or a whitespace-only change. This is what makes a 200-line
// reindent read as 200 whitespace and 0 modified lines.
//
// Pass 2 re-runs Myers over the RAW lines of each maximal
// OpDelete+OpInsert residue region left by pass 1 and splices the refined
// sub-alignment back in. Note the standing invariant this implies: while
// pass 1 succeeds exactly, pass 2 cannot discover any NEW OpEqual pair,
// because raw equality implies normalized equality and a
// normalized-equal pair inside a residue would have extended pass 1's
// longest common subsequence. Pass 2 is load-bearing exactly when pass 1
// degrades — when the myersMaxEditDistance cap is hit for the whole
// sequence but not for a smaller residue — and it fixes the delete/insert
// boundaries deterministically in every other case.
//
// Hunks tile the inputs exactly: concatenating the old ranges of the
// OpEqual and OpDelete hunks in order reproduces [0, len(oldLines)), and
// the new ranges of the OpEqual and OpInsert hunks reproduce
// [0, len(newLines)). Within a change region an OpDelete hunk always
// precedes the OpInsert hunk; either may be absent.
//
// Above DiffFallbackLines on either side Diff skips the search entirely
// and returns the degenerate alignment (see DiffDegraded).
func Diff(oldLines, newLines []string) []Hunk {
	if DiffDegraded(oldLines, newLines) {
		return degenerateHunks(len(oldLines), len(newLines))
	}
	if len(oldLines) == 0 && len(newLines) == 0 {
		return nil
	}

	oldNorm := normalizeAll(oldLines)
	newNorm := normalizeAll(newLines)

	pairs := lcsPairs(oldNorm, newNorm)
	hunks := hunksFromPairs(pairs, 0, len(oldLines), 0, len(newLines))
	return refineResidues(hunks, oldLines, newLines)
}

// normalizeAll maps normalizeWS over lines.
func normalizeAll(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = normalizeWS(line)
	}
	return out
}

// degenerateHunks is the alignment used when no search is run: everything
// old is deleted, everything new is inserted.
func degenerateHunks(oldLen, newLen int) []Hunk {
	var hunks []Hunk
	if oldLen > 0 {
		hunks = append(hunks, Hunk{Op: OpDelete, OldStart: 0, OldEnd: oldLen, NewStart: 0, NewEnd: 0})
	}
	if newLen > 0 {
		hunks = append(hunks, Hunk{Op: OpInsert, OldStart: oldLen, OldEnd: oldLen, NewStart: 0, NewEnd: newLen})
	}
	return hunks
}

// pair is one matched line: old index oi aligns with new index ni.
type pair struct {
	oi int
	ni int
}

// lcsPairs returns the matched (old, new) index pairs of a longest common
// subsequence of a and b, in ascending order and strictly increasing on
// both sides.
//
// It trims the common prefix and suffix first (both are always part of
// some optimal alignment) and then runs the bounded Myers search over the
// middle. A search that exceeds myersMaxEditDistance contributes no
// middle pairs, which yields a coarser but still valid alignment.
func lcsPairs(a, b []string) []pair {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return nil
	}

	prefix := 0
	for prefix < n && prefix < m && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < n-prefix && suffix < m-prefix && a[n-1-suffix] == b[m-1-suffix] {
		suffix++
	}

	pairs := make([]pair, 0, prefix+suffix)
	for i := 0; i < prefix; i++ {
		pairs = append(pairs, pair{oi: i, ni: i})
	}
	for _, p := range middlePairs(a[prefix:n-suffix], b[prefix:m-suffix]) {
		pairs = append(pairs, pair{oi: p.oi + prefix, ni: p.ni + prefix})
	}
	for i := 0; i < suffix; i++ {
		pairs = append(pairs, pair{oi: n - suffix + i, ni: m - suffix + i})
	}
	return pairs
}

// middlePairs aligns two sequences that share no common prefix or suffix.
//
// It first drops every line whose text occurs on ONE side only: such a
// line can never appear in a common subsequence, so removing it leaves
// the optimal alignment unchanged while collapsing the classic
// pathological case (two large sequences sharing nothing) to zero work.
func middlePairs(a, b []string) []pair {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}

	inA := make(map[string]struct{}, len(a))
	for _, line := range a {
		inA[line] = struct{}{}
	}
	inB := make(map[string]struct{}, len(b))
	for _, line := range b {
		inB[line] = struct{}{}
	}

	aIdx := make([]int, 0, len(a))
	aVal := make([]string, 0, len(a))
	for i, line := range a {
		if _, ok := inB[line]; ok {
			aIdx = append(aIdx, i)
			aVal = append(aVal, line)
		}
	}
	bIdx := make([]int, 0, len(b))
	bVal := make([]string, 0, len(b))
	for i, line := range b {
		if _, ok := inA[line]; ok {
			bIdx = append(bIdx, i)
			bVal = append(bVal, line)
		}
	}

	matched, ok := myersPairs(aVal, bVal, myersMaxEditDistance)
	if !ok {
		return nil
	}
	out := make([]pair, len(matched))
	for i, p := range matched {
		out[i] = pair{oi: aIdx[p.oi], ni: bIdx[p.ni]}
	}
	return out
}

// myersPairs runs the greedy O(ND) Myers shortest-edit-script and returns
// the matched index pairs. The second result is false when the search
// exceeded maxD edits, in which case no pairs are returned and the caller
// must fall back to a coarser alignment.
//
// Memory grows one V-band per edit-distance step, so nothing O(N^2) is
// allocated up front and a cheap alignment stays cheap.
func myersPairs(a, b []string, maxD int) ([]pair, bool) {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return nil, true
	}

	limit := n + m
	if limit > maxD {
		limit = maxD
	}
	offset := limit + 1
	v := make([]int, 2*limit+3)
	trace := make([][]int, 0, limit+1)

	for d := 0; d <= limit; d++ {
		// Snapshot the band backtracking will read for this round.
		lo, hi := offset-d-1, offset+d+1
		snap := make([]int, hi-lo+1)
		copy(snap, v[lo:hi+1])
		trace = append(trace, snap)

		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1]
			} else {
				x = v[offset+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x >= n && y >= m {
				return backtrackPairs(trace, d, n, m), true
			}
		}
	}
	return nil, false
}

// backtrackPairs walks the recorded V-bands backwards from the script
// endpoint (n, m) and collects the diagonal (matched) steps of the edit
// script. trace[dd] is the V-band as it stood BEFORE round dd ran, so it
// holds round dd-1's endpoints.
func backtrackPairs(trace [][]int, d, n, m int) []pair {
	var pairs []pair
	x, y := n, m
	for dd := d; dd >= 0; dd-- {
		band := trace[dd]
		k := x - y
		var prevK int
		if k == -dd || (k != dd && band[k+dd] < band[k+dd+2]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := band[prevK+dd+1]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			pairs = append(pairs, pair{oi: x, ni: y})
		}
		if dd > 0 {
			x, y = prevX, prevY
		}
	}
	for i, j := 0, len(pairs)-1; i < j; i, j = i+1, j-1 {
		pairs[i], pairs[j] = pairs[j], pairs[i]
	}
	return pairs
}

// hunksFromPairs turns an ascending list of matched index pairs into the
// hunk tiling of the two sequences.
//
// oldOff/newOff are added to every index so a refined residue can be
// spliced back into the whole-file coordinate space; oldLen/newLen are
// the lengths of the sequences the pairs index into.
func hunksFromPairs(pairs []pair, oldOff, oldLen, newOff, newLen int) []Hunk {
	var hunks []Hunk
	oi, ni := 0, 0

	for i := 0; i < len(pairs); {
		p := pairs[i]
		if p.oi > oi {
			hunks = append(hunks, Hunk{
				Op:       OpDelete,
				OldStart: oldOff + oi,
				OldEnd:   oldOff + p.oi,
				NewStart: newOff + ni,
				NewEnd:   newOff + ni,
			})
		}
		if p.ni > ni {
			hunks = append(hunks, Hunk{
				Op:       OpInsert,
				OldStart: oldOff + p.oi,
				OldEnd:   oldOff + p.oi,
				NewStart: newOff + ni,
				NewEnd:   newOff + p.ni,
			})
		}
		j := i
		for j+1 < len(pairs) && pairs[j+1].oi == pairs[j].oi+1 && pairs[j+1].ni == pairs[j].ni+1 {
			j++
		}
		hunks = append(hunks, Hunk{
			Op:       OpEqual,
			OldStart: oldOff + p.oi,
			OldEnd:   oldOff + pairs[j].oi + 1,
			NewStart: newOff + p.ni,
			NewEnd:   newOff + pairs[j].ni + 1,
		})
		oi = pairs[j].oi + 1
		ni = pairs[j].ni + 1
		i = j + 1
	}

	if oi < oldLen {
		hunks = append(hunks, Hunk{
			Op:       OpDelete,
			OldStart: oldOff + oi,
			OldEnd:   oldOff + oldLen,
			NewStart: newOff + ni,
			NewEnd:   newOff + ni,
		})
	}
	if ni < newLen {
		hunks = append(hunks, Hunk{
			Op:       OpInsert,
			OldStart: oldOff + oldLen,
			OldEnd:   oldOff + oldLen,
			NewStart: newOff + ni,
			NewEnd:   newOff + newLen,
		})
	}
	return hunks
}

// refineResidues is pass 2: for every maximal run of adjacent
// OpDelete/OpInsert hunks it re-aligns the region over the RAW lines and
// splices the result back in. A region with an empty side, or one whose
// re-alignment finds nothing, is left exactly as pass 1 produced it.
func refineResidues(hunks []Hunk, oldLines, newLines []string) []Hunk {
	if len(hunks) == 0 {
		return hunks
	}
	out := make([]Hunk, 0, len(hunks))
	for i := 0; i < len(hunks); {
		if hunks[i].Op == OpEqual {
			out = append(out, hunks[i])
			i++
			continue
		}

		j := i
		oldStart, oldEnd := hunks[i].OldStart, hunks[i].OldEnd
		newStart, newEnd := hunks[i].NewStart, hunks[i].NewEnd
		for j < len(hunks) && hunks[j].Op != OpEqual {
			oldStart = min(oldStart, hunks[j].OldStart)
			oldEnd = max(oldEnd, hunks[j].OldEnd)
			newStart = min(newStart, hunks[j].NewStart)
			newEnd = max(newEnd, hunks[j].NewEnd)
			j++
		}

		if oldEnd > oldStart && newEnd > newStart {
			pairs := lcsPairs(oldLines[oldStart:oldEnd], newLines[newStart:newEnd])
			if len(pairs) > 0 {
				out = append(out, hunksFromPairs(pairs, oldStart, oldEnd-oldStart, newStart, newEnd-newStart)...)
				i = j
				continue
			}
		}
		out = append(out, hunks[i:j]...)
		i = j
	}
	return out
}
