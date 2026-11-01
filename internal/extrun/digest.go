package extrun

import (
	"sort"
	"strings"
)

// CompareDigests compares the recorded digests against the expected ones.
// A nil expect, or an empty expected field, is not compared. A companion the
// expectation names but the run did not record is a mismatch with an empty
// Actual. Digests compare case-insensitively (hex). The result is sorted with
// the binary first, then companions by path.
func CompareDigests(expect *Digests, got Digests) []Mismatch {
	if expect == nil {
		return nil
	}
	var out []Mismatch
	if expect.Binary != "" && !strings.EqualFold(expect.Binary, got.Binary) {
		out = append(out, Mismatch{Expected: expect.Binary, Actual: got.Binary})
	}
	paths := make([]string, 0, len(expect.Companions))
	for p := range expect.Companions {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		want := expect.Companions[p]
		if want == "" {
			continue
		}
		if have := got.Companions[p]; !strings.EqualFold(want, have) {
			out = append(out, Mismatch{Path: p, Expected: want, Actual: have})
		}
	}
	return out
}
