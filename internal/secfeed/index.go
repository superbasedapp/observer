package secfeed

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The two index artifacts, one per content kind (content.MaliciousPackages
// and content.PopularNames), so the daily malicious list and the
// slower popular-names lists keep separate epochs and cadences.
const (
	MaliciousArtifact = "malicious.idx"
	PopularArtifact   = "popular.idx"
)

// File headers. A file whose first line is not its header is refused.
const (
	maliciousHeader = "# sbo-malicious-index v1"
	popularHeader   = "# sbo-popular-index v1"
)

// Caps on the index files. The OpenSSF list carries a few hundred thousand
// reports; the caps leave room and still bound a hook's read.
const (
	MaxIndexBytes   = 64 << 20
	MaxIndexLines   = 2_000_000
	MaxIndexLineLen = 4096
	MaxPopularPer   = 50_000
)

// MaliciousEntry is one listed package.
type MaliciousEntry struct {
	Eco  Ecosystem
	Name string
	// IDs are the OSV MAL- report ids; only MAL- ids are ever listed.
	IDs []string
	// Versions are the affected versions; empty with Ranged false means
	// every version.
	Versions []string
	// Ranged reports OSV ranges the builder could not enumerate (a fixed
	// or last_affected event): some versions are affected, which ones is
	// not known offline. Written as a "?" version token.
	Ranged bool
}

// rangedToken marks an entry's unenumerated ranges in the versions field.
const rangedToken = "?"

// ErrIndex wraps every index format refusal.
var ErrIndex = errors.New("secfeed: install index refused")

// EncodeMalicious writes the malicious artifact: header, then one
// tab-separated line per entry, sorted by ecosystem and name.
func EncodeMalicious(entries []MaliciousEntry) []byte {
	es := append([]MaliciousEntry(nil), entries...)
	sort.Slice(es, func(i, j int) bool {
		if es[i].Eco != es[j].Eco {
			return es[i].Eco < es[j].Eco
		}
		return es[i].Name < es[j].Name
	})
	var b bytes.Buffer
	b.WriteString(maliciousHeader + "\n")
	for _, e := range es {
		vers := "*"
		if len(e.Versions) > 0 || e.Ranged {
			vs := append([]string(nil), e.Versions...)
			if e.Ranged {
				vs = append(vs, rangedToken)
			}
			vers = strings.Join(vs, ",")
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", e.Eco, e.Name, strings.Join(e.IDs, ","), vers)
	}
	return b.Bytes()
}

// EncodePopular writes the popular artifact: header, then one
// "<eco>\t<name>" line per name, sorted.
func EncodePopular(names map[Ecosystem][]string) []byte {
	var lines []string
	for eco, ns := range names {
		for _, n := range ns {
			lines = append(lines, string(eco)+"\t"+n)
		}
	}
	sort.Strings(lines)
	var b bytes.Buffer
	b.WriteString(popularHeader + "\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.Bytes()
}

// Index is the offline install index in memory: per ecosystem, the listed
// packages and the popular names, both sorted for binary search.
type Index struct {
	malicious map[Ecosystem][]MaliciousEntry
	popular   map[Ecosystem][]string
	// malRaw and popRaw back a verified index (ParseIndexVerified): the
	// artifacts' own sorted lines, searched in place instead of parsed.
	malRaw, popRaw *rawList
	// HasMalicious and HasPopular report which artifact was loaded; a
	// lookup against a missing half says so (Answer.IndexMissing).
	HasMalicious, HasPopular bool
}

// ParseIndex reads the two artifacts; either may be nil (not installed).
func ParseIndex(malicious, popular []byte) (*Index, error) {
	ix := &Index{malicious: map[Ecosystem][]MaliciousEntry{}, popular: map[Ecosystem][]string{}}
	if malicious != nil {
		if err := scanIndex(malicious, maliciousHeader, func(f []string) error {
			if len(f) != 4 {
				return errors.New("want 4 fields")
			}
			eco := Ecosystem(f[0])
			if _, ok := EcosystemOf(eco); !ok {
				return nil // a newer builder's ecosystem: skipped, not refused
			}
			ids := strings.Split(f[2], ",")
			for _, id := range ids {
				if !strings.HasPrefix(id, "MAL-") {
					return fmt.Errorf("id %q is not a MAL- report", clip(id, 40))
				}
			}
			e := MaliciousEntry{Eco: eco, Name: f[1], IDs: ids}
			if f[3] != "*" {
				for _, v := range strings.Split(f[3], ",") {
					if v == rangedToken {
						e.Ranged = true
						continue
					}
					e.Versions = append(e.Versions, v)
				}
			}
			ix.malicious[eco] = append(ix.malicious[eco], e)
			return nil
		}); err != nil {
			return nil, err
		}
		ix.HasMalicious = true
	}
	if popular != nil {
		count := map[Ecosystem]int{}
		if err := scanIndex(popular, popularHeader, func(f []string) error {
			if len(f) != 2 {
				return errors.New("want 2 fields")
			}
			eco := Ecosystem(f[0])
			if _, ok := EcosystemOf(eco); !ok {
				return nil
			}
			if count[eco]++; count[eco] > MaxPopularPer {
				return fmt.Errorf("more than %d popular names for %s", MaxPopularPer, eco)
			}
			ix.popular[eco] = append(ix.popular[eco], f[1])
			return nil
		}); err != nil {
			return nil, err
		}
		ix.HasPopular = true
	}
	for eco := range ix.malicious {
		es := ix.malicious[eco]
		sort.Slice(es, func(i, j int) bool { return es[i].Name < es[j].Name })
	}
	for eco := range ix.popular {
		sort.Strings(ix.popular[eco])
	}
	return ix, nil
}

// scanIndex walks an artifact's lines after its header.
func scanIndex(b []byte, header string, line func([]string) error) error {
	if len(b) > MaxIndexBytes {
		return fmt.Errorf("%w: %d bytes", ErrIndex, len(b))
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), MaxIndexLineLen)
	n := 0
	for sc.Scan() {
		n++
		if n > MaxIndexLines {
			return fmt.Errorf("%w: more than %d lines", ErrIndex, MaxIndexLines)
		}
		t := sc.Text()
		if n == 1 {
			if t != header {
				return fmt.Errorf("%w: header %q", ErrIndex, clip(t, 40))
			}
			continue
		}
		if t == "" {
			continue
		}
		if err := line(strings.Split(t, "\t")); err != nil {
			return fmt.Errorf("%w: line %d: %w", ErrIndex, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrIndex, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: empty", ErrIndex)
	}
	return nil
}

// Answer is the offline index's answer about one package.
type Answer struct {
	// Malicious is set when the listing covers the version installed: an
	// entry for every version, or a pinned version the entry lists. IDs
	// are its MAL- reports.
	Malicious bool
	IDs       []string
	// ListedVersions is set when some versions are listed but the install
	// may or may not resolve to one: an unpinned install against a
	// version-specific listing, or any install against a listing by
	// range. It is never Malicious (S-749 flags it, S-741 does not deny).
	ListedVersions bool
	// Popular is set when the name is on the popular list.
	Popular bool
	// NearMiss is the popular name this one is one edit from, "" if none.
	NearMiss string
	// MaliciousMissing and PopularMissing report a half the index did not
	// have (not installed, or unusable): the answer cannot claim it.
	MaliciousMissing, PopularMissing bool
}

// Lookup answers for one package. name is normalized here; version "" asks
// about any version (an install with no pin can resolve to a listed one).
func (ix *Index) Lookup(eco Ecosystem, name, version string) Answer {
	var a Answer
	if ix == nil {
		return Answer{MaliciousMissing: true, PopularMissing: true}
	}
	n := Normalize(eco, name)
	a.MaliciousMissing, a.PopularMissing = !ix.HasMalicious, !ix.HasPopular
	es := ix.malicious[eco]
	if ix.malRaw != nil {
		es = ix.malRaw.entries(eco, n)
	}
	i := sort.Search(len(es), func(i int) bool { return es[i].Name >= n })
	for ; i < len(es) && es[i].Name == n; i++ {
		switch versionListed(es[i], version) {
		case listedCovers:
			a.Malicious = true
			a.IDs = append(a.IDs, es[i].IDs...)
		case listedSome:
			a.ListedVersions = true
			a.IDs = append(a.IDs, es[i].IDs...)
		}
	}
	if a.Malicious {
		a.ListedVersions = false
	}
	pop := ix.popular[eco]
	if ix.popRaw != nil {
		pop = ix.popRaw.names(eco)
	}
	j := sort.SearchStrings(pop, n)
	a.Popular = j < len(pop) && pop[j] == n
	if !a.Popular {
		a.NearMiss = nearMiss(eco, n, pop)
	}
	return a
}

// listedMatch is how one entry relates to the version installed.
type listedMatch int

const (
	listedNone   listedMatch = iota // a pinned version the entry does not list
	listedCovers                    // every version, or the pinned version listed
	listedSome                      // some versions; the install may resolve to one
)

// versionListed: an entry for every version covers anything; a pinned
// install is covered when its version is listed; an unpinned install
// against a version-specific listing, or any install the entry's
// unenumerated ranges may contain, is "some" (S-749, never S-741).
func versionListed(e MaliciousEntry, version string) listedMatch {
	if len(e.Versions) == 0 && !e.Ranged {
		return listedCovers
	}
	if version == "" {
		return listedSome
	}
	for _, v := range e.Versions {
		if v == version {
			return listedCovers
		}
	}
	if e.Ranged {
		return listedSome
	}
	return listedNone
}

// nearMiss returns the popular name n is one edit from (an insertion,
// deletion, substitution or adjacent swap, or a separator change), or "".
func nearMiss(eco Ecosystem, n string, popular []string) string {
	spec, _ := EcosystemOf(eco)
	if len(n) < spec.NearMissMin {
		return ""
	}
	sepless := stripSeparators(n)
	for _, p := range popular {
		if len(p) < spec.NearMissMin {
			continue
		}
		d := len(p) - len(n)
		if d > 1 || d < -1 {
			if stripSeparators(p) != sepless {
				continue
			}
		}
		if p != n && (withinOneEdit(n, p) || stripSeparators(p) == sepless) {
			return p
		}
	}
	return ""
}

func stripSeparators(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(s)
}

// withinOneEdit reports an optimal-string-alignment distance of at most 1.
func withinOneEdit(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	switch {
	case la == lb:
		diff := -1
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				if diff >= 0 {
					// a second mismatch: only an adjacent swap is one edit
					return diff == i-1 && a[diff] == b[i] && a[i] == b[diff] && a[i+1:] == b[i+1:]
				}
				diff = i
			}
		}
		return true
	case la == lb+1:
		return oneDeletion(a, b)
	case lb == la+1:
		return oneDeletion(b, a)
	}
	return false
}

// oneDeletion reports that removing one byte of long gives short.
func oneDeletion(long, short string) bool {
	i := 0
	for i < len(short) && long[i] == short[i] {
		i++
	}
	return long[i+1:] == short[i:]
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// rawList is a verified artifact searched in place: the offsets of its
// lines after the header, in the file's (ecosystem, name) order.
type rawList struct {
	b      []byte
	starts []int
}

// newRawList indexes an artifact's lines. It checks the header and the
// caps only: the caller vouches that the bytes passed ValidateIndex.
func newRawList(b []byte, header string) (*rawList, error) {
	if len(b) > MaxIndexBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrIndex, len(b))
	}
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 || string(b[:nl]) != header {
		return nil, fmt.Errorf("%w: header", ErrIndex)
	}
	r := &rawList{b: b}
	for i := nl + 1; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		end := len(b)
		if j >= 0 {
			end = i + j
		}
		if end > i {
			r.starts = append(r.starts, i)
			if len(r.starts) > MaxIndexLines {
				return nil, fmt.Errorf("%w: more than %d lines", ErrIndex, MaxIndexLines)
			}
		}
		i = end + 1
	}
	return r, nil
}

// line returns line i without its newline.
func (r *rawList) line(i int) []byte {
	l := r.b[r.starts[i]:]
	if j := bytes.IndexByte(l, '\n'); j >= 0 {
		l = l[:j]
	}
	return l
}

// key returns line i's "<eco>\t<name>" prefix.
func (r *rawList) key(i int) []byte {
	l := r.line(i)
	first := bytes.IndexByte(l, '\t')
	if first < 0 {
		return l
	}
	if second := bytes.IndexByte(l[first+1:], '\t'); second >= 0 {
		return l[:first+1+second]
	}
	return l
}

// span returns the lines whose key equals k exactly, or (when prefix) whose
// key starts with k.
func (r *rawList) span(k string, prefix bool) (int, int) {
	lo := sort.Search(len(r.starts), func(i int) bool { return string(r.key(i)) >= k })
	hi := lo
	for hi < len(r.starts) {
		key := string(r.key(hi))
		if key != k && !(prefix && strings.HasPrefix(key, k)) {
			break
		}
		hi++
	}
	return lo, hi
}

// entries returns the listed entries for one normalized name.
func (r *rawList) entries(eco Ecosystem, n string) []MaliciousEntry {
	lo, hi := r.span(string(eco)+"\t"+n, false)
	var out []MaliciousEntry
	for i := lo; i < hi; i++ {
		if e, ok := maliciousEntryOf(strings.Split(string(r.line(i)), "\t")); ok {
			out = append(out, e)
		}
	}
	return out
}

// names returns an ecosystem's popular names, in order.
func (r *rawList) names(eco Ecosystem) []string {
	lo, hi := r.span(string(eco)+"\t", true)
	out := make([]string, 0, hi-lo)
	for i := lo; i < hi; i++ {
		_, name, _ := strings.Cut(string(r.line(i)), "\t")
		out = append(out, name)
	}
	return out
}

// maliciousEntryOf reads one malicious line's fields (already validated).
func maliciousEntryOf(f []string) (MaliciousEntry, bool) {
	if len(f) != 4 {
		return MaliciousEntry{}, false
	}
	e := MaliciousEntry{Eco: Ecosystem(f[0]), Name: f[1], IDs: strings.Split(f[2], ",")}
	if f[3] != "*" {
		for _, v := range strings.Split(f[3], ",") {
			if v == rangedToken {
				e.Ranged = true
				continue
			}
			e.Versions = append(e.Versions, v)
		}
	}
	return e, true
}

// ValidateIndex checks one artifact fully, once per index version: every
// line as ParseIndex reads it, and the lines in strict (ecosystem, name)
// order, so a verified index can be searched in place
// (ParseIndexVerified). popular selects the popular artifact's format.
func ValidateIndex(b []byte, popular bool) error {
	var err error
	header := maliciousHeader
	if popular {
		_, err = ParseIndex(nil, b)
		header = popularHeader
	} else {
		_, err = ParseIndex(b, nil)
	}
	if err != nil {
		return err
	}
	r, err := newRawList(b, header)
	if err != nil {
		return err
	}
	for i := 1; i < len(r.starts); i++ {
		if bytes.Compare(r.key(i-1), r.key(i)) > 0 {
			return fmt.Errorf("%w: line %d is out of order", ErrIndex, i+2)
		}
	}
	return nil
}

// ParseIndexVerified builds an index over artifacts that passed
// ValidateIndex (the caller recorded that once per index version) without
// parsing them: lookups binary-search the sorted lines in place, so the
// hook does not parse a list of hundreds of thousands of reports on every
// install. Either artifact may be nil (not installed).
func ParseIndexVerified(malicious, popular []byte) (*Index, error) {
	ix := &Index{malicious: map[Ecosystem][]MaliciousEntry{}, popular: map[Ecosystem][]string{}}
	var err error
	if malicious != nil {
		if ix.malRaw, err = newRawList(malicious, maliciousHeader); err != nil {
			return nil, err
		}
		ix.HasMalicious = true
	}
	if popular != nil {
		if ix.popRaw, err = newRawList(popular, popularHeader); err != nil {
			return nil, err
		}
		ix.HasPopular = true
	}
	return ix, nil
}
