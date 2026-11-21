package secfeed

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// build.go is the index builder's pure half (security plan section 8.5,
// Phase D1): it turns OSV malicious-package records and popular-name lists
// into the two index artifacts and their content manifests. It runs where
// the manifest is built (the release pipeline, or tools/secindexbuild on an
// operator's machine), never on a node's hot path; the bytes it is handed
// were fetched by that caller.

// MaxOSVRecordBytes caps one OSV record.
const MaxOSVRecordBytes = 1 << 20

// The builder's caps on one malicious-list item, so EncodeMalicious can
// always fit an entry into index lines (maliciousLines): a longer report
// id or package name is counted malformed and dropped, and a longer
// version is dropped from the entry's list, which then reads as ranged
// (some versions listed, which ones not known offline: S-749, never a
// clean answer). No registry or OSV id comes near them (an npm name is at
// most 214 bytes; a MAL- id is about 15).
const (
	maxMaliciousID      = 64
	maxMaliciousName    = 1024
	maxMaliciousVersion = 256
)

// osvRecord is the subset of the OSV schema the builder reads.
type osvRecord struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string   `json:"versions"`
		Ranges   []osvRange `json:"ranges"`
	} `json:"affected"`
}

// osvRange is one OSV affected range: introduced, fixed, last_affected
// and limit events.
type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// everyVersion reports a range that covers every version: introduced at
// "0" (or nothing) with no fixed, last_affected or limit event. Any other
// range covers some versions only, which the builder cannot enumerate
// without a version comparator (section 8.2: Observer writes none).
func (r osvRange) everyVersion() bool {
	introduced0 := false
	for _, e := range r.Events {
		for k, v := range e {
			switch k {
			case "introduced":
				if v == "0" || v == "" {
					introduced0 = true
				}
			case "fixed", "last_affected", "limit":
				return false
			}
		}
	}
	return introduced0
}

// coverage reads one affected entry: every version, or the enumerated
// versions plus whether some ranges leave versions unenumerated.
func coverage(versions []string, ranges []osvRange) (all, ranged bool) {
	if len(versions) > 0 {
		return false, false
	}
	if len(ranges) == 0 {
		// No versions and no ranges: OSV's "the whole package".
		return true, false
	}
	for _, r := range ranges {
		if r.everyVersion() {
			return true, false
		}
	}
	return false, true
}

// MalCoversEveryVersion reads one OSV record (as `/v1/vulns/{id}` returns
// it) and reports whether it is a live MAL- report whose affected entry for
// the package covers every version (build.go's coverage rule: no versions
// and no ranges, or a range introduced at "0" with no end). ok is false for
// a record that does not parse, is not a MAL- report, is withdrawn, or
// names another id or package: such a record never raises a verdict.
func MalCoversEveryVersion(raw []byte, id string, eco Ecosystem, name string) (all, ok bool) {
	var r osvRecord
	if len(raw) > MaxOSVRecordBytes || json.Unmarshal(raw, &r) != nil || r.ID != id || !strings.HasPrefix(r.ID, "MAL-") || r.Withdrawn != "" {
		return false, false
	}
	want := Normalize(eco, name)
	for _, a := range r.Affected {
		e, known := EcosystemFromOSV(a.Package.Ecosystem)
		if !known || e != eco || Normalize(eco, a.Package.Name) != want {
			continue
		}
		ok = true
		if every, _ := coverage(a.Versions, a.Ranges); every {
			return true, true
		}
	}
	return false, ok
}

// BuildStats counts what the builder kept and why it dropped the rest.
type BuildStats struct {
	Records, Kept, NotMAL, Withdrawn, UnknownEco, Malformed int
}

// MaliciousFromOSV reads OSV records (one JSON document each) and keeps
// only MAL- reports (the authenticated source of S-741's deny, section
// 8.5): a GHSA or CVE id never enters the malicious list, and a withdrawn
// report is dropped. Entries for one package merge. It is MaliciousBuilder
// over a slice; a caller reading a whole OSV export (hundreds of MB of
// records) feeds the builder one record at a time instead.
func MaliciousFromOSV(records [][]byte) ([]MaliciousEntry, BuildStats) {
	b := NewMaliciousBuilder()
	for _, raw := range records {
		b.Add(raw)
	}
	return b.Entries()
}

// maliciousKey is one listed package.
type maliciousKey struct {
	eco  Ecosystem
	name string
}

// MaliciousBuilder merges OSV records into the malicious list one record
// at a time, so a builder reading an export never holds every record (the
// npm export carried 223,008 MAL- reports, 364 MB of JSON, on 2026-11-06).
// The rules are MaliciousFromOSV's.
type MaliciousBuilder struct {
	st          BuildStats
	merged      map[maliciousKey]*MaliciousEntry
	allVersions map[maliciousKey]bool
}

// NewMaliciousBuilder returns an empty builder.
func NewMaliciousBuilder() *MaliciousBuilder {
	return &MaliciousBuilder{merged: map[maliciousKey]*MaliciousEntry{}, allVersions: map[maliciousKey]bool{}}
}

// Add reads one OSV record.
func (b *MaliciousBuilder) Add(raw []byte) {
	b.st.Records++
	var r osvRecord
	if len(raw) > MaxOSVRecordBytes || json.Unmarshal(raw, &r) != nil || r.ID == "" {
		b.st.Malformed++
		return
	}
	if !strings.HasPrefix(r.ID, "MAL-") {
		b.st.NotMAL++
		return
	}
	if len(r.ID) > maxMaliciousID || strings.ContainsAny(r.ID, ",\t\n\r ") {
		b.st.Malformed++
		return
	}
	if r.Withdrawn != "" {
		b.st.Withdrawn++
		return
	}
	kept := false
	for _, a := range r.Affected {
		eco, ok := EcosystemFromOSV(a.Package.Ecosystem)
		if !ok {
			b.st.UnknownEco++
			continue
		}
		name := Normalize(eco, a.Package.Name)
		if name == "" || len(name) > maxMaliciousName || strings.ContainsAny(name, "\t\n\r") {
			b.st.Malformed++
			continue
		}
		k := maliciousKey{eco, name}
		e := b.merged[k]
		if e == nil {
			e = &MaliciousEntry{Eco: eco, Name: name}
			b.merged[k] = e
		}
		if !containsString(e.IDs, r.ID) {
			e.IDs = append(e.IDs, r.ID)
		}
		all, ranged := coverage(a.Versions, a.Ranges)
		if all {
			b.allVersions[k] = true
		}
		if ranged {
			e.Ranged = true
		}
		for _, v := range a.Versions {
			switch {
			case v == "" || containsString(e.Versions, v):
			case len(v) > maxMaliciousVersion || strings.ContainsAny(v, ",\t\n\r"):
				// A listed version the index cannot carry: the entry lists
				// some versions it does not name, which is what ranged
				// means (S-749), never a silently dropped listing.
				e.Ranged = true
			default:
				e.Versions = append(e.Versions, v)
			}
		}
		kept = true
	}
	if kept {
		b.st.Kept++
	}
}

// Stats returns the counts so far.
func (b *MaliciousBuilder) Stats() BuildStats { return b.st }

// Len returns the number of packages listed so far.
func (b *MaliciousBuilder) Len() int { return len(b.merged) }

// Entries returns the merged list, sorted by ecosystem and name, and the
// counts so far. Call it once, after the last Add.
func (b *MaliciousBuilder) Entries() ([]MaliciousEntry, BuildStats) {
	out := make([]MaliciousEntry, 0, len(b.merged))
	for k, e := range b.merged {
		if b.allVersions[k] {
			// One report covers every version: the entry does too.
			e.Versions, e.Ranged = nil, false
		}
		sort.Strings(e.IDs)
		sort.Strings(e.Versions)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Eco != out[j].Eco {
			return out[i].Eco < out[j].Eco
		}
		return out[i].Name < out[j].Name
	})
	return out, b.st
}

// PopularFromList reads one name per line (blank lines and # comments
// skipped), normalized and deduplicated, capped at MaxPopularPer.
func PopularFromList(eco Ecosystem, list []byte) ([]string, error) {
	if _, ok := EcosystemOf(eco); !ok {
		return nil, fmt.Errorf("secfeed.PopularFromList: unknown ecosystem %q", eco)
	}
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(list))
	sc.Buffer(make([]byte, 0, 4096), MaxIndexLineLen)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		names = append(names, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secfeed.PopularFromList: %w", err)
	}
	return PopularFromNames(eco, names)
}

// PopularFromNames normalizes and deduplicates a list of names already
// split (a line list, or a ranked JSON array of names as a popularity
// source serves it), capped at MaxPopularPer, sorted. A name that is empty
// after normalization, or holds whitespace or a control character, is
// skipped: no registry names a package that way, and such a name could
// break the index's line format.
func PopularFromNames(eco Ecosystem, names []string) ([]string, error) {
	if _, ok := EcosystemOf(eco); !ok {
		return nil, fmt.Errorf("secfeed.PopularFromNames: unknown ecosystem %q", eco)
	}
	// The longest line the index carries: "<eco>\t<name>".
	maxName := MaxIndexLineLen - len(eco) - 1
	seen := map[string]bool{}
	var out []string
	for _, raw := range names {
		n := Normalize(eco, raw)
		if n == "" || len(n) > maxName || strings.ContainsFunc(n, isSpaceOrControl) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) > MaxPopularPer {
			return nil, fmt.Errorf("secfeed.PopularFromNames: more than %d names for %s", MaxPopularPer, eco)
		}
	}
	sort.Strings(out)
	return out, nil
}

// isSpaceOrControl reports a rune no package name holds.
func isSpaceOrControl(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r)
}

// ManifestInput is one artifact's publication.
type ManifestInput struct {
	Kind            content.Kind
	ManifestVersion int64
	Epoch           int64
	Issued          time.Time
	Validity        time.Duration
	Name            string
	Data            []byte
	Version         string
	Source          string
	License         string
}

// BuildManifest returns the content manifest that covers one index
// artifact. The caller signs it (content.Sign).
func BuildManifest(in ManifestInput) (content.Manifest, error) {
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: in.Kind, ManifestVersion: in.ManifestVersion, Epoch: in.Epoch,
		IssuedAt:  in.Issued.UTC().Format(time.RFC3339),
		ExpiresAt: in.Issued.Add(in.Validity).UTC().Format(time.RFC3339),
		Entries: []content.Entry{{
			Name: in.Name, Version: in.Version, SizeBytes: int64(len(in.Data)), SHA256: content.HashBytes(in.Data),
			Source: in.Source, License: in.License, Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
		}},
	}
	if err := content.Validate(m); err != nil {
		return content.Manifest{}, fmt.Errorf("secfeed.BuildManifest: %w", err)
	}
	return m, nil
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
