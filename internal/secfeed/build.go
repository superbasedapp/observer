package secfeed

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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
// report is dropped. Entries for one package merge.
func MaliciousFromOSV(records [][]byte) ([]MaliciousEntry, BuildStats) {
	var st BuildStats
	type key struct {
		eco  Ecosystem
		name string
	}
	merged := map[key]*MaliciousEntry{}
	allVersions := map[key]bool{}
	for _, raw := range records {
		st.Records++
		var r osvRecord
		if len(raw) > MaxOSVRecordBytes || json.Unmarshal(raw, &r) != nil || r.ID == "" {
			st.Malformed++
			continue
		}
		if !strings.HasPrefix(r.ID, "MAL-") {
			st.NotMAL++
			continue
		}
		if r.Withdrawn != "" {
			st.Withdrawn++
			continue
		}
		kept := false
		for _, a := range r.Affected {
			eco, ok := EcosystemFromOSV(a.Package.Ecosystem)
			if !ok {
				st.UnknownEco++
				continue
			}
			name := Normalize(eco, a.Package.Name)
			if name == "" || strings.ContainsAny(name, "\t\n\r") {
				st.Malformed++
				continue
			}
			k := key{eco, name}
			e := merged[k]
			if e == nil {
				e = &MaliciousEntry{Eco: eco, Name: name}
				merged[k] = e
			}
			if !containsString(e.IDs, r.ID) {
				e.IDs = append(e.IDs, r.ID)
			}
			all, ranged := coverage(a.Versions, a.Ranges)
			if all {
				allVersions[k] = true
			}
			if ranged {
				e.Ranged = true
			}
			for _, v := range a.Versions {
				if v != "" && !strings.ContainsAny(v, ",\t\n") && !containsString(e.Versions, v) {
					e.Versions = append(e.Versions, v)
				}
			}
			kept = true
		}
		if kept {
			st.Kept++
		}
	}
	out := make([]MaliciousEntry, 0, len(merged))
	for k, e := range merged {
		if allVersions[k] {
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
	return out, st
}

// PopularFromList reads one name per line (blank lines and # comments
// skipped), normalized and deduplicated, capped at MaxPopularPer.
func PopularFromList(eco Ecosystem, list []byte) ([]string, error) {
	if _, ok := EcosystemOf(eco); !ok {
		return nil, fmt.Errorf("secfeed.PopularFromList: unknown ecosystem %q", eco)
	}
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(list))
	sc.Buffer(make([]byte, 0, 4096), MaxIndexLineLen)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n := Normalize(eco, t)
		if n == "" || strings.ContainsAny(n, "\t ") || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) > MaxPopularPer {
			return nil, fmt.Errorf("secfeed.PopularFromList: more than %d names for %s", MaxPopularPer, eco)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secfeed.PopularFromList: %w", err)
	}
	sort.Strings(out)
	return out, nil
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
