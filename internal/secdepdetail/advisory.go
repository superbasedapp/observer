package secdepdetail

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Caps on what one advisory carries into the response.
const (
	// MaxDetailsBytes caps an advisory's details (DetailsTruncated says
	// when it was cut).
	MaxDetailsBytes = 4000
	// MaxSummaryBytes caps the one-line summary.
	MaxSummaryBytes = 500
	// MaxReferences caps the reference links.
	MaxReferences = 12
	// MaxSymbols caps the affected symbols (Go's ecosystem_specific
	// imports).
	MaxSymbols = 20
	// MaxRanges caps the affected ranges.
	MaxRanges = 20
	// MaxRecordBytes caps one OSV record ParseAdvisory reads.
	MaxRecordBytes = 1 << 20

	maxAliases   = 16
	maxCWE       = 10
	maxCVSS      = 4
	maxVersionSz = 64
)

// Advisory is one OSV record as the drawer shows it. Summary and Details
// are third-party prose: they are view-time only (see the package doc).
type Advisory struct {
	ID               string
	Aliases          []string
	Summary          string
	Details          string
	DetailsTruncated bool
	// Published and Modified are RFC 3339 (UTC), "" when the record's value
	// does not parse.
	Published string
	Modified  string
	// CWE are the record's database_specific.cwe_ids ("CWE-1321").
	CWE []string
	// CVSS are the CVSS vectors of the record's severity[].
	CVSS       []string
	References []Reference
	// Ranges are the affected ranges of the affected[] entries that name
	// this package (GIT ranges left out), as intervals.
	Ranges []Range
	// ExplicitVersions counts the versions those entries list one by one.
	ExplicitVersions int
	// AffectedSymbols are "<import path>.<symbol>" from the entries'
	// ecosystem_specific.imports (Go records).
	AffectedSymbols []string
	// MatchesPackage reports whether any affected[] entry names the
	// package (only those entries feed Ranges and the fix).
	MatchesPackage bool
}

// Reference is one http(s) link of a record.
type Reference struct {
	Type string
	URL  string
}

// Range is one affected interval: introduced (inclusive) up to fixed
// (exclusive) or last_affected (inclusive); both empty is open-ended.
type Range struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// osvRecord is the part of the OSV schema the drawer reads. The free-form
// objects are decoded separately so a record with an unexpected shape
// there still parses.
type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected   []osvAffected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
			Limit        string `json:"limit"`
		} `json:"events"`
	} `json:"ranges"`
	Versions          []string        `json:"versions"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
}

var (
	cwePattern   = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	cvssPattern  = regexp.MustCompile(`^CVSS:[0-9.]+/[A-Za-z0-9:/.]{1,200}$`)
	refTypeChars = regexp.MustCompile(`^[A-Z_]{1,32}$`)
	symbolChars  = regexp.MustCompile(`^[A-Za-z0-9_./\-*()]{1,200}$`)
)

// ErrRecordTooLarge reports a record over MaxRecordBytes.
var ErrRecordTooLarge = errors.New("secdepdetail: advisory record too large")

// ParseAdvisory decodes one OSV record for pkg: the record's own fields,
// and the ranges, explicit versions and affected symbols of the affected[]
// entries whose ecosystem and name are the package's (the name normalised
// per ecosystem, NormalizeName). Every text field is stripped of control
// characters and capped; only http and https references are kept.
func ParseAdvisory(raw []byte, pkg Package) (Advisory, error) {
	if len(raw) > MaxRecordBytes {
		return Advisory{}, ErrRecordTooLarge
	}
	var rec osvRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Advisory{}, fmt.Errorf("secdepdetail.ParseAdvisory: %w", err)
	}
	if !validID(rec.ID) {
		return Advisory{}, errors.New("secdepdetail.ParseAdvisory: the record has no valid id")
	}
	a := Advisory{ID: rec.ID}
	for _, al := range rec.Aliases {
		if validID(al) && al != rec.ID && len(a.Aliases) < maxAliases {
			a.Aliases = append(a.Aliases, al)
		}
	}
	a.Summary = cleanShort(rec.Summary, MaxSummaryBytes)
	a.Details, a.DetailsTruncated = capBytes(strings.TrimSpace(cleanText(rec.Details, true)), MaxDetailsBytes)
	a.Published, a.Modified = rfc3339(rec.Published), rfc3339(rec.Modified)
	a.CWE = cweIDs(rec.DatabaseSpecific)
	for _, s := range rec.Severity {
		score := strings.TrimSpace(s.Score)
		if strings.HasPrefix(s.Type, "CVSS_") && cvssPattern.MatchString(score) && len(a.CVSS) < maxCVSS {
			a.CVSS = append(a.CVSS, score)
		}
	}
	for _, r := range rec.References {
		if len(a.References) >= MaxReferences {
			break
		}
		if u, ok := httpURL(r.URL); ok {
			t := strings.ToUpper(strings.TrimSpace(r.Type))
			if !refTypeChars.MatchString(t) {
				t = ""
			}
			a.References = append(a.References, Reference{Type: t, URL: u})
		}
	}
	want := NormalizeName(pkg.Ecosystem, pkg.Name)
	for _, aff := range rec.Affected {
		eco, _, _ := strings.Cut(aff.Package.Ecosystem, ":")
		if eco != pkg.Ecosystem || NormalizeName(pkg.Ecosystem, aff.Package.Name) != want {
			continue
		}
		a.MatchesPackage = true
		a.ExplicitVersions += len(aff.Versions)
		a.Ranges = appendRanges(a.Ranges, aff)
		a.AffectedSymbols = appendSymbols(a.AffectedSymbols, aff.EcosystemSpecific)
	}
	return a, nil
}

// appendRanges turns an entry's range events into intervals: an
// introduced event opens one, a fixed or last_affected event closes it;
// one left open at the end is open-ended. GIT ranges (commit hashes, not
// versions) are left out.
func appendRanges(out []Range, aff osvAffected) []Range {
	for _, rg := range aff.Ranges {
		if strings.EqualFold(rg.Type, "GIT") {
			continue
		}
		var cur *Range
		push := func() {
			if cur != nil && len(out) < MaxRanges {
				out = append(out, *cur)
			}
			cur = nil
		}
		for _, ev := range rg.Events {
			switch {
			case ev.Introduced != "":
				push()
				cur = &Range{Introduced: cleanShort(ev.Introduced, maxVersionSz)}
			case ev.Fixed != "":
				if cur == nil {
					cur = &Range{}
				}
				cur.Fixed = cleanShort(ev.Fixed, maxVersionSz)
				push()
			case ev.LastAffected != "":
				if cur == nil {
					cur = &Range{}
				}
				cur.LastAffected = cleanShort(ev.LastAffected, maxVersionSz)
				push()
			}
		}
		push()
	}
	return out
}

// appendSymbols reads Go's ecosystem_specific.imports[].symbols.
func appendSymbols(out []string, raw json.RawMessage) []string {
	if len(raw) == 0 {
		return out
	}
	var es struct {
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
	}
	if json.Unmarshal(raw, &es) != nil {
		return out
	}
	for _, imp := range es.Imports {
		for _, sym := range imp.Symbols {
			if len(out) >= MaxSymbols {
				return out
			}
			full := sym
			if imp.Path != "" {
				full = imp.Path + "." + sym
			}
			if symbolChars.MatchString(full) {
				out = append(out, full)
			}
		}
	}
	return out
}

// cweIDs reads database_specific.cwe_ids (GitHub advisories).
func cweIDs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var ds struct {
		CWEIDs []string `json:"cwe_ids"`
	}
	if json.Unmarshal(raw, &ds) != nil {
		return nil
	}
	var out []string
	for _, c := range ds.CWEIDs {
		c = strings.TrimSpace(c)
		if cwePattern.MatchString(c) && len(out) < maxCWE {
			out = append(out, c)
		}
	}
	return out
}

// httpURL keeps an absolute http or https URL with a host, re-serialised;
// anything else (javascript:, data:, a relative path) is dropped.
func httpURL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 {
		return "", false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || bidiControl(r) {
			return "", false
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", false
	}
	return u.String(), true
}

// rfc3339 normalises an OSV timestamp to RFC 3339 UTC, "" when it does not
// parse.
func rfc3339(s string) string {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// aliasSet is an advisory's id and aliases.
func (a Advisory) aliasSet() map[string]bool {
	m := map[string]bool{a.ID: true}
	for _, al := range a.Aliases {
		m[al] = true
	}
	return m
}
