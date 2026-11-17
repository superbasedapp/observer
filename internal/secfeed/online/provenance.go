package online

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// provenanceMinLeft is the least time the install wait must still hold for
// an extra provenance request: with less, the state is unknown and no
// request is made (the verdict never waits on provenance).
const provenanceMinLeft = 200 * time.Millisecond

// pypiSimpleAccept is the PyPI simple index's JSON media type (PEP 691).
const pypiSimpleAccept = "application/vnd.pypi.simple.v1+json"

// npmAbbrevDoc is the part of npm's abbreviated packument the lane reads.
// Versions stay raw: a version entry the provenance read cannot decode
// counts as one without provenance and never fails the verdict's read.
type npmAbbrevDoc struct {
	Modified string                     `json:"modified"`
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
}

// npmAbbrevVersion is one version of the abbreviated packument.
type npmAbbrevVersion struct {
	Dist struct {
		Attestations *struct {
			Provenance json.RawMessage `json:"provenance"`
		} `json:"attestations"`
	} `json:"dist"`
}

// npmHasProvenance reports a version published with npm provenance: its
// dist.attestations names a provenance predicate.
func npmHasProvenance(raw json.RawMessage) bool {
	var v npmAbbrevVersion
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	a := v.Dist.Attestations
	if a == nil {
		return false
	}
	p := strings.TrimSpace(string(a.Provenance))
	return p != "" && p != "null"
}

// npmProvenanceFacts builds the provenance facts of an npm install from
// the abbreviated packument: Order is semver order (golang.org/x/mod/semver
// over "v"+version; a version that is not valid semver is dropped), the
// target is the pinned version (or the dist-tag it names), else
// dist-tags.latest.
func npmProvenanceFacts(d npmAbbrevDoc, pinned string) secfeed.ProvenanceFacts {
	type ver struct {
		name string
		has  bool
	}
	var vs []ver
	for name, v := range d.Versions {
		if !semver.IsValid("v" + name) {
			continue
		}
		vs = append(vs, ver{name, npmHasProvenance(v)})
	}
	sort.Slice(vs, func(i, j int) bool {
		if c := semver.Compare("v"+vs[i].name, "v"+vs[j].name); c != 0 {
			return c < 0
		}
		return vs[i].name < vs[j].name
	})
	f := secfeed.ProvenanceFacts{Target: pinned}
	order := 0
	for i, v := range vs {
		if i > 0 && semver.Compare("v"+vs[i-1].name, "v"+v.name) != 0 {
			order++
		}
		f.Versions = append(f.Versions, secfeed.VersionProvenance{Version: v.name, Has: v.has, Order: order})
	}
	if tag, ok := d.DistTags[f.Target]; ok && f.Target != "" {
		f.Target = tag
	}
	if f.Target == "" {
		f.Target = d.DistTags["latest"]
	}
	return f
}

// pypiSimpleDoc is the part of PyPI's simple JSON page the lane reads.
type pypiSimpleDoc struct {
	Files []struct {
		Filename   string          `json:"filename"`
		Provenance json.RawMessage `json:"provenance"`
		UploadTime string          `json:"upload-time"`
		Yanked     json.RawMessage `json:"yanked"`
	} `json:"files"`
}

// pypiProvenance is PyPI's provenance reader: one GET of the simple index
// page for name, under its own back-off key so a 429 there never cools
// down the verdict's JSON request. Any failure is unknown; it never sets a
// status or a reason.
func pypiProvenance(ctx context.Context, c *Client, name, pinned string) policy.InstallProvenance {
	raw := "https://pypi.org/simple/" + url.PathEscape(name) + "/"
	b, status, _, err := c.doKeyed(ctx, "pypi.org/simple", http.MethodGet, raw, nil, maxRegistryBytes, pypiSimpleAccept, "")
	if err != nil || status != http.StatusOK {
		return policy.InstallProvenanceUnknown
	}
	var d pypiSimpleDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return policy.InstallProvenanceUnknown
	}
	return secfeed.DecideProvenance(pypiProvenanceFacts(d, name, pinned))
}

// pypiProvenanceFacts builds the provenance facts of a PyPI install from
// the simple JSON page: each non-yanked file's version from its name, a
// version Has when any of its files carries a provenance URL, Order by the
// version's earliest upload, the target the pinned version else the
// version first uploaded last.
func pypiProvenanceFacts(d pypiSimpleDoc, name, pinned string) secfeed.ProvenanceFacts {
	type ver struct {
		first time.Time
		has   bool
	}
	byVer := map[string]*ver{}
	for _, f := range d.Files {
		if yanked(f.Yanked) {
			continue
		}
		v := pypiFileVersion(f.Filename, name)
		up := parseTime(f.UploadTime)
		if v == "" || up.IsZero() {
			continue
		}
		e := byVer[v]
		if e == nil {
			e = &ver{first: up}
			byVer[v] = e
		}
		e.first = earliest(e.first, up)
		p := strings.TrimSpace(string(f.Provenance))
		if p != "" && p != "null" && p != `""` {
			e.has = true
		}
	}
	names := make([]string, 0, len(byVer))
	for v := range byVer {
		names = append(names, v)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := byVer[names[i]].first, byVer[names[j]].first
		if !a.Equal(b) {
			return a.Before(b)
		}
		return names[i] < names[j]
	})
	f := secfeed.ProvenanceFacts{Target: strings.ToLower(pinned)}
	for i, v := range names {
		f.Versions = append(f.Versions, secfeed.VersionProvenance{Version: v, Has: byVer[v].has, Order: i})
	}
	if f.Target == "" {
		// An unpinned install resolves to the newest final release (pip
		// skips pre-releases by default); a project with only pre-releases
		// leaves the target unknown.
		for i := len(names) - 1; i >= 0; i-- {
			if !pep440Pre.MatchString(names[i]) {
				f.Target = names[i]
				break
			}
		}
	}
	return f
}

// pep440Pre matches a PEP 440 pre-release or development version
// (1.0a1, 2.0b2, 3.0rc1, 1.0.dev3, 1.0-alpha, 2.0.preview1).
var pep440Pre = regexp.MustCompile(`(?i)\d[._-]?(a|b|c|rc|alpha|beta|pre|preview|dev)[._-]?\d*([.+]|$)`)

// yanked reads the simple API's yanked field: false, or true / a reason
// string (PEP 592).
func yanked(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "false" && s != "null"
}

// pypiCanon is the PEP 503 form of a project name (lower case, runs of
// "-", "_" and "." one "-").
func pypiCanon(s string) string { return secfeed.Normalize(secfeed.EcoPyPI, s) }

// pypiFileVersion returns the version a distribution file name carries for
// project name ("" when the file is not one of name's or its form is not
// known): a wheel's second dash field; an sdist's stem after the name.
func pypiFileVersion(filename, name string) string {
	want := pypiCanon(name)
	lower := strings.ToLower(filename)
	if stem, ok := strings.CutSuffix(lower, ".whl"); ok {
		parts := strings.Split(stem, "-")
		if len(parts) < 5 || pypiCanon(parts[0]) != want {
			return ""
		}
		return parts[1]
	}
	stem := ""
	for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2"} {
		if s, ok := strings.CutSuffix(lower, ext); ok {
			stem = s
			break
		}
	}
	if stem == "" {
		return ""
	}
	for i := 0; i < len(stem); i++ {
		if stem[i] == '-' && i+1 < len(stem) && pypiCanon(stem[:i]) == want {
			return stem[i+1:]
		}
	}
	return ""
}

// provenanceOf is the provenance state of one answered package: "" with
// provenance off or no reader for its ecosystem; the facts reader's state
// when it set one (npm); else the row's extra request (PyPI), made only
// when the install wait still holds provenanceMinLeft.
func (c *Client) provenanceOf(ctx context.Context, s secfeed.InstallSpec, reg regResult) policy.InstallProvenance {
	if !c.provenanceEnabled() {
		return policy.InstallProvenanceNotChecked
	}
	if reg.provSet {
		return reg.prov
	}
	row, ok := registryTable[s.Eco]
	if !ok || row.provenance == nil {
		return policy.InstallProvenanceNotChecked
	}
	if dl, ok := ctx.Deadline(); ok && dl.Sub(c.now()) < provenanceMinLeft {
		return policy.InstallProvenanceUnknown
	}
	if ctx.Err() != nil {
		return policy.InstallProvenanceUnknown
	}
	return row.provenance(ctx, c, secfeed.Normalize(s.Eco, s.Name), s.Version)
}
