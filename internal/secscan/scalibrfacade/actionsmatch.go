//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// actionsmatch.go matches the ecosystems SCALIBR's own matcher cannot: at
// v0.5.3 SCALIBR maps the PURL type github to OSV's "GitHub Actions"
// ecosystem, but its semantic package has no comparator for it, and
// osvlocal's rangeContainsVersion calls semantic.MustParse, which PANICS on
// an ecosystem it does not know. So a package of such an ecosystem is never
// handed to osvlocal; Match routes it here, one ecosystem at a time, like
// every other.
//
// The one deviation from "Observer writes no version-ordering code": this
// file evaluates an OSV record's range EVENTS itself (the OSV schema's
// algorithm: an exact `versions` entry first, then each ECOSYSTEM or SEMVER
// range's events sorted, introduced / fixed / last_affected / limit), the
// same walk osvlocal does. Every comparison of two versions is still
// SCALIBR's own comparator (semantic.ParseSemverVersion(...).CompareStr);
// Observer compares no version itself. GIT ranges are skipped (a commit
// range needs the repository). A record that does not decode, or whose
// evaluation fails, is skipped and can never panic the scan child.

// ownMatcher is one ecosystem Match routes away from osvlocal.
type ownMatcher struct {
	// name is the matcher's name (MatchResult.Matcher).
	name string
	// compare orders two versions of the ecosystem; it must be SCALIBR's.
	compare func(a, b string) int
}

// ownMatchers are the ecosystems the facade matches itself, by the
// ecosystem's OSV name. GitHub Actions tags are semver-like (`v45.0.0`,
// moving `v4`), so SCALIBR's semver comparator orders them; its parser drops
// a lowercase leading v, and trimV drops either case first.
var ownMatchers = map[string]ownMatcher{
	"GitHub Actions": {name: "observer/osvranges", compare: semverCompare},
}

// semverCompare is SCALIBR's semver comparator over two tags.
func semverCompare(a, b string) int {
	c, _ := semantic.ParseSemverVersion(trimV(a)).CompareStr(trimV(b))
	return c
}

// trimV drops one leading v or V (tags are written `v4.1.0`, OSV ranges
// `4.1.0`).
func trimV(s string) string {
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		return s[1:]
	}
	return s
}

// The bounds of one own-matched database: the zip itself (GitHub Actions
// is about 100 KB) and one record.
const (
	maxOwnDBBytes     = 64 << 20
	maxOwnRecordBytes = 1 << 20
	// maxOwnVersion bounds a version string handed to the comparator.
	maxOwnVersion = 128
)

// osvRecord is the part of an OSV record the range walk reads.
type osvRecord struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Withdrawn        string          `json:"withdrawn"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
	Affected         []osvAffected   `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// version is the event's one version ("" for an empty event).
func (e osvEvent) version() string {
	for _, v := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
		if v != "" {
			return v
		}
	}
	return ""
}

// severity is the record's database_specific severity label, "" when it
// carries none (or the block is not an object).
func (r osvRecord) severity() string {
	var ds struct {
		Severity string `json:"severity"`
	}
	if len(r.DatabaseSpecific) == 0 || json.Unmarshal(r.DatabaseSpecific, &ds) != nil {
		return ""
	}
	return ds.Severity
}

// ownTarget is one package (or the canary, index -1) to match.
type ownTarget struct {
	name, version string
	index         int
}

// matchOwn matches one own-matched ecosystem's packages against its local
// export, <DBDir>/osv-scalibr/<Ecosystem>/all.zip (the layout osvlocal
// reads). A missing export answers ErrNoDatabase.
func matchOwn(ctx context.Context, m ownMatcher, inv *Inventory, req MatchRequest, opts MatchOptions) (MatchResult, error) {
	res := MatchResult{Matcher: m.name}
	if opts.Online {
		return res, fmt.Errorf("scalibrfacade.Match: no online matcher for %s", req.Ecosystem)
	}
	if opts.DBDir == "" {
		return res, errors.New("scalibrfacade.Match: local matching needs a database directory")
	}
	var targets []ownTarget
	for _, i := range req.Indices {
		if i < 0 || i >= len(inv.Packages) {
			return res, fmt.Errorf("scalibrfacade.Match: index %d out of range", i)
		}
		p := inv.Packages[i]
		if p.Ecosystem != req.Ecosystem || !plainVersion(p.Version) || p.Name == "" {
			continue
		}
		targets = append(targets, ownTarget{name: strings.ToLower(p.Name), version: p.Version, index: i})
	}
	if req.Canary != nil {
		targets = append(targets, ownTarget{name: strings.ToLower(req.Canary.Name), version: req.Canary.Version, index: -1})
	}
	if len(targets) == 0 {
		return res, nil
	}
	dbPath := filepath.Join(opts.DBDir, "osv-scalibr", req.Ecosystem, "all.zip")
	fi, err := os.Stat(dbPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return res, ErrNoDatabase
	case err != nil:
		return res, fmt.Errorf("scalibrfacade.Match: %w", err)
	case !fi.Mode().IsRegular() || fi.Size() > maxOwnDBBytes:
		return res, fmt.Errorf("scalibrfacade.Match: the %s database is not a regular file under %d bytes", req.Ecosystem, maxOwnDBBytes)
	}
	zr, err := zip.OpenReader(dbPath)
	if err != nil {
		return res, fmt.Errorf("scalibrfacade.Match: the %s database is not a zip: %w", req.Ecosystem, err)
	}
	defer func() { _ = zr.Close() }()
	names := map[string]bool{}
	for _, t := range targets {
		names[t.name] = true
	}
	hit := map[int]map[string]bool{}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("scalibrfacade.Match: %w", err)
		}
		rec, ok := readOwnRecord(f)
		if !ok || rec.Withdrawn != "" || !mentions(rec, req.Ecosystem, names) {
			continue
		}
		for _, t := range targets {
			if !recordAffects(m, rec, req.Ecosystem, t) {
				continue
			}
			if t.index < 0 {
				res.CanaryHit = true
				continue
			}
			if hit[t.index] == nil {
				hit[t.index] = map[string]bool{}
			}
			if hit[t.index][rec.ID] {
				continue
			}
			hit[t.index][rec.ID] = true
			res.Vulns = append(res.Vulns, Vuln{ID: rec.ID, Aliases: append([]string(nil), rec.Aliases...), Severity: rec.severity(), Index: t.index})
		}
	}
	sort.Slice(res.Vulns, func(a, b int) bool {
		if res.Vulns[a].Index != res.Vulns[b].Index {
			return res.Vulns[a].Index < res.Vulns[b].Index
		}
		return res.Vulns[a].ID < res.Vulns[b].ID
	})
	return res, nil
}

// plainVersion reports a version the comparator may be handed: non-empty,
// bounded, printable ASCII with no space.
func plainVersion(v string) bool {
	if v == "" || len(v) > maxOwnVersion {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

// readOwnRecord decodes one export entry; ok is false for anything that is
// not a bounded, well-formed record with an id.
func readOwnRecord(f *zip.File) (osvRecord, bool) {
	if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > maxOwnRecordBytes {
		return osvRecord{}, false
	}
	rc, err := f.Open()
	if err != nil {
		return osvRecord{}, false
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxOwnRecordBytes+1))
	if err != nil || len(b) > maxOwnRecordBytes {
		return osvRecord{}, false
	}
	var rec osvRecord
	if json.Unmarshal(b, &rec) != nil || rec.ID == "" {
		return osvRecord{}, false
	}
	return rec, true
}

// mentions reports whether the record names one of the packages in the
// ecosystem (the cheap filter before any comparison).
func mentions(rec osvRecord, eco string, names map[string]bool) bool {
	for _, a := range rec.Affected {
		if a.Package.Ecosystem == eco && names[strings.ToLower(a.Package.Name)] {
			return true
		}
	}
	return false
}

// recordAffects reports whether the record affects the target. A failure
// inside the evaluation (a comparator that panics on some input) answers
// false: one bad record never stops the scan child.
func recordAffects(m ownMatcher, rec osvRecord, eco string, t ownTarget) (affected bool) {
	defer func() {
		if recover() != nil {
			affected = false
		}
	}()
	for _, a := range rec.Affected {
		if a.Package.Ecosystem != eco || strings.ToLower(a.Package.Name) != t.name {
			continue
		}
		if exactVersion(a.Versions, t.version) {
			return true
		}
		for _, r := range a.Ranges {
			if (r.Type == "ECOSYSTEM" || r.Type == "SEMVER") && rangeAffects(m.compare, r.Events, t.version) {
				return true
			}
		}
	}
	return false
}

// exactVersion reports an exact `versions` entry, a leading v tolerated on
// either side (osvlocal's matchVersionOrTag rule).
func exactVersion(versions []string, v string) bool {
	tv := trimV(v)
	for _, x := range versions {
		if x == v || trimV(x) == tv {
			return true
		}
	}
	return false
}

// rangeAffects is the OSV schema's range evaluation over events sorted by
// version ("introduced": "0" first): at or past a limit is never affected;
// otherwise introduced (0 or at most the version) turns affected on, and a
// fixed at most the version, or a last_affected below it, turns it off. A
// range with an event that names no version, or a version the comparator
// may not be handed, affects nothing.
func rangeAffects(cmp func(a, b string) int, events []osvEvent, v string) bool {
	evs := make([]osvEvent, 0, len(events))
	for _, e := range events {
		if ev := e.version(); !plainVersion(ev) {
			return false
		}
		evs = append(evs, e)
	}
	if len(evs) == 0 {
		return false
	}
	for _, e := range evs {
		if e.Limit != "" && cmp(v, e.Limit) >= 0 {
			return false
		}
	}
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		switch {
		case a.Introduced == "0" && b.Introduced != "0":
			return true
		case b.Introduced == "0":
			return false
		}
		return cmp(a.version(), b.version()) < 0
	})
	affected := false
	for _, e := range evs {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || cmp(v, e.Introduced) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if cmp(v, e.Fixed) >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if cmp(v, e.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected
}
