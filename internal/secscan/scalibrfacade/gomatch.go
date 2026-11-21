//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unicode"

	"github.com/google/osv-scalibr/semantic"
)

// gomatch.go repairs SECP-43, a false negative in SCALIBR v0.5.3's local
// matcher (found by spike RM-0). osvlocal rebuilds a package's name from its
// PURL, and the Go PURL lower-cases the namespace, so the name it compares to
// an advisory's module path (byte equality) no longer equals it when the
// module path has a capital letter: github.com/Azure/..., github.com/
// BurntSushi/toml, github.com/Microsoft/go-winio are never matched.
//
// The repair, for Go packages whose module path contains an upper-case
// letter only: match them here by their RAW module path against the Go
// export's records (case-sensitive equality with affected[].package.name,
// ecosystem "Go"), with the same range walk the GitHub Actions matcher uses
// (actionsmatch.go: rangeAffects, exactVersion, readOwnRecord) and SCALIBR's
// own Go comparator; Observer orders no version itself. The records are
// streamed one at a time out of the zip, bounded per record and per file, so
// nothing the size of the export is held in memory. The result is merged into
// osvlocal's, deduplicated by advisory id and package, so a future SCALIBR
// that fixes the bug cannot double-report. The online path (osvdev) builds
// the same name and keeps the gap.

// maxGoDBBytes bounds the Go export (about 13 MB at v0.5.3); a larger file
// is refused rather than streamed.
const maxGoDBBytes = 256 << 20

// goComparator is SCALIBR's own comparator for the Go ecosystem.
func goComparator(a, b string) int {
	va, err := semantic.Parse(a, "Go")
	if err != nil {
		return 0
	}
	c, _ := va.CompareStr(b)
	return c
}

// hasUpper reports whether s contains an upper-case letter.
func hasUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// mergeGoMixedCase adds, to osvlocal's answer res for a Go request, the
// matches of the packages (and canary) osvlocal cannot see. A missing export
// is osvlocal's ErrNoDatabase and never reaches here.
func mergeGoMixedCase(ctx context.Context, res MatchResult, inv *Inventory, req MatchRequest, opts MatchOptions) (MatchResult, error) {
	var targets []ownTarget
	for _, i := range req.Indices {
		if i < 0 || i >= len(inv.Packages) {
			return res, fmt.Errorf("scalibrfacade.Match: index %d out of range", i)
		}
		p := inv.Packages[i]
		if p.Ecosystem != req.Ecosystem || !hasUpper(p.Name) || !plainVersion(p.Version) {
			continue
		}
		targets = append(targets, ownTarget{name: p.Name, version: p.Version, index: i})
	}
	if c := req.Canary; c != nil && hasUpper(c.Name) && plainVersion(c.Version) {
		targets = append(targets, ownTarget{name: c.Name, version: c.Version, index: -1})
	}
	if len(targets) == 0 || opts.DBDir == "" {
		return res, nil
	}
	dbPath := filepath.Join(opts.DBDir, "osv-scalibr", req.Ecosystem, "all.zip")
	fi, err := os.Stat(dbPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return res, ErrNoDatabase
	case err != nil:
		return res, fmt.Errorf("scalibrfacade.Match: %w", err)
	case !fi.Mode().IsRegular() || fi.Size() > maxGoDBBytes:
		return res, fmt.Errorf("scalibrfacade.Match: the %s database is not a regular file under %d bytes", req.Ecosystem, maxGoDBBytes)
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
	// seen holds what osvlocal already reported, so nothing is added twice.
	type key struct {
		index int
		id    string
	}
	seen := map[key]bool{}
	for _, v := range res.Vulns {
		seen[key{v.Index, v.ID}] = true
	}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("scalibrfacade.Match: %w", err)
		}
		rec, ok := readOwnRecord(f)
		if !ok || rec.Withdrawn != "" || !mentionsExact(rec, req.Ecosystem, names) {
			continue
		}
		for _, t := range targets {
			if !recordAffectsExact(rec, req.Ecosystem, t) {
				continue
			}
			if t.index < 0 {
				res.CanaryHit = true
				continue
			}
			k := key{t.index, rec.ID}
			if seen[k] {
				continue
			}
			seen[k] = true
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

// mentionsExact is mentions with case-sensitive names (the cheap filter
// before any comparison).
func mentionsExact(rec osvRecord, eco string, names map[string]bool) bool {
	for _, a := range rec.Affected {
		if a.Package.Ecosystem == eco && names[a.Package.Name] {
			return true
		}
	}
	return false
}

// recordAffectsExact reports whether the record affects the target by raw
// module path. Like recordAffects, a failure inside the evaluation answers
// false: one bad record never stops the scan child.
func recordAffectsExact(rec osvRecord, eco string, t ownTarget) (affected bool) {
	defer func() {
		if recover() != nil {
			affected = false
		}
	}()
	for _, a := range rec.Affected {
		if a.Package.Ecosystem != eco || a.Package.Name != t.name {
			continue
		}
		if exactVersion(a.Versions, t.version) {
			return true
		}
		for _, r := range a.Ranges {
			if (r.Type == "ECOSYSTEM" || r.Type == "SEMVER") && rangeAffects(goComparator, r.Events, t.version) {
				return true
			}
		}
	}
	return false
}
