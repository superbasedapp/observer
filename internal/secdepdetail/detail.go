package secdepdetail

import (
	"errors"
	"path"
	"sort"
	"strings"
)

// Errors the injected reads return, which Build maps onto a reason.
var (
	// ErrOutsideProject: ReadFile refused a path that resolves outside the
	// project root (a "..", an absolute path, a symlink escape).
	ErrOutsideProject = errors.New("secdepdetail: path outside the project")
	// ErrFileTooLarge: ReadFile refused a file over its cap.
	ErrFileTooLarge = errors.New("secdepdetail: file too large")
	// ErrDatabaseNotInstalled: LookupRecord has no local database for the
	// ecosystem.
	ErrDatabaseNotInstalled = errors.New("secdepdetail: local OSV database not installed")
	// ErrRecordNotFound: the local database holds no record of that id.
	ErrRecordNotFound = errors.New("secdepdetail: record not in the local database")
)

// Advisory sources (Detail.AdvisorySource).
const (
	SourceLocalDatabase        = "local_database"
	SourceNotInLocalDatabase   = "not_in_local_database"
	SourceDatabaseNotInstalled = "database_not_installed"
)

// Input is one dependency finding and the injected reads.
type Input struct {
	// Category, Evidence, RuleID and Message are the finding's own fields
	// (Evidence is its redacted evidence; nothing is read unless Category
	// is vulnerable_dependency).
	Category string
	Evidence string
	RuleID   string
	Message  string
	// RelPath is the lockfile, relative to the project root, slash form.
	RelPath string
	// ReadFile reads a project-relative file (ErrOutsideProject,
	// ErrFileTooLarge or any other error for an unreadable file). Nil reads
	// nothing (the location is unreadable).
	ReadFile func(rel string) ([]byte, error)
	// LookupRecord reads one OSV record from the local database
	// (ErrDatabaseNotInstalled, ErrRecordNotFound). Nil looks nothing up.
	LookupRecord func(ecosystem, id string) ([]byte, error)
	// CleanLine, when set, is applied to every shown lockfile line (the
	// caller's secret scrubber).
	CleanLine func(string) string
}

// Detail is the dependency block of one finding.
type Detail struct {
	Package
	Relationship
	Location         Location
	FixedVersions    []string
	SuggestedVersion string
	AdvisorySource   string
	Advisories       []Advisory
}

// Build composes the detail of a dependency finding: the package from the
// evidence, its lockfile location and relationship, the local advisories
// (deduplicated by alias group) and the fix. ok is false for a finding that
// is not a dependency finding or whose evidence names no package; then
// nothing was read.
func Build(in Input) (Detail, bool) {
	pkg, ok := ParsePackage(in.Category, in.Evidence)
	if !ok {
		return Detail{}, false
	}
	d := Detail{Package: pkg}
	d.Location, d.Relationship = locateIn(in, pkg)
	d.Advisories, d.AdvisorySource = lookupAdvisories(in, pkg)
	fix := SuggestFix(pkg.Ecosystem, pkg.Version, d.Advisories)
	d.FixedVersions, d.SuggestedVersion = fix.FixedVersions, fix.Suggested
	return d, true
}

// cleanRel is a project-relative slash path, or ok false for one that is
// absolute or climbs out ("..").
func cleanRel(rel string) (string, bool) {
	rel = strings.ReplaceAll(strings.TrimSpace(rel), `\`, "/")
	if rel == "" || strings.HasPrefix(rel, "/") || (len(rel) >= 2 && rel[1] == ':') {
		return "", false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." {
			return "", false
		}
	}
	c := path.Clean(rel)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

func locateIn(in Input, pkg Package) (Location, Relationship) {
	rel, ok := cleanRel(in.RelPath)
	if !ok {
		return Location{RelPath: in.RelPath, Reason: ReasonOutsideProject}, Relationship{}
	}
	if !Supported(rel) {
		return Location{RelPath: rel, Reason: ReasonUnsupportedFormat}, Relationship{}
	}
	if in.ReadFile == nil {
		return Location{RelPath: rel, Reason: ReasonUnreadable}, Relationship{}
	}
	data, err := in.ReadFile(rel)
	switch {
	case errors.Is(err, ErrOutsideProject):
		return Location{RelPath: rel, Reason: ReasonOutsideProject}, Relationship{}
	case errors.Is(err, ErrFileTooLarge):
		return Location{RelPath: rel, Reason: ReasonFileTooLarge}, Relationship{}
	case err != nil:
		return Location{RelPath: rel, Reason: ReasonUnreadable}, Relationship{}
	}
	return Locate(rel, data, pkg, in.CleanLine)
}

// lookupOrder puts the ids an ecosystem database is keyed by first (a
// GitHub advisory, then the ecosystem's own) and a CVE last: an OSV export
// names each record by its own id, and a CVE is rarely one there.
func lookupOrder(ids []string) []string {
	rank := func(id string) int {
		switch {
		case strings.HasPrefix(id, "GHSA-"):
			return 0
		case strings.HasPrefix(id, "CVE-"):
			return 2
		}
		return 1
	}
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// lookupAdvisories reads the finding's advisories from the local database,
// skipping an id an advisory already read names (its alias group), and
// says where they came from.
func lookupAdvisories(in Input, pkg Package) ([]Advisory, string) {
	ids := lookupOrder(AdvisoryIDs(in.RuleID, in.Message))
	if in.LookupRecord == nil || len(ids) == 0 {
		return nil, SourceNotInLocalDatabase
	}
	var out []Advisory
	covered := map[string]bool{}
	notInstalled := false
	for _, id := range ids {
		if covered[id] {
			continue
		}
		raw, err := in.LookupRecord(pkg.Ecosystem, id)
		if errors.Is(err, ErrDatabaseNotInstalled) {
			notInstalled = true
			break
		}
		if err != nil {
			continue
		}
		a, err := ParseAdvisory(raw, pkg)
		if err != nil {
			continue
		}
		set := a.aliasSet()
		dup := false
		for k := range set {
			if covered[k] {
				dup = true
			}
		}
		for k := range set {
			covered[k] = true
		}
		if !dup {
			out = append(out, a)
		}
	}
	switch {
	case len(out) > 0:
		return out, SourceLocalDatabase
	case notInstalled:
		return nil, SourceDatabaseNotInstalled
	}
	return nil, SourceNotInLocalDatabase
}
