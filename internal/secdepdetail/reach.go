package secdepdetail

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Caps on what one advisory's affected imports carry.
const (
	// MaxImportPaths caps the affected import paths read from one record.
	MaxImportPaths = 64
	maxImportPath  = 300
	// MaxFunctions caps the affected functions read from one record.
	MaxFunctions = 64
)

// functionPathChars is the charset an affected function path keeps
// (RUSTSEC: "crate::module::Type::function", identifiers joined by "::").
var functionPathChars = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$`)

// importPathChars is the charset an affected import path keeps (Go import
// paths: letters, digits and . _ - ~ + /).
var importPathChars = regexp.MustCompile(`^[A-Za-z0-9_.~+/-]{1,300}$`)

// AffectedImports is one OSV record's affected import paths and functions
// for a package: affected[].ecosystem_specific.imports[].path (Go records)
// and affected[].ecosystem_specific.affects.functions (RUSTSEC records) of
// the entries naming the package, for the reachability tier
// (internal/secreach). No prose is read.
type AffectedImports struct {
	ID      string
	Aliases []string
	// MatchesPackage reports whether any affected[] entry names the
	// package (only those entries feed ImportPaths).
	MatchesPackage bool
	// ImportPaths are the entries' import paths, deduplicated, at most
	// MaxImportPaths; empty when the record lists none.
	ImportPaths []string
	// Functions are the entries' affected function paths, deduplicated,
	// at most MaxFunctions; empty when the record lists none.
	Functions []string
}

// detailed reports a record that lists import paths or functions (the one
// an alias group keeps).
func (a AffectedImports) detailed() bool { return len(a.ImportPaths) > 0 || len(a.Functions) > 0 }

// ParseAffectedImports decodes the affected import paths of one OSV record
// for pkg (the entries whose ecosystem and normalised name are the
// package's, as ParseAdvisory matches them).
func ParseAffectedImports(raw []byte, pkg Package) (AffectedImports, error) {
	if len(raw) > MaxRecordBytes {
		return AffectedImports{}, ErrRecordTooLarge
	}
	var rec osvRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return AffectedImports{}, fmt.Errorf("secdepdetail.ParseAffectedImports: %w", err)
	}
	if !validID(rec.ID) {
		return AffectedImports{}, errors.New("secdepdetail.ParseAffectedImports: the record has no valid id")
	}
	out := AffectedImports{ID: rec.ID}
	for _, al := range rec.Aliases {
		if validID(al) && al != rec.ID && len(out.Aliases) < maxAliases {
			out.Aliases = append(out.Aliases, al)
		}
	}
	want := NormalizeName(pkg.Ecosystem, pkg.Name)
	seen := map[string]bool{}
	for _, aff := range rec.Affected {
		eco, _, _ := strings.Cut(aff.Package.Ecosystem, ":")
		if eco != pkg.Ecosystem || NormalizeName(pkg.Ecosystem, aff.Package.Name) != want {
			continue
		}
		out.MatchesPackage = true
		for _, p := range importPaths(aff.EcosystemSpecific) {
			if !seen[p] && len(out.ImportPaths) < MaxImportPaths {
				seen[p] = true
				out.ImportPaths = append(out.ImportPaths, p)
			}
		}
		for _, f := range affectedFunctions(aff.EcosystemSpecific) {
			if !seen["fn\x00"+f] && len(out.Functions) < MaxFunctions {
				seen["fn\x00"+f] = true
				out.Functions = append(out.Functions, f)
			}
		}
	}
	return out, nil
}

// affectedFunctions reads ecosystem_specific.affects.functions (RUSTSEC),
// keeping only plain "a::b" paths.
func affectedFunctions(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var es struct {
		Affects struct {
			Functions []string `json:"functions"`
		} `json:"affects"`
	}
	if json.Unmarshal(raw, &es) != nil {
		return nil
	}
	var out []string
	for _, f := range es.Affects.Functions {
		f = strings.TrimSpace(f)
		if len(f) <= maxImportPath && functionPathChars.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// importPaths reads ecosystem_specific.imports[].path, keeping only plain
// import-path characters.
func importPaths(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var es struct {
		Imports []struct {
			Path string `json:"path"`
		} `json:"imports"`
	}
	if json.Unmarshal(raw, &es) != nil {
		return nil
	}
	var out []string
	for _, imp := range es.Imports {
		p := strings.TrimSpace(imp.Path)
		if p != "" && len(p) <= maxImportPath && importPathChars.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

// LookupAffectedImports reads, for a dependency finding (in's Category,
// Evidence, RuleID, Message and LookupRecord; nothing else is used), the
// package and the affected imports of each advisory the local database
// holds for it that names the package, one per alias group (the group's
// record that lists import paths or functions, when it holds one), in Build's lookup
// order. ok is false when the finding is not a dependency finding or
// its evidence names no package; records is empty when the local database
// holds none (or is not installed).
func LookupAffectedImports(in Input) (pkg Package, records []AffectedImports, ok bool) {
	pkg, ok = ParsePackage(in.Category, in.Evidence)
	if !ok {
		return Package{}, nil, false
	}
	if in.LookupRecord == nil {
		return pkg, nil, true
	}
	// group maps every id of an alias group to the index of the record kept
	// for it. A group's record with import paths or functions replaces one
	// without (a GitHub advisory of a Go module or a crate lists none; the
	// Go database's or RustSec's record of the same issue lists the
	// packages or functions), so an id already covered is still read while
	// its group's record lists none.
	group := map[string]int{}
	for _, id := range lookupOrder(AdvisoryIDs(in.RuleID, in.Message)) {
		if i, ok := group[id]; ok && records[i].detailed() {
			continue
		}
		raw, err := in.LookupRecord(pkg.Ecosystem, id)
		if errors.Is(err, ErrDatabaseNotInstalled) {
			break
		}
		if err != nil {
			continue
		}
		a, err := ParseAffectedImports(raw, pkg)
		if err != nil || !a.MatchesPackage {
			continue
		}
		idx, found := -1, false
		for _, k := range append([]string{a.ID}, a.Aliases...) {
			if i, ok := group[k]; ok {
				idx, found = i, true
				break
			}
		}
		switch {
		case !found:
			idx = len(records)
			records = append(records, a)
		case !records[idx].detailed() && a.detailed():
			records[idx] = a
		}
		for _, k := range append([]string{a.ID}, a.Aliases...) {
			if _, ok := group[k]; !ok {
				group[k] = idx
			}
		}
	}
	return pkg, records, true
}
