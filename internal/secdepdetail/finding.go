package secdepdetail

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Package is the dependency a finding names: the OSV ecosystem (the
// database's directory name, e.g. "npm", "PyPI", "Go"), the package name
// and the installed version.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// String is the package as the findings list shows it: "name@version".
func (p Package) String() string { return p.Name + "@" + p.Version }

// MaxAdvisoryIDs caps the advisory ids one detail looks up.
const MaxAdvisoryIDs = 8

// maxID mirrors the finding rule-id cap (secfinding.MaxRuleID) and the
// OSV record id cap (osvdb.MaxIDLength).
const maxID = 128

// ParsePackage reads the package a dependency finding was built for from
// its redacted evidence, which depscan.Findings writes as
// "<ecosystem> <name>@<version>" (depscan.EcosystemOfFinding reads the same
// ecosystem; it may hold a space, "GitHub Actions"). The name and version split on the LAST '@', so a scoped npm
// name ("@scope/pkg@1.2.3") keeps its own '@'. Any other category, or
// evidence of another shape, is not a package (ok false): the evidence of a
// non-dependency finding is never parsed.
func ParsePackage(category, evidence string) (Package, bool) {
	if category != string(policy.FindingVulnerableDependency) {
		return Package{}, false
	}
	// The ecosystem is everything before the LAST space: a name and a
	// version never hold one, an ecosystem may ("GitHub Actions").
	sp := strings.LastIndex(evidence, " ")
	if sp <= 0 {
		return Package{}, false
	}
	eco, rest := evidence[:sp], evidence[sp+1:]
	if !validEcosystem(eco) {
		return Package{}, false
	}
	i := strings.LastIndex(rest, "@")
	if i <= 0 || i == len(rest)-1 {
		return Package{}, false
	}
	name, ver := rest[:i], rest[i+1:]
	if !plainToken(name) || !plainToken(ver) {
		return Package{}, false
	}
	return Package{Ecosystem: eco, Name: name, Version: ver}, true
}

// validEcosystem reports an ecosystem name safe to pass to the record
// lookup: letters, digits, '.', '-', '_' and ':' (OSV ecosystem names such
// as "crates.io"), and single interior spaces ("GitHub Actions"); never "."
// or "..".
func validEcosystem(eco string) bool {
	if eco == "" || len(eco) > 64 || eco == "." || eco == ".." || strings.HasPrefix(eco, " ") || strings.HasSuffix(eco, " ") || strings.Contains(eco, "  ") {
		return false
	}
	for i := 0; i < len(eco); i++ {
		c := eco[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':', c == ' ':
		default:
			return false
		}
	}
	return true
}

// plainToken reports a non-empty name or version with no space or
// control character (the evidence is already Clip'ed, which drops control
// characters; a space would mean another shape).
func plainToken(s string) bool {
	if s == "" || len(s) > 214 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// validID reports an advisory id safe to look up: the finding rule-id
// charset (letters, digits, '.', '_', '-', ':'; depscan.validID), at most
// maxID bytes, never "." or "..".
func validID(id string) bool {
	if id == "" || len(id) > maxID || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// AdvisoryIDs returns the advisory ids a dependency finding names: its rule
// id (the group's primary id) first, then the ids its templated message
// lists in parentheses ("Known vulnerability in a npm dependency (CVE-1,
// GHSA-2 and 3 more)."), each charset-checked, deduplicated, at most
// MaxAdvisoryIDs. The ids the message elided ("and N more") are not
// recoverable from the finding and are not invented.
func AdvisoryIDs(ruleID, message string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if !validID(id) || seen[id] || len(out) >= MaxAdvisoryIDs {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(ruleID)
	open, closing := strings.LastIndex(message, "("), strings.LastIndex(message, ")")
	if open >= 0 && closing > open {
		for _, part := range strings.Split(message[open+1:closing], ",") {
			part = strings.TrimSpace(part)
			if i := strings.Index(part, " and "); i >= 0 {
				part = part[:i]
			}
			add(part)
		}
	}
	return out
}
