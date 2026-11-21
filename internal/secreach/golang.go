package secreach

import (
	"strconv"
	"strings"
)

// The OSV Go ecosystem's two pseudo-modules.
const (
	goStdlib    = "stdlib"
	goToolchain = "toolchain"
)

// goRecordRule is one row of the Go per-record rule table: the first row
// whose When holds decides the record.
type goRecordRule struct {
	Name   string
	When   func(adv Advisory, rec Record) bool
	Decide recordMatcher
}

// goRecordRules is walked top-down (one test case per row in
// golang_test.go).
var goRecordRules = []goRecordRule{
	{
		// The go command itself: nothing a project imports.
		Name:   "toolchain",
		When:   func(adv Advisory, _ Record) bool { return adv.Package == goToolchain },
		Decide: func(Advisory, Record, ImportSet, []string) Tier { return UnknownTier(ReasonNotALibrary) },
	},
	{
		// The record lists the affected packages: exact import path match
		// (stdlib records list "net/http", module records
		// "golang.org/x/net/html"). A subpackage of a listed path is a
		// different package and does not match.
		Name:   "listed import paths",
		When:   func(_ Advisory, rec Record) bool { return len(rec.ImportPaths) > 0 },
		Decide: matchListedPaths,
	},
	{
		// A standard-library record that lists no package: any standard
		// library import counts.
		Name:   "whole standard library",
		When:   func(adv Advisory, _ Record) bool { return adv.Package == goStdlib },
		Decide: matchAnyStdlib,
	},
	{
		// A module record that lists no package: any package of the module
		// (the module path or under it, not a /vN major version or a nested
		// module the build graph names).
		Name:   "module path",
		When:   func(Advisory, Record) bool { return true },
		Decide: matchModule,
	},
}

// matchGoRecord decides one Go record through goRecordRules.
func matchGoRecord(adv Advisory, rec Record, set ImportSet, paths []string) Tier {
	for _, rule := range goRecordRules {
		if rule.When(adv, rec) {
			return rule.Decide(adv, rec, set, paths)
		}
	}
	return UnknownTier(ReasonNoMapping)
}

func matchListedPaths(_ Advisory, rec Record, set ImportSet, _ []string) Tier {
	found, nonTest, match := false, false, ""
	for _, p := range rec.ImportPaths {
		u, ok := set.Uses[p]
		if !ok {
			continue
		}
		if u.NonTest && !nonTest {
			found, nonTest, match = true, true, p
		} else if !found {
			found, match = true, p
		}
	}
	return decide(set, found, nonTest, match)
}

func matchAnyStdlib(_ Advisory, _ Record, set ImportSet, paths []string) Tier {
	return scan(set, paths, isStdlibPath)
}

func matchModule(adv Advisory, _ Record, set ImportSet, paths []string) Tier {
	mod := adv.Package
	return scan(set, paths, func(p string) bool { return inModule(p, mod, set.Modules) })
}

// scan finds the first path (sorted order) that pred holds for, preferring
// one a non-test file imports.
func scan(set ImportSet, paths []string, pred func(string) bool) Tier {
	found, match := false, ""
	for _, p := range paths {
		if !pred(p) {
			continue
		}
		if set.Uses[p].NonTest {
			return decide(set, true, true, p)
		}
		if !found {
			found, match = true, p
		}
	}
	return decide(set, found, false, match)
}

// isStdlibPath reports a standard-library import path: its first element
// holds no dot ("net/http", "crypto/tls"); cgo's "C" is not a package.
func isStdlibPath(p string) bool {
	if p == "" || p == "C" {
		return false
	}
	first, _, _ := strings.Cut(p, "/")
	return !strings.Contains(first, ".")
}

// inModule reports whether import path p is a package of module mod: p is
// mod, or under mod where the next element is not a major-version suffix
// (mod/v2 is another module) and no longer module of the build graph owns
// p (a nested module such as .../service/s3 under .../aws-sdk-go-v2).
func inModule(p, mod string, modules []string) bool {
	if mod == "" {
		return false
	}
	if p == mod {
		return true
	}
	rest, ok := strings.CutPrefix(p, mod+"/")
	if !ok {
		return false
	}
	next, _, _ := strings.Cut(rest, "/")
	if isMajorSuffix(next) {
		return false
	}
	owner := owningModule(p, modules)
	return len(owner) <= len(mod)
}

// owningModule is the longest module of modules that p is or is under, ""
// when none.
func owningModule(p string, modules []string) string {
	best := ""
	for _, m := range modules {
		if len(m) > len(best) && (p == m || strings.HasPrefix(p, m+"/")) {
			best = m
		}
	}
	return best
}

// isMajorSuffix reports a Go major-version path element "v2", "v3", ...
// (no leading zero; v0 and v1 never appear as a suffix).
func isMajorSuffix(seg string) bool {
	if len(seg) < 2 || seg[0] != 'v' || seg[1] == '0' {
		return false
	}
	n, err := strconv.Atoi(seg[1:])
	return err == nil && n >= 2 && strconv.Itoa(n) == seg[1:]
}
