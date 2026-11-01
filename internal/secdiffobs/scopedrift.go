package secdiffobs

import (
	"path"
	"regexp"
	"strings"
)

// scopedrift.go is S-770 (section 5.7): a deterministic table of path
// classes and prompt terms. A class fires for a changed file in it when the
// session's prompt is known and names none of the class's terms. The
// prompt text is read here and never returned: a drift carries the path,
// the path class and the absent term class only.

// DriftClass is one row of the scope drift table.
type DriftClass struct {
	// Class names both the path class and the term class.
	Class string
	// InClass reports a changed path in the class.
	InClass func(p string) bool
	// Terms are the prompt words that put the class in scope.
	Terms *regexp.Regexp
}

var (
	authPath  = regexp.MustCompile(`(^|/)(auth|authn|authz|login|logout|oauth2?|jwt|rbac|acl|permissions?|sessions?|sso)([/._-]|$)|authentication|authoriz`)
	iacPath   = regexp.MustCompile(`(\.tf|\.tfvars|\.bicep|\.hcl)$|(^|/)(terraform|k8s|kubernetes|helm|charts|ansible|pulumi|cloudformation|deploy|infra)/|(^|/)dockerfile|(^|/)docker-compose[^/]*\.ya?ml$|(^|/)compose\.ya?ml$`)
	lockfiles = map[string]bool{
		"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lockb": true, "bun.lock": true,
		"go.sum": true, "cargo.lock": true, "poetry.lock": true, "pipfile.lock": true, "uv.lock": true, "pdm.lock": true,
		"gemfile.lock": true, "composer.lock": true, "packages.lock.json": true, "mix.lock": true, "pubspec.lock": true, "podfile.lock": true,
	}
)

// DriftTable is THE scope drift table, walked top-down.
var DriftTable = []DriftClass{
	{
		Class: "auth", InClass: func(p string) bool { return authPath.MatchString(p) },
		Terms: regexp.MustCompile(`\b(auth\w*|log ?in|log ?out|sign ?(in|on|out)|signin|session\w*|password\w*|permission\w*|roles?|tokens?|jwt|oauth\w*|sso|saml|access control|rbac|acl|credential\w*|security)\b`),
	},
	{
		Class: "ci", InClass: IsCIPath,
		Terms: regexp.MustCompile(`\b(ci|cd|workflows?|pipelines?|github actions?|actions?|gitlab|jenkins|circleci|build\w*|release\w*|deploy\w*)\b`),
	},
	{
		Class: "iac", InClass: func(p string) bool { return iacPath.MatchString(p) },
		Terms: regexp.MustCompile(`\b(infra\w*|terraform|kubernetes|k8s|helm|docker\w*|containers?|deploy\w*|cloud|aws|azure|gcp|ansible|pulumi|bicep|compose)\b`),
	},
	{
		Class: "lockfile", InClass: func(p string) bool { return lockfiles[path.Base(p)] },
		Terms: regexp.MustCompile(`\b(dependenc\w*|packages?|upgrade\w*|update\w*|bump\w*|install\w*|lock\w*|versions?|npm|pnpm|yarn|pip|poetry|cargo|go ?mod|bundler?|composer|modules?|librar\w*)\b`),
	},
	{
		Class: "test", InClass: IsTestPath,
		Terms: regexp.MustCompile(`\b(tests?|testing|spec\w*|coverage|unit|e2e|integration|fixtures?|failing|ci|assert\w*|flaky)\b`),
	},
}

// Drift is one S-770 hit: never prompt text.
type Drift struct {
	Path      string
	PathClass string
	TermClass string
}

// ScopeDrift returns one drift per changed file in a class whose terms the
// prompt does not name. An empty prompt (none available to the node) never
// fires.
func ScopeDrift(files []FileDiff, prompt string) []Drift {
	text := strings.ToLower(strings.TrimSpace(prompt))
	if text == "" {
		return nil
	}
	named := map[string]bool{}
	for _, c := range DriftTable {
		named[c.Class] = c.Terms.MatchString(text)
	}
	var out []Drift
	for _, f := range files {
		p := strings.ToLower(strings.ReplaceAll(f.Path, "\\", "/"))
		for _, c := range DriftTable {
			if !named[c.Class] && c.InClass(p) {
				out = append(out, Drift{Path: f.Path, PathClass: c.Class, TermClass: c.Class})
				break
			}
		}
	}
	return out
}
