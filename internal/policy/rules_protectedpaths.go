package policy

import "strings"

// R-166 (D-761, security pillar plan section 5.2, Q19): protected test and
// CI paths are read-only for agents. It is a core Guard rule, off by
// default because ordinary test maintenance is common: the rows are inert
// until the developer names one or more path classes in
// [guard.boundary].protected_path_classes (Config.ProtectedPathClasses).
// It is the ImpossibleBench "read-only tests" mitigation and the blocking
// variant of the pillar's test-tampering observations (section 5.7).
//
// A path is judged by its place in the project: the patterns match the
// path relative to the event's project root, so a project that itself
// lives under a folder named test, tests or spec is not wholly protected
// (plans decision log P-004). A path outside the project, or an event with
// no project root, is judged separately and more narrowly: only the rows
// that name a file (a "**/<name>" pattern with no directory part, such as
// "**/*_test.go" or "**/.gitlab-ci.yml") match it, by its file name.
//
// A shell delete counts as a write here (removing a test is the commonest
// way to make a suite pass), unlike R-114. Matching is case-insensitive
// (pathPattern), so no pattern relies on case (a "*Test.java" row would
// also match "Latest.java").

// Protected path classes, the closed vocabulary of
// [guard.boundary].protected_path_classes.
const (
	// ProtectedClassTests is test sources, test data and test runner
	// configuration.
	ProtectedClassTests = "tests"
	// ProtectedClassCI is CI pipeline definitions.
	ProtectedClassCI = "ci"
	// ProtectedClassCoverage is coverage configuration and thresholds.
	ProtectedClassCoverage = "coverage"
)

// protectedPathClass is one class of the R-166 table.
type protectedPathClass struct {
	name string
	pats []pathPattern
}

// protectedPathTable is the R-166 path-class table, one row per class.
var protectedPathTable = []protectedPathClass{
	{ProtectedClassTests, []pathPattern{
		{"**/test/**", "test directory"},
		{"**/tests/**", "test directory"},
		{"**/__tests__/**", "test directory"},
		{"**/spec/**", "spec directory"},
		{"**/testdata/**", "test data"},
		{"**/*_test.go", "Go test"},
		{"**/*_test.py", "Python test"},
		{"**/test_*.py", "Python test"},
		{"**/conftest.py", "pytest fixture file"},
		{"**/*.test.js", "JavaScript test"},
		{"**/*.test.jsx", "JavaScript test"},
		{"**/*.test.ts", "TypeScript test"},
		{"**/*.test.tsx", "TypeScript test"},
		{"**/*.test.mjs", "JavaScript test"},
		{"**/*.test.cjs", "JavaScript test"},
		{"**/*.spec.js", "JavaScript spec"},
		{"**/*.spec.jsx", "JavaScript spec"},
		{"**/*.spec.ts", "TypeScript spec"},
		{"**/*.spec.tsx", "TypeScript spec"},
		{"**/*_spec.rb", "Ruby spec"},
		{"**/pytest.ini", "pytest config"},
		{"**/jest.config.*", "Jest config"},
		{"**/vitest.config.*", "Vitest config"},
		{"**/.mocharc*", "Mocha config"},
		{"**/karma.conf.*", "Karma config"},
		{"**/phpunit.xml", "PHPUnit config"},
		{"**/phpunit.xml.dist", "PHPUnit config"},
	}},
	{ProtectedClassCI, []pathPattern{
		{"**/.github/workflows/**", "GitHub Actions workflow"},
		{"**/.github/actions/**", "GitHub Actions action"},
		{"**/.gitlab-ci.yml", "GitLab CI pipeline"},
		{"**/.gitlab-ci/**", "GitLab CI include"},
		{"**/.circleci/**", "CircleCI config"},
		{"**/azure-pipelines.yml", "Azure Pipelines config"},
		{"**/azure-pipelines.yaml", "Azure Pipelines config"},
		{"**/.azure-pipelines/**", "Azure Pipelines config"},
		{"**/Jenkinsfile", "Jenkins pipeline"},
		{"**/.buildkite/**", "Buildkite pipeline"},
		{"**/bitbucket-pipelines.yml", "Bitbucket Pipelines config"},
		{"**/.travis.yml", "Travis CI config"},
		{"**/.drone.yml", "Drone CI config"},
		{"**/.woodpecker.yml", "Woodpecker CI config"},
		{"**/.woodpecker/**", "Woodpecker CI config"},
	}},
	{ProtectedClassCoverage, []pathPattern{
		{"**/.coveragerc", "coverage.py config"},
		{"**/codecov.yml", "Codecov config"},
		{"**/.codecov.yml", "Codecov config"},
		{"**/codecov.yaml", "Codecov config"},
		{"**/.nycrc", "nyc coverage config"},
		{"**/.nycrc.json", "nyc coverage config"},
		{"**/.nycrc.yml", "nyc coverage config"},
		{"**/.c8rc", "c8 coverage config"},
		{"**/.c8rc.json", "c8 coverage config"},
		{"**/.simplecov", "SimpleCov config"},
		{"**/coverage.config.*", "coverage config"},
	}},
}

// ProtectedPathClasses returns the closed class vocabulary, in table order.
func ProtectedPathClasses() []string {
	out := make([]string, len(protectedPathTable))
	for i, c := range protectedPathTable {
		out[i] = c.name
	}
	return out
}

// protectedPatterns returns the patterns of the classes named in classes
// (unknown names are ignored; config validation refuses them earlier).
func protectedPatterns(classes []string) []pathPattern {
	if len(classes) == 0 {
		return nil
	}
	on := setOf(classes...)
	var out []pathPattern
	for _, c := range protectedPathTable {
		if on[c.name] {
			out = append(out, c.pats...)
		}
	}
	return out
}

// matchProtectedPathWrite is the R-166 file row: a write, edit or delete
// of a path in a configured class.
func matchProtectedPathWrite(ctx *MatchContext) (bool, string) {
	pats := protectedPatterns(ctx.Cfg.ProtectedPathClasses)
	if len(pats) == 0 || !isWriteEvent(ctx.Event) {
		return false, ""
	}
	desc, ok := protectedPathMatch(ctx.Path, ctx.Event.ProjectRoot, pats)
	if !ok {
		return false, ""
	}
	return true, desc + " (" + ctx.Event.Target + ")"
}

// protectedPathMatch judges one resolved path against the R-166 patterns:
// inside the project by its path from the project root, outside it (or
// with no project root) by its file name against the file-name rows only.
func protectedPathMatch(p, projectRoot string, pats []pathPattern) (string, bool) {
	if p == "" {
		return "", false
	}
	np, root := normPath(p), normPath(projectRoot)
	if root != "" && comparableFlavors(np, root) && isUnder(np, root) && len(np) > len(root) {
		rel := strings.TrimPrefix(np[len(root):], "/")
		for _, pat := range pats {
			if matchGlob(pat.glob, rel, true) {
				return pat.desc, true
			}
		}
		return "", false
	}
	base := np[strings.LastIndex(np, "/")+1:]
	for _, pat := range pats {
		if name, ok := strings.CutPrefix(pat.glob, "**/"); ok && !strings.Contains(name, "/") && matchGlob(name, base, true) {
			return pat.desc + ", outside the project", true
		}
	}
	return "", false
}

// matchProtectedPathShell is the R-166 shell row: a command that writes,
// moves or deletes a path in a configured class.
func matchProtectedPathShell(ctx *MatchContext, cmd *Command) (bool, string) {
	pats := protectedPatterns(ctx.Cfg.ProtectedPathClasses)
	if len(pats) == 0 {
		return false, ""
	}
	return shPathMatchBy(func(ctx *MatchContext, p string) (string, bool) {
		return protectedPathMatch(p, ctx.Event.ProjectRoot, pats)
	}, true)(ctx, cmd)
}

// protectedPathRules returns the R-166 rows (appended to the boundary
// table).
func protectedPathRules() []Rule {
	const advice = "These files are protected on this machine: the developer made tests and CI read-only for agents. Change the code under test instead, or ask the developer to make the change."
	return []Rule{
		{
			ID: "R-166", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindFileAccess, KindConfigChange}, Match: matchProtectedPathWrite,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent write to a protected test, CI or coverage path (opt-in path classes)",
			Advice: advice,
		},
		{
			ID: "R-166", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec}, MatchCmd: matchProtectedPathShell,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command writing a protected test, CI or coverage path (opt-in path classes)",
			Advice: advice,
		},
	}
}
