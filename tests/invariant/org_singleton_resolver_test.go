package invariant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The org singleton (the `org` row with id = 1) is read in exactly ONE place:
// the single-org resolver orgdb.LookupOrg. Every other org server and
// observer-org CLI path passes the org it acts for (managed-SaaS plan 07,
// M1.2; plan 06 17.3), so a pooled deployment, which carries an explicit org
// on every path and may hold no singleton at all, never depends on it.
//
// The guard parses every non-test Go file under the scan roots (build tags
// ignored, so every edition is covered), folds each SQL string literal
// (including a "+" concatenation of literals) and walks it through
// orgSingletonRules. A match outside the allow-listed resolver fails.

// orgSingletonScanRoots are the trees M1.2 sweeps, relative to the repo root.
var orgSingletonScanRoots = []string{
	filepath.Join("internal", "orgserver"),
	filepath.Join("cmd", "observer-org"),
}

// orgSingletonResolver is the one function allowed to read the singleton:
// the repo-relative file (forward slashes) and the function name.
var orgSingletonResolver = struct{ file, fn string }{"internal/orgserver/db/db.go", "LookupOrg"}

// orgSingletonForeignReads are singleton reads of a database that is NOT this
// server's store, so they are not a way for a server to learn its own org.
// Each row must still match exactly one read (no stale exemptions).
var orgSingletonForeignReads = []struct{ file, fn, why string }{
	{
		"internal/orgserver/db/sqlitemigrate/catalog.go", "snapshotOrg",
		"reads the SOURCE SQLite snapshot being imported; a pre-R2 snapshot is single-org by definition, and its org may be NULL or lack columns LookupOrg reads",
	},
	{
		"internal/orgserver/tenantexportstore/importer.go", "targetFacts",
		"counts the org rows of the IMPORT TARGET (any org at all refuses the import, M5.9); it never learns or acts as an org",
	},
}

// orgTableRef finds a SQL statement that reads or writes the org table itself
// (SELECT ... FROM / JOIN org, UPDATE org SET, DELETE FROM org): `org\b`
// cannot match org_members and the like, because `_` is a word character,
// and the SQL shape keeps prose ("pushed from org nodes") out.
var orgTableRef = regexp.MustCompile(`\bselect\b.*\b(from|join)\s+org\b|\bupdate\s+org\s+set\b|\bdelete\s+from\s+org\b`)

// orgSingletonRules are the shapes that select the singleton instead of a
// named org, walked top down; the first match names the finding. Each rule
// sees a normalized statement (lower case, one space between tokens,
// identifier quotes removed) that already references the org table.
var orgSingletonRules = []struct {
	name  string
	match func(stmt string) bool
}{
	{"keyed by the singleton id (id = 1)", regexp.MustCompile(`\b(\w+\.)?id\s*=\s*1\b`).MatchString},
	{"first row of org (LIMIT 1)", regexp.MustCompile(`\blimit\s+1\b`).MatchString},
	{"unfiltered org access (no WHERE)", func(stmt string) bool { return !strings.Contains(stmt, " where ") }},
}

// orgSingletonFinding returns the rule a SQL string breaks, or "" when it is
// not a singleton read (it does not touch the org table, or it names the org
// explicitly).
func orgSingletonFinding(sql string) string {
	stmt := normalizeSQL(sql)
	if !orgTableRef.MatchString(stmt) {
		return ""
	}
	for _, r := range orgSingletonRules {
		if r.match(stmt) {
			return r.name
		}
	}
	return ""
}

// normalizeSQL lower-cases s, drops identifier quotes and collapses every
// run of whitespace to one space, padding the ends so " where " also matches
// at the edges.
func normalizeSQL(s string) string {
	s = strings.ToLower(strings.NewReplacer(`"`, "", "`", "").Replace(s))
	return " " + strings.Join(strings.Fields(s), " ") + " "
}

// TestOrgSingletonFindingRules is one case per rule plus the shapes that must
// stay legal (an explicit org, other tables keyed by id = 1, the singleton
// INSERT that creates the row).
func TestOrgSingletonFindingRules(t *testing.T) {
	cases := []struct {
		name, sql, want string
	}{
		{"select by singleton id", "SELECT org_id FROM org WHERE id = 1", orgSingletonRules[0].name},
		{"compact spelling", "SELECT org_id FROM org WHERE id=1", orgSingletonRules[0].name},
		{"multi-line and quoted", "SELECT org_id\n  FROM \"org\"\n WHERE id = 1", orgSingletonRules[0].name},
		{"alias qualified", "SELECT o.org_id FROM org o WHERE o.id = 1", orgSingletonRules[0].name},
		{"table qualified", "SELECT org.org_id FROM org WHERE org.id = 1", orgSingletonRules[0].name},
		{"update by singleton id", "UPDATE org SET org_name = ? WHERE id = 1", orgSingletonRules[0].name},
		{"join on the singleton", "SELECT s.id FROM sessions s JOIN org ON org.id = 1 WHERE s.id = ?", orgSingletonRules[0].name},
		{"subquery", "INSERT INTO t (org_id) VALUES ((SELECT org_id FROM org WHERE id = 1))", orgSingletonRules[0].name},
		{"limit 1", "SELECT org_id FROM org LIMIT 1", orgSingletonRules[1].name},
		{"unfiltered", "SELECT org_id FROM org", orgSingletonRules[2].name},
		{"unfiltered delete", "DELETE FROM org", orgSingletonRules[2].name},
		{"explicit org", "SELECT org_id, org_name, external_url FROM org WHERE org_id = ?", ""},
		{"explicit org update", "UPDATE org SET external_url = ? WHERE org_id = $1", ""},
		{"other table keyed by id 1", "SELECT public_key FROM routing_policy_keys WHERE id = 1", ""},
		{"org-prefixed table", "SELECT * FROM org_deployment_wizard WHERE id = 1", ""},
		{"org_members", "SELECT email FROM org_members WHERE user_id = ?", ""},
		{"singleton create", "INSERT INTO org (id, org_id, org_name, external_url, created_at) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING", ""},
		{"prose", "the org is a singleton", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := orgSingletonFinding(tc.sql); got != tc.want {
				t.Errorf("orgSingletonFinding(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}

// TestOrgSingletonReadOnlyInResolver pins M1.2: no non-test file under the
// scan roots reads the org singleton outside orgdb.LookupOrg, and the
// resolver itself is still there (so the guard cannot pass vacuously).
func TestOrgSingletonReadOnlyInResolver(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "internal/orgserver")
	root := repoRoot(t)
	resolverHits := 0
	foreignHits := make([]int, len(orgSingletonForeignReads))
	for _, rel := range orgSingletonScanRoots {
		err := filepath.WalkDir(filepath.Join(root, rel), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			relPath, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			relPath = filepath.ToSlash(relPath)
			for _, f := range orgSingletonFindingsIn(t, p) {
				if relPath == orgSingletonResolver.file && f.fn == orgSingletonResolver.fn {
					resolverHits++
					continue
				}
				if i := foreignReadIndex(relPath, f.fn); i >= 0 {
					foreignHits[i]++
					continue
				}
				t.Errorf("%s:%d (%s): %s: read the org a caller acts for, or go through orgdb.LookupOrg (the one single-org resolver)",
					relPath, f.line, f.fnOrPackage(), f.rule)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", rel, err)
		}
	}
	for i, n := range foreignHits {
		if n != 1 {
			e := orgSingletonForeignReads[i]
			t.Errorf("foreign-read exemption %s.%s matched %d reads, want exactly 1: remove or update the row", e.file, e.fn, n)
		}
	}
	if resolverHits != 1 {
		t.Fatalf("found %d singleton reads in %s.%s, want exactly 1 (the resolver moved or was renamed: update orgSingletonResolver)",
			resolverHits, orgSingletonResolver.file, orgSingletonResolver.fn)
	}
}

// orgSingletonSite is one singleton read: the enclosing function ("" at
// package level), its line and the rule it breaks.
type orgSingletonSite struct {
	fn   string
	line int
	rule string
}

func (s orgSingletonSite) fnOrPackage() string {
	if s.fn == "" {
		return "package level"
	}
	return s.fn
}

// orgSingletonFindingsIn parses one Go file and returns its singleton reads.
// A literal that is an operand of a "+" concatenation is judged as part of
// the folded whole, never on its own.
func orgSingletonFindingsIn(t *testing.T, path string) []orgSingletonSite {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []orgSingletonSite
	for _, decl := range file.Decls {
		fn := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		inConcat := map[ast.Node]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if inConcat[x] || x.Op != token.ADD {
					return true
				}
				s, ok := foldStringConcat(x, inConcat)
				if ok {
					if rule := orgSingletonFinding(s); rule != "" {
						out = append(out, orgSingletonSite{fn: fn, line: fset.Position(x.Pos()).Line, rule: rule})
					}
				}
			case *ast.BasicLit:
				if inConcat[x] || x.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(x.Value)
				if err != nil {
					return true
				}
				if rule := orgSingletonFinding(s); rule != "" {
					out = append(out, orgSingletonSite{fn: fn, line: fset.Position(x.Pos()).Line, rule: rule})
				}
			}
			return true
		})
	}
	return out
}

// foldStringConcat folds a "+" chain of string literals into one string and
// marks every node of the chain in seen. ok is false when any operand is not
// a string literal (the chain is then left to its literal operands).
func foldStringConcat(e ast.Expr, seen map[ast.Node]bool) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", false
		}
		seen[x] = true
		return s, true
	case *ast.ParenExpr:
		return foldStringConcat(x.X, seen)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		marks := map[ast.Node]bool{}
		l, lok := foldStringConcat(x.X, marks)
		r, rok := foldStringConcat(x.Y, marks)
		if !lok || !rok {
			return "", false
		}
		seen[x] = true
		for n := range marks {
			seen[n] = true
		}
		return l + r, true
	}
	return "", false
}

// foreignReadIndex is the orgSingletonForeignReads row for file.fn, or -1.
func foreignReadIndex(file, fn string) int {
	for i, e := range orgSingletonForeignReads {
		if e.file == file && e.fn == fn {
			return i
		}
	}
	return -1
}
