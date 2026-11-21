package invariant

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// plane_wording_test.go keeps the retired meanings of the two planes out of
// user-facing text (Plane A polish lane S2, review finding P-20/P-21, sweep
// docs/audits/plane-a-b-definition-sweep-2026-11-20.md). Since 2026-11-20
// "Plane A" means the AI apps and agents people build (user-facing name
// "AI Apps", shared/lib/productNames.json) and "Plane B" the AI coding agents
// (user-facing "coding agents"); "Plane A" / "Plane B" are engineering labels
// that never appear in user-facing text, and the older "hosted-app plane"
// framing is retired everywhere (docs/deployment-models.md "Retired framing").
//
// What counts as user-facing text here, one surface per row of
// planeWordingSurfaces:
//
//   - every string literal in a non-test Go file under cmd/ and internal/
//     (CLI help, errors, API messages, consent copy, log lines an operator
//     reads), comments excluded;
//   - the application source of web/, web2/, webcloud/ and shared/ (.ts and
//     .tsx, tests and generated files excluded) with comments stripped;
//   - the public text the website serves: website/llms.txt, the marketing
//     page sources (website/pages-src, HTML comments stripped) and the /docs
//     sources (website/docs-src, the changelog excluded: it is release
//     history, correct for its date);
//   - the values of shared/lib/productNames.json (its "_" note keys skipped).
//
// Reference docs under docs/ (root level only; plans, audits and handovers
// are dated records) are scanned for the retired-plane phrases only, because
// engineering docs may keep the "Plane A/B" labels.
//
// A hit outside planeWordingAllow fails. Each allow-list entry pins an exact
// count and carries its reason; a count that drops is also a failure, so an
// entry is tightened or deleted as soon as its text is fixed (for example
// when lane S1 rewords the admin assistant, delete its entries here).

// planeWordingRule is one phrase that must not appear.
type planeWordingRule struct {
	id string
	re *regexp.Regexp
	// docs: the rule also applies to the root-level reference docs.
	docs bool
	why  string
}

// planeWordingRules is the ordered rule table. A string is counted once per
// rule per match.
var planeWordingRules = []planeWordingRule{
	{
		id: "hosted-app-plane", re: regexp.MustCompile(`(?i)\bhosted[- ]apps?[- ]plane\b`), docs: true,
		why: `the retired name of Plane A; say "AI Apps"`,
	},
	{
		id: "org-hosted-app", re: regexp.MustCompile(`(?i)\borg[- ]hosted[- ]apps?\b`), docs: true,
		why: `the retired org-hosted-app model; say "AI Apps"`,
	},
	{
		id: "hosted-app-adjective", re: regexp.MustCompile(`(?i)\bhosted-apps?\b`), docs: false,
		why: `"hosted-app traces / traffic / alerts" names the plane by its retired meaning; say "AI Apps traces" (a "hosted app" with end users, two words, is fine)`,
	},
	{
		id: "hosted-apps-area", re: regexp.MustCompile(`\bHosted [Aa]pps\b`), docs: true,
		why: `the retired navigation area; it is "AI apps" (productNames.json planea_area)`,
	},
	{
		id: "plane-label", re: regexp.MustCompile(`\bPlane[- ][AB]\b`), docs: false,
		why: `"Plane A" / "Plane B" are engineering labels; user-facing text says "AI Apps" / "coding agents"`,
	},
	{
		id: "plane-b-mode", re: regexp.MustCompile(`(?i)\bplane[- ]b mode\b`), docs: false,
		why: `the setting is "enforcement mode (coding agents)" (finding F-25)`,
	},
}

// planeWordingAllowEntry pins how many times one rule may match in one file.
type planeWordingAllowEntry struct {
	count  int
	reason string
}

// planeWordingKey is "<repo-relative path>|<rule id>".
func planeWordingKey(path, rule string) string { return path + "|" + rule }

// Reasons shared by several entries. Every entry outside lane S2's files is
// also listed in docs/plans/plane-a-sdk-buildout/lanes/POLISH-S2.md; lane S5
// (POLISH-S5.md) closed S2-F1 to S2-F5 and removed their entries.
const (
	allowTables  = "the tenancy table catalog's engineering notes (migration lineage and build lane), not shown to users"
	allowHistory = "a dated demo record listed under 'Historical records' in the 2026-11-20 sweep audit; not edited"
)

// planeWordingAllow is the exhaustive allow-list. Keep it short: fix the
// text instead of adding an entry where the file is yours to change.
var planeWordingAllow = map[string]planeWordingAllowEntry{
	"internal/orgserver/tenancy/tables.go|plane-label": {9, allowTables},
	"internal/ownagent/otlpclaim.go|hosted-app-adjective": {
		1,
		"the OTLPClaimRules row name, an identifier pinned by otlpclaim_test.go, not prose",
	},
	"docs/plane-b-demo-client-walkthrough.md|hosted-apps-area": {1, allowHistory},

	// The Agent Access glossary lists the retired terms it replaces, on
	// purpose, so a search for the old words finds the new one.
	"web2/src/lib/agentAccessVocab.ts|plane-label":  {2, "a glossary 'replaces' list of retired terms, kept so search finds the new name"},
	"web2/src/lib/agentAccessVocab.ts|plane-b-mode": {1, "a glossary 'replaces' list of retired terms, kept so search finds the new name"},

	// Public website sources owned by other polish lanes.
	"website/docs-src/glossary/agent-observability.md|plane-label":          {1, "lane S4 owns the old-scope glossary entry; delete this entry when S4 merges"},
	"website/docs-src/reference/privacy-data-model.md|hosted-app-adjective": {1, "lane S4 owns privacy-data-model.md (its line 92); delete this entry when S4 merges"},
	"website/pages-src/security.html|hosted-app-adjective":                  {1, "lane F6 owns website/pages-src; the same sentence as privacy-data-model.md (POLISH-S2 finding S2-F6)"},
}

// planeWordingSurface collects the strings of one surface.
type planeWordingSurface struct {
	name string
	// docsOnly: only the rules with docs=true apply.
	docsOnly bool
	// requires: a path the surface lives under; when the tree has no such
	// path (the public tree leaves website/ out), the surface is not checked.
	requires string
	scan     func(t *testing.T, root string) map[string][]string // path -> texts
}

var planeWordingSurfaces = []planeWordingSurface{
	{name: "go string literals", scan: scanGoStrings},
	{name: "app sources", scan: scanAppSources},
	{name: "website text", requires: "website", scan: scanWebsiteText},
	{name: "product names", scan: scanProductNames},
	{name: "reference docs", docsOnly: true, scan: scanReferenceDocs},
}

func TestPlaneWordingInUserFacingText(t *testing.T) {
	root := filepath.Join("..", "..")
	counts := map[string]int{}
	samples := map[string]string{}
	for _, s := range planeWordingSurfaces {
		if s.requires != "" && !planeWordingPresent(root, s.requires) {
			continue
		}
		texts := s.scan(t, root)
		if len(texts) == 0 {
			t.Errorf("surface %q scanned nothing: the walk is broken", s.name)
		}
		for path, list := range texts {
			for _, txt := range list {
				for _, r := range planeWordingRules {
					if s.docsOnly && !r.docs {
						continue
					}
					for _, m := range r.re.FindAllStringIndex(txt, -1) {
						k := planeWordingKey(path, r.id)
						counts[k]++
						if _, ok := samples[k]; !ok {
							samples[k] = planeWordingSample(txt, m[0], m[1])
						}
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	why := map[string]string{}
	for _, r := range planeWordingRules {
		why[r.id] = r.why
	}
	for _, k := range keys {
		got := counts[k]
		allow, ok := planeWordingAllow[k]
		path, rule, _ := strings.Cut(k, "|")
		switch {
		case !ok:
			t.Errorf("%s: %d user-facing match(es) of %s (%s), e.g. %q", path, got, rule, why[rule], samples[k])
		case got > allow.count:
			t.Errorf("%s: %d match(es) of %s, allow-list pins %d (%s); fix the new text, e.g. %q", path, got, rule, allow.count, why[rule], samples[k])
		case got < allow.count:
			t.Errorf("%s: %d match(es) of %s, allow-list pins %d: tighten the entry to %d (or delete it at 0)", path, got, rule, allow.count, got)
		}
	}
	for k, allow := range planeWordingAllow {
		if allow.reason == "" {
			t.Errorf("allow-list entry %s has no reason", k)
		}
		if _, ok := counts[k]; !ok {
			if path, _, _ := strings.Cut(k, "|"); !planeWordingPresent(root, path) {
				// A private-only file the public tree leaves out.
				continue
			}
			t.Errorf("allow-list entry %s matches nothing now: delete it", k)
		}
	}
}

// planeWordingPresent reports whether rel exists under root. The public tree
// (scripts/release.sh public) leaves the private-only paths out (website/,
// web2/, most of docs/, the org server), so a surface or an allow-list entry
// over one of them is not checked there; in the private tree every one of
// them exists and is checked.
func planeWordingPresent(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// TestPlaneWordingRulesBite proves each rule catches the phrase it names and
// leaves the current wording alone, so an edit to a pattern cannot silently
// disarm the walk above.
func TestPlaneWordingRulesBite(t *testing.T) {
	bad := map[string]string{
		"hosted-app-plane":     "spans are never sent to the hosted-app plane",
		"org-hosted-app":       "the org-hosted-app model",
		"hosted-app-adjective": "collect full hosted-app traces from this machine",
		"hosted-apps-area":     "Hosted Apps > Alerts",
		"plane-label":          "this image has no Plane A gateway",
		"plane-b-mode":         "Settings > Plane B mode",
	}
	good := []string{
		"collect full AI Apps traces from this machine",
		"a hosted app with end users",
		"the org-hosted OpenShell gateway",
		"/api/org/plane-b/mode",
		"planeb.admission",
		"org.planea.gateway",
		"Your AI apps",
	}
	for _, r := range planeWordingRules {
		sample, ok := bad[r.id]
		if !ok {
			t.Errorf("rule %s has no bad sample in this test", r.id)
			continue
		}
		if !r.re.MatchString(sample) {
			t.Errorf("rule %s does not match %q", r.id, sample)
		}
		for _, g := range good {
			if r.re.MatchString(g) {
				t.Errorf("rule %s matches the allowed wording %q", r.id, g)
			}
		}
	}
}

func planeWordingSample(txt string, lo, hi int) string {
	a, b := lo-40, hi+40
	if a < 0 {
		a = 0
	}
	if b > len(txt) {
		b = len(txt)
	}
	return strings.Join(strings.Fields(txt[a:b]), " ")
}

func planeWordingRel(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s: %v", path, err)
	}
	return filepath.ToSlash(rel)
}

// planeWordingSkipDir names the directories no surface walks.
func planeWordingSkipDir(name string) bool {
	switch name {
	case "testdata", "node_modules", "dist", "build", ".git", "vendor":
		return true
	}
	return false
}

// scanGoStrings returns every string literal of every non-test Go file under
// cmd/ and internal/.
func scanGoStrings(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if planeWordingSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel := planeWordingRel(t, root, p)
			ast.Inspect(f, func(n ast.Node) bool {
				bl, ok := n.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					return true
				}
				if s, err := strconv.Unquote(bl.Value); err == nil {
					out[rel] = append(out[rel], s)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

// scanAppSources returns the comment-stripped .ts/.tsx application source of
// the three dashboards and the shared package.
func scanAppSources(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, dir := range []string{"web/src", "web2/src", "webcloud/src", "shared"} {
		base := filepath.Join(root, filepath.FromSlash(dir))
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if planeWordingSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".ts") && !strings.HasSuffix(name, ".tsx") {
				return nil
			}
			if strings.HasSuffix(name, ".d.ts") || strings.Contains(name, ".test.") || strings.Contains(name, ".gen.") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[planeWordingRel(t, root, p)] = []string{stripTSComments(string(raw))}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

// stripTSComments removes // and /* */ comments from TypeScript source,
// leaving string and template literals (and JSX text) in place. It is a
// small scanner, not a parser: a regular-expression literal containing a
// quote may confuse it, which at worst keeps a comment in the scanned text.
func stripTSComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if c != '`' && src[j] == '\n' {
					break
				}
				j++
			}
			if j >= len(src) {
				j = len(src) - 1
			}
			b.WriteString(src[i : j+1])
			i = j
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var htmlCommentRE = regexp.MustCompile(`(?s)<!--.*?-->`)

// scanWebsiteText returns the public text the website serves.
func scanWebsiteText(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	read := func(p string) string {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(raw)
	}
	llms := filepath.Join(root, "website", "llms.txt")
	out[planeWordingRel(t, root, llms)] = []string{read(llms)}
	for _, dir := range []string{"website/pages-src", "website/docs-src"} {
		base := filepath.Join(root, filepath.FromSlash(dir))
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if planeWordingSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if name == "changelog.md" {
				return nil
			}
			if !strings.HasSuffix(name, ".html") && !strings.HasSuffix(name, ".md") {
				return nil
			}
			out[planeWordingRel(t, root, p)] = []string{htmlCommentRE.ReplaceAllString(read(p), "")}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

// scanProductNames returns the names (not the "_" notes) of the vocabulary.
func scanProductNames(t *testing.T, root string) map[string][]string {
	t.Helper()
	p := filepath.Join(root, "shared", "lib", "productNames.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", p, err)
	}
	var vals []string
	for k, v := range m {
		if !strings.HasPrefix(k, "_") {
			vals = append(vals, v)
		}
	}
	return map[string][]string{planeWordingRel(t, root, p): vals}
}

// scanReferenceDocs returns the root-level docs/*.md reference docs.
func scanReferenceDocs(t *testing.T, root string) map[string][]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	out := map[string][]string{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		out[planeWordingRel(t, root, p)] = []string{string(raw)}
	}
	return out
}
