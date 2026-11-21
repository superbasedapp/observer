package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// hosted_copy_words_test.go pins the "Getting started v2" vocabulary on the
// surfaces a person meets while signing in and connecting a machine
// (onboarding v2, lane 7). The five user-facing words are Account, Personal
// dashboard, Team, Machine and Connect. The words this test retires there:
//
//   - "Cloud Intelligence" (the feature is "AI summaries"; the legacy feature
//     id cloud_intelligence has no space and is never matched);
//   - "organization" / "org" as a product noun (say "team" or "personal
//     dashboard");
//   - "workspace";
//   - "enrol" / "enroll" in user-facing text (say "connect");
//   - "node", "device" or "agent" for a machine (say "machine").
//
// It is a text check, deliberately cheap: it never builds a binary or a
// bundle. It reads the string literals of every file in scope (plus JSX text
// in .tsx files), keeps the ones that read like prose (a space and a letter),
// and matches each retired-word rule against them. A match is an error
// unless an allow-list row covers it, or the file is still listed in
// hostedCopyPending (its rewrite belongs to another onboarding lane and is
// reported, not failed, until that lane lands).
//
// The three tables are meant to be amended by hand:
//   - hostedCopySurfaces: the files in scope (a path or a "dir/**/*.ext"
//     pattern). Add a surface when a new account / connect screen appears.
//   - hostedCopyPending: files whose hits are only logged. Delete a row when
//     the owning lane's rewrite is merged; the test then enforces that file.
//   - hostedCopyAllow: a permanent exception (file + rule + a substring of the
//     literal), each with its reason. Keep it short: a wrong word is fixed in
//     the copy, not listed here.

// copySurface is one entry of the scope: a repo-relative path or pattern.
type copySurface struct {
	// Pattern is a repo-relative path, a filepath.Glob pattern, or
	// "<dir>/**/<base glob>" for every matching file under dir.
	Pattern string
	// What names the surface, for the failure message.
	What string
}

// hostedCopySurfaces lists the user-facing hosted-mode and connect surfaces.
var hostedCopySurfaces = []copySurface{
	// The hosted portal at cloud.superbased.app (account, personal dashboard,
	// teams, billing, privacy).
	{Pattern: "webcloud/src/**/*.ts", What: "hosted portal"},
	{Pattern: "webcloud/src/**/*.tsx", What: "hosted portal"},
	// web2 strings shown only on a hosted personal dashboard or hosted team,
	// plus the get-started, connect and sign-in screens every team sees.
	{Pattern: "web2/src/components/OrgSwitcher.tsx", What: "web2 hosted switcher"},
	{Pattern: "web2/src/lib/orgSwitcherModel.ts", What: "web2 hosted switcher"},
	{Pattern: "web2/src/lib/orgKindNav.ts", What: "web2 hosted navigation"},
	{Pattern: "web2/src/components/QuotaBanner.tsx", What: "web2 hosted quota banner"},
	{Pattern: "web2/src/lib/quotaBannerModel.ts", What: "web2 hosted quota banner"},
	{Pattern: "web2/src/components/SupportBanner.tsx", What: "web2 hosted support banner"},
	{Pattern: "web2/src/lib/supportBannerModel.ts", What: "web2 hosted support banner"},
	{Pattern: "web2/src/components/SupportAccessSettings.tsx", What: "web2 hosted support access"},
	{Pattern: "web2/src/lib/supportAccessModel.ts", What: "web2 hosted support access"},
	{Pattern: "web2/src/components/OrgDeletionSettings.tsx", What: "web2 hosted deletion"},
	{Pattern: "web2/src/components/IntelConsentPrompt.tsx", What: "web2 hosted AI summaries consent"},
	{Pattern: "web2/src/components/OnboardingCard.tsx", What: "web2 get-started card"},
	{Pattern: "web2/src/lib/getStarted.ts", What: "web2 get-started card"},
	{Pattern: "web2/src/components/ConnectCommand.tsx", What: "web2 connect command"},
	{Pattern: "web2/src/components/SignInInvitations.tsx", What: "web2 sign-in invitations"},
	{Pattern: "web2/src/pages/Install.tsx", What: "web2 connect a machine page"},
	{Pattern: "web2/src/lib/pairingView.ts", What: "web2 connect a machine page"},
	// The local dashboard's account, get-started and connect screens.
	{Pattern: "web/src/components/GetStarted.tsx", What: "local dashboard get started"},
	{Pattern: "web/src/lib/getStarted.ts", What: "local dashboard get started"},
	{Pattern: "web/src/components/ConnectProgress.tsx", What: "local dashboard connect"},
	{Pattern: "web/src/lib/useConnectFlow.ts", What: "local dashboard connect"},
	{Pattern: "web/src/lib/connect.ts", What: "local dashboard connect"},
	{Pattern: "web/src/components/TopBar.tsx", What: "local dashboard top bar"},
	{Pattern: "web/src/components/FirstRunModal.tsx", What: "local dashboard first run"},
	{Pattern: "web/src/components/FirstRunHost.tsx", What: "local dashboard first run"},
	{Pattern: "web/src/pages/settings/AccountSection.tsx", What: "local dashboard account settings"},
	{Pattern: "web/src/pages/settings/CloudIntelligenceSection.tsx", What: "local dashboard AI summaries settings"},
	{Pattern: "web/src/pages/settings/EnrolmentSection.tsx", What: "local dashboard connection settings"},
	// CLI output of `observer connect`, `observer disconnect`, the welcome
	// text and `observer start` (including its sign-in prompt).
	{Pattern: "cmd/observer/connect*.go", What: "observer connect"},
	{Pattern: "cmd/observer/disconnect.go", What: "observer disconnect"},
	{Pattern: "cmd/observer/welcome.go", What: "observer welcome"},
	{Pattern: "cmd/observer/start.go", What: "observer start"},
	{Pattern: "cmd/observer/start_signin.go", What: "observer start sign-in prompt"},
}

// hostedCopyExclude lists paths under a surface pattern that are not shown to
// a customer, with the reason.
var hostedCopyExclude = map[string]string{
	"webcloud/src/staff/":         "the staff console is used by SuperBased staff only, where organization is the operator's own noun",
	"webcloud/src/devmock.ts":     "development-only mock data, never served",
	"webcloud/src/devmockOrgs.ts": "development-only mock data, never served",
}

// hostedCopyPending lists files whose hits are logged instead of failed,
// keyed by repo-relative path, valued by the lane that rewrites them. Every
// onboarding lane (1 to 9) is merged on onb/merge, so no file is pending: a
// row here is a deliberate, temporary exception with its owner named.
var hostedCopyPending = map[string]string{}

// copyRule is one retired-word rule.
type copyRule struct {
	// ID names the rule in allow-list rows and messages.
	ID string
	// Match finds the retired word in a prose literal (case-insensitive).
	Match *regexp.Regexp
	// Strip, when set, is removed from the literal before Match runs (RE2 has
	// no lookahead, so a legitimate neighbour such as "Node.js" is removed
	// first).
	Strip *regexp.Regexp
	// Say is the replacement word, for the failure message.
	Say string
}

// retiredWordRules is the ordered rule table; one literal can hit several.
var retiredWordRules = []copyRule{
	{ID: "cloud-intelligence", Match: regexp.MustCompile(`(?i)\bcloud intelligence\b`), Say: `"AI summaries"`},
	// "org" and "organization" as words, but not inside a path (/api/org/), a
	// host or file name (.org, observer-org) or an identifier (org_id).
	{ID: "org", Match: regexp.MustCompile(`(?i)(?:^|[^\w/.\-])(?:organi[sz]ations?|orgs?)(?:$|[^\w/\-])`), Say: `"team" or "personal dashboard"`},
	{ID: "workspace", Match: regexp.MustCompile(`(?i)\bworkspaces?\b`), Say: `"team" or "personal dashboard"`},
	{ID: "enrol", Match: regexp.MustCompile(`(?i)\b(?:un|re)?enrol(?:l|ls|led|ling|ment|ments|s)?\b`), Say: `"connect"`},
	{ID: "node", Match: regexp.MustCompile(`(?i)\bnodes?\b`), Strip: regexp.MustCompile(`(?i)\bnode\.?js\b`), Say: `"machine"`},
	{ID: "device", Match: regexp.MustCompile(`(?i)\bdevices?\b`), Say: `"machine"`},
	// "agent" also means the AI coding agent, which stays; only the phrasings
	// that name the machine-side program are retired.
	{ID: "agent", Match: regexp.MustCompile(`(?i)\b(?:observer|local|enrolled|connected|managed|org) agents?\b|\bagent (?:version|id|key|token)s?\b`), Say: `"machine"`},
}

// copyAllow is a permanent exception.
type copyAllow struct {
	// File is the repo-relative path.
	File string
	// Rule is a retiredWordRules ID.
	Rule string
	// Contains is a substring of the literal; empty covers every literal of
	// that file for that rule (use sparingly).
	Contains string
	// Reason says why the word stays.
	Reason string
}

// hostedCopyAllow lists the permanent exceptions.
var hostedCopyAllow = []copyAllow{
	// autoRegisterOwesLive's values are code-review notes naming the
	// operator's demo host "node 1" where a hook binding was (or was not)
	// live-tested. start.go only reads the map's keys; no value is ever
	// printed, logged or shown to a person.
	{File: "cmd/observer/start.go", Rule: "node", Contains: "on demo node 1; doc-grounded", Reason: "autoRegisterOwesLive value: a never-printed review note naming the demo host"},
	{File: "cmd/observer/start.go", Rule: "node", Contains: "droid exec 0.233.0 on node 1", Reason: "autoRegisterOwesLive value: a never-printed review note naming the demo host"},
}

// TestHostedCopyHasNoRetiredWords enforces the onboarding v2 vocabulary on
// the hosted and connect surfaces.
func TestHostedCopyHasNoRetiredWords(t *testing.T) {
	root := repoRoot(t)
	files := hostedCopyFiles(t, root)
	if len(files) == 0 {
		t.Fatal("no file matched hostedCopySurfaces; the scope table is stale")
	}
	used := make([]bool, len(hostedCopyAllow))
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, h := range retiredWordHits(rel, string(raw)) {
			if i := hostedCopyAllowed(rel, h.Rule, h.Text); i >= 0 {
				used[i] = true
				continue
			}
			msg := rel + ": retired word (" + h.Rule + ") in user-facing text " + quoteSnippet(h.Text) + "; say " + h.Say
			if lane, ok := hostedCopyPending[rel]; ok {
				t.Logf("pending, %s: %s", lane, msg)
				continue
			}
			t.Error(msg)
		}
	}
	for i, ok := range used {
		if !ok {
			a := hostedCopyAllow[i]
			t.Logf("allow-list row no longer matches anything (delete it): %s %s %q", a.File, a.Rule, a.Contains)
		}
	}
	for rel := range hostedCopyPending {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Logf("hostedCopyPending names %s, which does not exist (delete the row)", rel)
		}
	}
}

// TestRetiredWordRulesTable pins the rule table on known inputs, one case
// per row and per deliberate non-match.
func TestRetiredWordRulesTable(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"Turn on Cloud Intelligence for this account", []string{"cloud-intelligence"}},
		{"Your personal organization is ready.", []string{"org"}},
		{"Ask your org admin for a code", []string{"org"}},
		{"Team workspaces are by invitation", []string{"workspace"}},
		{"Enroll this machine", []string{"enrol"}},
		{"No devices enrolled.", []string{"enrol", "device"}},
		{"The node keeps its own copy", []string{"node"}},
		{"Revoke device?", []string{"device"}},
		{"Update the observer agent first", []string{"agent"}},
		{"Your AI agent tried to install a package", nil},
		{"Connect this machine to your team", nil},
		{"Needs Node.js 20 or later", nil},
		{"GET /api/org/members failed", nil},
		{"Run observer-org doctor", nil},
		{"Visit superbased.org today", nil},
	}
	for _, c := range cases {
		var got []string
		for _, r := range retiredWordRules {
			if ruleMatches(r, c.text) {
				got = append(got, r.ID)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%q: rules %v, want %v", c.text, got, c.want)
		}
	}
}

// copyHit is one retired word found in one literal.
type copyHit struct {
	Rule string
	Say  string
	Text string
}

// retiredWordHits returns every rule hit in the prose literals of src.
func retiredWordHits(rel, src string) []copyHit {
	var out []copyHit
	for _, text := range proseLiterals(rel, src) {
		for _, r := range retiredWordRules {
			if ruleMatches(r, text) {
				out = append(out, copyHit{Rule: r.ID, Say: r.Say, Text: text})
			}
		}
	}
	return out
}

// ruleMatches applies one rule (Strip first) to text.
func ruleMatches(r copyRule, text string) bool {
	if r.Strip != nil {
		text = r.Strip.ReplaceAllString(text, " ")
	}
	return r.Match.MatchString(text)
}

// hostedCopyAllowed returns the index of the allow-list row covering the hit,
// or -1.
func hostedCopyAllowed(rel, rule, text string) int {
	for i, a := range hostedCopyAllow {
		if a.File == rel && a.Rule == rule && (a.Contains == "" || strings.Contains(text, a.Contains)) {
			return i
		}
	}
	return -1
}

// hostedCopyFiles expands hostedCopySurfaces into a sorted, de-duplicated
// list of repo-relative paths, dropping test files and hostedCopyExclude.
func hostedCopyFiles(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, s := range hostedCopySurfaces {
		for _, rel := range expandCopyPattern(t, root, s.Pattern) {
			if isCopyTestFile(rel) || copyExcluded(rel) {
				continue
			}
			seen[rel] = true
		}
	}
	out := make([]string, 0, len(seen))
	for rel := range seen {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// expandCopyPattern resolves one surface pattern to repo-relative,
// slash-separated paths. A missing path is not an error: another lane may
// add or rename it.
func expandCopyPattern(t *testing.T, root, pattern string) []string {
	t.Helper()
	if dir, base, ok := strings.Cut(pattern, "/**/"); ok {
		var out []string
		walkRoot := filepath.Join(root, filepath.FromSlash(dir))
		if _, err := os.Stat(walkRoot); err != nil {
			return nil
		}
		err := filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "dist" {
					return filepath.SkipDir
				}
				return nil
			}
			if m, _ := filepath.Match(base, d.Name()); m {
				rel, rerr := filepath.Rel(root, p)
				if rerr != nil {
					return rerr
				}
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", pattern, err)
		}
		return out
	}
	matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		rel, err := filepath.Rel(root, m)
		if err != nil {
			t.Fatalf("rel %s: %v", m, err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// isCopyTestFile reports whether rel is a test or story file.
func isCopyTestFile(rel string) bool {
	return strings.HasSuffix(rel, "_test.go") || strings.Contains(rel, ".test.") || strings.Contains(rel, ".spec.")
}

// copyExcluded reports whether rel is covered by hostedCopyExclude (a key
// ending in "/" excludes a directory).
func copyExcluded(rel string) bool {
	for k := range hostedCopyExclude {
		if rel == k || (strings.HasSuffix(k, "/") && strings.HasPrefix(rel, k)) {
			return true
		}
	}
	return false
}

// jsxTextRE captures text between a JSX closing ">" and the next "<". It runs
// on comment-free source; a capture holding ";" or "=" is TypeScript (a
// generic such as useState<string | null>(null); ...), not text.
var jsxTextRE = regexp.MustCompile(`>([^<>{}]*[A-Za-z][^<>{}]*)<`)

// proseLetterRE requires at least one letter.
var proseLetterRE = regexp.MustCompile(`[A-Za-z]`)

// proseLiterals returns the string literals of src that read like prose (a
// space and a letter), plus JSX text for .tsx files. Comments are skipped.
func proseLiterals(rel, src string) []string {
	lits, stripped := scanLiterals(src)
	var out []string
	for _, l := range lits {
		if isProse(l) && !isStructTag(l) {
			out = append(out, l)
		}
	}
	if strings.HasSuffix(rel, ".tsx") {
		for _, m := range jsxTextRE.FindAllStringSubmatch(stripped, -1) {
			text := m[1]
			if strings.TrimSpace(text) == "" || strings.ContainsAny(text, ";=") {
				continue
			}
			out = append(out, text)
		}
	}
	return out
}

// isProse reports whether a literal reads like words rather than a key,
// path or identifier.
func isProse(s string) bool {
	return strings.ContainsAny(s, " \t\n") && proseLetterRE.MatchString(s)
}

// structTagRE matches a Go struct tag such as `json:"x" toml:"y"`.
var structTagRE = regexp.MustCompile(`^\w+:"`)

// isStructTag reports whether a raw literal is a Go struct tag.
func isStructTag(s string) bool { return structTagRE.MatchString(s) }

// scanLiterals walks Go or TypeScript source once and returns its string
// literals ("...", '...', `...`) and a copy of the source with comments
// blanked out (newlines kept). A quote right after a letter, digit, ")" or
// "]" is an apostrophe in JSX text ("don't"), not a string; '...' and "..."
// stop at a newline, so a misread quote damages one line at most.
func scanLiterals(src string) (lits []string, stripped string) {
	b := []byte(src)
	st := make([]byte, len(b))
	copy(st, b)
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			j := i
			for j < n && b[j] != '\n' {
				st[j] = ' '
				j++
			}
			i = j
		case c == '/' && i+1 < n && b[i+1] == '*':
			j := i + 2
			for j+1 < n && (b[j] != '*' || b[j+1] != '/') {
				j++
			}
			end := j + 2
			if end > n {
				end = n
			}
			for k := i; k < end; k++ {
				if st[k] != '\n' {
					st[k] = ' '
				}
			}
			i = end
		case (c == '"' || c == '\'' || c == '`') && (c == '`' || i == 0 || !isQuoteNeighbour(b[i-1])):
			var sb strings.Builder
			j := i + 1
			for j < n && b[j] != c {
				if b[j] == '\\' && j+1 < n {
					sb.WriteByte(b[j])
					sb.WriteByte(b[j+1])
					j += 2
					continue
				}
				if c != '`' && b[j] == '\n' {
					break
				}
				sb.WriteByte(b[j])
				j++
			}
			lits = append(lits, sb.String())
			i = j + 1
		default:
			i++
		}
	}
	return lits, string(st)
}

// isQuoteNeighbour reports whether a byte before a quote makes it an
// apostrophe or a closing context rather than an opening quote.
func isQuoteNeighbour(c byte) bool {
	return c == ')' || c == ']' || c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// quoteSnippet shortens a literal for a message.
func quoteSnippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		s = s[:100] + "..."
	}
	return `"` + s + `"`
}
