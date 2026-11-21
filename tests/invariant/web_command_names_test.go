package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// web_command_names_test.go pins the CLI command names the two dashboards
// tell a reader to type (org audit 2026-11-11, CG-23: web2 onboarding said
// "run `observer-org enroll`", but enroll is an `observer` command; the
// org binary has none).
//
// It is a text check, deliberately cheap: it never builds a binary. The
// known command words of each binary are the first word of every cobra
// `Use: "<name> ..."` literal (plus `Aliases`) under that binary's cmd/
// directory, and every `observer <verb>` / `observer-org <verb>` literal in
// web/src and web2/src must name a verb its binary registers. Only the verb
// is checked: a second word may be a subcommand or an argument, and telling
// them apart would need the real command tree.

// webCommandBinaries maps each binary name the dashboards mention to the
// cmd/ directory whose cobra tree defines it.
var webCommandBinaries = map[string]string{
	"observer":     filepath.Join("cmd", "observer"),
	"observer-org": filepath.Join("cmd", "observer-org"),
}

// webCommandAllow lists command literals the extractor finds that are not a
// wrong command name, keyed "<binary> <verb>", each with its reason. Keep it
// short: a genuinely wrong name is fixed in the copy, not listed here.
var webCommandAllow = map[string]string{
	"observer ide": "real verb: cmd/observer/ide.go registers it as `Use: integration.GUILaunchVerb + ...` (GUILaunchVerb = \"ide\"), which is not a string literal the Use parser reads",
}

// cobraUseRE captures the first word of a literal cobra Use string, e.g.
// `Use:   "enroll [<org-url> <token>]"` -> "enroll". A Use built from a
// variable is not a literal and is not captured; its verbs go in
// webCommandAllow when the dashboards name one.
var cobraUseRE = regexp.MustCompile("Use:\\s*[\"`]([A-Za-z0-9][A-Za-z0-9_-]*)")

// cobraAliasesRE captures the body of an `Aliases: []string{...}` literal.
var cobraAliasesRE = regexp.MustCompile(`Aliases:\s*\[\]string\{([^}]*)\}`)

// quotedWordRE pulls each quoted word out of an Aliases body.
var quotedWordRE = regexp.MustCompile(`"([^"]+)"`)

// webCommandRE matches a command literal in dashboard source: the binary
// name right after a backtick, a quote or a JSX `>` (so prose such as "the
// observer daemon" in a sentence is not read as a command), then the rest of
// the literal up to the closing delimiter or the end of the line.
var webCommandRE = regexp.MustCompile("(?:^|[`\"'>])(observer(?:-org)?)[ \\t]+([^`\"'<\\n]*)")

// commandWordsFor returns the known command words of the binary whose cobra
// tree lives in dir.
func commandWordsFor(t *testing.T, root, dir string) map[string]bool {
	t.Helper()
	words := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		for _, m := range cobraUseRE.FindAllStringSubmatch(src, -1) {
			words[m[1]] = true
		}
		for _, m := range cobraAliasesRE.FindAllStringSubmatch(src, -1) {
			for _, w := range quotedWordRE.FindAllStringSubmatch(m[1], -1) {
				words[w[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(words) < 20 {
		t.Fatalf("found only %d cobra command words under %s - the Use parser broke, or the tree moved", len(words), dir)
	}
	return words
}

// commandVerb returns the first word of a command literal's remainder when it
// looks like a subcommand: not a flag, placeholder, quote or interpolation,
// and not a path, file name or assignment. ok is false otherwise.
func commandVerb(rest string) (string, bool) {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	w := fields[0]
	if strings.ContainsAny(w[:1], "-<[{$(\"'`") || strings.ContainsAny(w, "=/.\\") {
		return "", false
	}
	w = strings.TrimRight(w, ",;:)!?")
	for _, r := range w {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "", false
		}
	}
	return w, w != ""
}

// webCommandHit is one command literal found in dashboard source.
type webCommandHit struct {
	file, binary, verb string
	line               int
}

// webCommandLiterals walks web/src and web2/src (.ts and .tsx, test files
// skipped) and returns every command literal with a subcommand-shaped verb.
func webCommandLiterals(t *testing.T, root string) []webCommandHit {
	t.Helper()
	var hits []webCommandHit
	for _, tree := range []string{filepath.Join("web", "src"), filepath.Join("web2", "src")} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "dist" {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !(strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".tsx")) || strings.Contains(name, ".test.") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for i, line := range strings.Split(string(data), "\n") {
				for _, m := range webCommandRE.FindAllStringSubmatch(line, -1) {
					verb, ok := commandVerb(m[2])
					if !ok {
						continue
					}
					hits = append(hits, webCommandHit{file: filepath.ToSlash(rel), line: i + 1, binary: m[1], verb: verb})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", tree, err)
		}
	}
	return hits
}

// TestWebCommandNamesExist fails when a dashboard tells a reader to run an
// `observer` or `observer-org` verb that binary does not register.
func TestWebCommandNamesExist(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "web2 and cmd/observer-org")
	root := repoRoot(t)
	known := map[string]map[string]bool{}
	for bin, dir := range webCommandBinaries {
		known[bin] = commandWordsFor(t, root, dir)
	}
	hits := webCommandLiterals(t, root)
	if len(hits) < 10 {
		t.Fatalf("found only %d command literals in web/src and web2/src - the extractor broke, or the copy moved", len(hits))
	}
	var bad []string
	for _, h := range hits {
		key := h.binary + " " + h.verb
		if _, ok := webCommandAllow[key]; ok {
			continue
		}
		if !known[h.binary][h.verb] {
			bad = append(bad, h.file+":"+strconv.Itoa(h.line)+": "+key)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d dashboard command literal(s) name a verb the binary does not register (fix the copy, or list a known-false match in webCommandAllow with its reason):\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestWebCommandNameAllowListIsReasoned keeps the allow-list honest: every entry
// carries a reason.
func TestWebCommandNameAllowListIsReasoned(t *testing.T) {
	for key, reason := range webCommandAllow {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("webCommandAllow[%q] has no reason", key)
		}
	}
}
