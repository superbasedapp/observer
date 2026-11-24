package main

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// hint_commands_test.go: SR-5 (ship-readiness audit, 2026-11-23). A hint that
// tells a user to run a command that does not exist is worse than no hint:
// `observer stop` and `observer db check` were printed for months. This test
// walks the real cobra tree and fails when a user-facing string in
// cmd/observer, or in the node dashboard's copy (web/src), names an
// `observer ...` command or flag the tree does not have.
//
// What counts as a command mention (prose like "the observer binary" must not
// trip it):
//   - a backticked span that starts with observer: "`observer db vacuum`";
//   - a <code>observer ...</code> span in the dashboard's JSX;
//   - plain text after a cue that introduces a command: "run observer x",
//     "then observer x", "try", "use", "using", or an opening "(".
//
// Each mention is resolved word by word from the root. A word that is not a
// subcommand of a group fails; a placeholder (<tool>, %s, ${sub}) in command
// position stops the check, since it stands for any command; after the
// command resolves, every --flag must exist on it.

// hintCommandExceptions are mentions the walk accepts although the tree does
// not resolve them. A row matches a mention that starts with its prefix.
// Every row must still match something, so a stale row fails the test too.
var hintCommandExceptions = []struct {
	prefix string
	reason string
}{
	{"observer and ", "prose in web/src help: \"(observer and watcher make no network calls)\""},
	{"observer does ", "prose in web/src Routing: \"(observer does not write this tool ...)\""},
	{"observer never ", "prose in web/src help: \"(observer never writes their files)\""},
	{"observer then ", "prose in opencode's help: \"... then observer then sees local activity\""},
}

var (
	hintBacktickRE = regexp.MustCompile("`(observer(?:\\s[^`]*)?)`")
	hintCodeTagRE  = regexp.MustCompile(`<code>(observer(?:\s[^<]*)?)</code>`)
	hintCueRE      = regexp.MustCompile(`(?:\b(?:[Rr]un|then|[Tt]ry|[Uu]se|[Uu]sing)\s+|\(\s*)(observer\s[^,;:)\n"'` + "`" + `]*)`)
	hintWordRE     = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	hintFlagRE     = regexp.MustCompile(`^(?:--[a-z][a-z0-9-]*|-[a-zA-Z])$`)
	hintSplitRE    = regexp.MustCompile(`\s*(?:&&|\|\||;|\|)\s*`)
)

// hintMention is one command mention and where it was found.
type hintMention struct {
	where string
	span  string
}

// hintMentions returns the command mentions in one piece of copy.
func hintMentions(where, text string) []hintMention {
	var out []hintMention
	for _, re := range []*regexp.Regexp{hintBacktickRE, hintCodeTagRE, hintCueRE} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			for _, part := range hintSplitRE.Split(m[1], -1) {
				part = strings.TrimSpace(part)
				if part == "observer" || strings.HasPrefix(part, "observer ") {
					out = append(out, hintMention{where: where, span: part})
				}
			}
		}
	}
	return out
}

// hintFlagKnown reports whether cmd accepts flag (--name or -x).
func hintFlagKnown(cmd *cobra.Command, flag string) bool {
	switch flag {
	case "--help", "-h":
		return true
	}
	if strings.HasPrefix(flag, "--") {
		name := strings.TrimPrefix(flag, "--")
		return cmd.Flags().Lookup(name) != nil || cmd.InheritedFlags().Lookup(name) != nil
	}
	short := strings.TrimPrefix(flag, "-")
	return cmd.Flags().ShorthandLookup(short) != nil || cmd.InheritedFlags().ShorthandLookup(short) != nil
}

// hintSubcommand returns the child of cmd named (or aliased) word.
func hintSubcommand(cmd *cobra.Command, word string) *cobra.Command {
	for _, c := range cmd.Commands() {
		if c.Name() == word || c.HasAlias(word) {
			return c
		}
	}
	return nil
}

// hintCheck resolves one mention against root and returns why it is wrong
// ("" when it names a real command and real flags).
func hintCheck(root *cobra.Command, span string) string {
	toks := strings.Fields(span)[1:]
	cur := root
	resolving := true
	for _, tok := range toks {
		tok = strings.TrimRight(tok, ".,:;)'\"")
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			name, _, _ := strings.Cut(tok, "=")
			resolving = false
			if !hintFlagRE.MatchString(name) {
				continue // a placeholder such as --<tool>
			}
			if !hintFlagKnown(cur, name) {
				return "`" + cur.CommandPath() + "` has no flag " + name
			}
			continue
		}
		if !resolving {
			continue // a positional argument or a flag value
		}
		if !hintWordRE.MatchString(tok) {
			if cur == root || (cur.HasSubCommands() && cur.Annotations[annotationGroupGuard] == "true") {
				return "" // a placeholder in command position: any command
			}
			resolving = false // a positional placeholder such as <id>
			continue
		}
		if next := hintSubcommand(cur, tok); next != nil {
			cur = next
			continue
		}
		if cur == root || cur.Annotations[annotationGroupGuard] == "true" {
			return "`" + cur.CommandPath() + "` has no subcommand " + strconv.Quote(tok)
		}
		resolving = false // a group or command that takes positional words
	}
	return ""
}

// Editions. The edition gate units run this test in a build made with a
// distro's tags (sbo_distro_<name> plus its sbo_omit_<id> tags), where some
// commands are not compiled in. Two rules keep a command the edition leaves
// out from counting as a broken hint there, and neither changes anything in
// a plain build, which carries no tags and omits nothing, so every hint is
// still checked against the full tree:
//   - hintFileInBuild: a Go file the binary's own build tags exclude is not
//     in this edition, so its copy is never printed here and is not scanned
//     (the build that compiles the file checks it);
//   - hintOmittedVerbs: a mention whose verb belongs to a component this
//     binary was built without names the compiledOutVerb stand-in, which
//     refuses with "not in this build" and the builds that have it (D-514);
//     the component's real subcommands and flags are checked by the build
//     that has them. This covers the dashboard's copy, which every edition
//     shares, and a compiled file pointing at an omitted component's verb.

// hintBinaryTags returns the build tags this test binary was compiled with
// (go test -tags), read from its own build info; empty for a plain build.
func hintBinaryTags() map[string]bool {
	tags := map[string]bool{}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return tags
	}
	for _, s := range bi.Settings {
		if s.Key != "-tags" {
			continue
		}
		for _, tag := range strings.Split(s.Value, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags[tag] = true
			}
		}
	}
	return tags
}

// hintBuildConstraint returns the //go:build expression of a Go source
// file, nil when it has none.
func hintBuildConstraint(src []byte) (constraint.Expr, error) {
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			return constraint.Parse(line)
		}
	}
	return nil, nil
}

// hintFileInBuild reports whether a Go file with build constraint expr (nil:
// none) is compiled into this binary on some platform: expr holds with every
// tag the binary was built with set, for some value of each other tag it
// names (an OS, an architecture, an edition tag this binary does not carry).
// With no tags (a plain build) every satisfiable file is in, as before.
func hintFileInBuild(expr constraint.Expr, tags map[string]bool) bool {
	if expr == nil {
		return true
	}
	idx := map[string]int{}
	expr.Eval(func(tag string) bool { // Eval visits every tag it names
		if _, seen := idx[tag]; !seen && !tags[tag] {
			idx[tag] = len(idx)
		}
		return false
	})
	if len(idx) > 16 {
		return true // too many free tags to enumerate: scan it, as before
	}
	for mask := 0; mask < 1<<len(idx); mask++ {
		if expr.Eval(func(tag string) bool {
			if tags[tag] {
				return true
			}
			return mask&(1<<idx[tag]) != 0
		}) {
			return true
		}
	}
	return false
}

// hintOmittedVerbs returns the top-level verbs whose component this binary
// was built without (components.Omitted), each with that component. In an
// edition build such a verb is a compiledOutVerb stand-in; a plain build
// omits nothing, so the map is empty there.
func hintOmittedVerbs() map[string]string {
	omitted := map[string]bool{}
	for _, id := range components.Omitted() {
		omitted[id] = true
	}
	out := map[string]string{}
	for verb, id := range verbComponents() {
		if omitted[id] {
			out[verb] = id
		}
	}
	return out
}

// hintVerb returns the first word after `observer` in a mention: the verb
// when the mention names one.
func hintVerb(span string) string {
	toks := strings.Fields(span)
	if len(toks) < 2 {
		return ""
	}
	return strings.TrimRight(toks[1], ".,:;)'\"")
}

// hintGoCopy returns every string constant in the non-test Go files of dir
// that this binary compiles (hintFileInBuild over tags), with adjacent
// "a" + "b" concatenations folded into one string.
func hintGoCopy(t *testing.T, dir string, tags map[string]bool) []hintMention {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []hintMention
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		expr, err := hintBuildConstraint(src)
		if err != nil {
			t.Fatalf("%s: build constraint: %v", f, err)
		}
		if !hintFileInBuild(expr, tags) {
			continue
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BinaryExpr:
				if s, ok := hintFoldString(e); ok {
					out = append(out, hintMentions(fset.Position(e.Pos()).String(), s)...)
					return false
				}
			case *ast.BasicLit:
				if e.Kind == token.STRING {
					if s, err := strconv.Unquote(e.Value); err == nil {
						out = append(out, hintMentions(fset.Position(e.Pos()).String(), s)...)
					}
				}
			}
			return true
		})
	}
	return out
}

// hintFoldString folds a + chain made only of string literals.
func hintFoldString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return hintFoldString(v.X)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, ok := hintFoldString(v.X)
		if !ok {
			return "", false
		}
		r, ok := hintFoldString(v.Y)
		return l + r, ok
	}
	return "", false
}

// hintWebCopy returns the mentions in the dashboard's non-test TypeScript,
// with comments removed (a code comment is not copy).
func hintWebCopy(t *testing.T, dir string) []hintMention {
	t.Helper()
	var out []hintMention
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() || strings.Contains(name, ".test.") || !(strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".tsx")) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		for i, line := range strings.Split(stripTSComments(string(raw)), "\n") {
			out = append(out, hintMentions("web/src/"+filepath.ToSlash(rel)+":"+strconv.Itoa(i+1), line)...)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stripTSComments blanks // and /* */ comments outside string literals,
// keeping line numbers. Template literals are copied whole (their ${...}
// parts are not parsed: a comment inside one is rare and harmless here).
func stripTSComments(src string) string {
	var b strings.Builder
	n := len(src)
	for i := 0; i < n; {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				return b.String()
			}
			i += j
		case c == '/' && i+1 < n && src[i+1] == '*':
			end := n
			if j := strings.Index(src[i+2:], "*/"); j >= 0 {
				end = i + 2 + j + 2
			}
			b.WriteString(strings.Repeat("\n", strings.Count(src[i:end], "\n")))
			i = end
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < n && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= n {
				j = n - 1
			}
			b.WriteString(src[i : j+1])
			i = j + 1
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// hintRoot is the CLI's root as a user runs it: the help command and the
// --help / --version flags cobra adds at Execute are present.
func hintRoot() *cobra.Command {
	root := newRootCmd()
	root.InitDefaultHelpCmd()
	root.InitDefaultHelpFlag()
	root.InitDefaultVersionFlag()
	return root
}

func TestHintsNameRealCommands(t *testing.T) {
	root := hintRoot()
	mentions := hintGoCopy(t, ".", hintBinaryTags())
	mentions = append(mentions, hintWebCopy(t, filepath.Join("..", "..", "web", "src"))...)
	if len(mentions) < 100 {
		t.Fatalf("found only %d command mentions; the scan is not reading the copy", len(mentions))
	}
	omittedVerbs := hintOmittedVerbs()
	used := make([]bool, len(hintCommandExceptions))
	for _, m := range mentions {
		excepted := false
		for i, ex := range hintCommandExceptions {
			if strings.HasPrefix(m.span+" ", ex.prefix) {
				used[i], excepted = true, true
			}
		}
		if excepted {
			continue
		}
		if omittedVerbs[hintVerb(m.span)] != "" {
			continue // a stand-in for a component this edition leaves out
		}
		if why := hintCheck(root, m.span); why != "" {
			t.Errorf("%s: %q: %s (fix the hint, or add a reasoned row to hintCommandExceptions)", m.where, m.span, why)
		}
	}
	for i, ex := range hintCommandExceptions {
		if !used[i] {
			t.Errorf("hintCommandExceptions row %q matches nothing any more; remove it", ex.prefix)
		}
	}
}

// TestHintCheckRules pins the resolver on known shapes, so a change to the
// walk cannot quietly accept a missing command.
func TestHintCheckRules(t *testing.T) {
	root := hintRoot()
	cases := []struct {
		span    string
		wantBad bool
	}{
		{"observer start", false},
		{"observer db vacuum", false},
		{"observer doctor db", false},
		{"observer doctor codex --integrity", false},
		{"observer service restart --when-idle", false},
		{"observer help sandbox", false},
		{"observer --version", false},
		{"observer <tool> --attach", false},
		{"observer %s --continue-from <id>", false},
		{"observer predict <id>", false},
		{"observer stop", true},
		{"observer db check", true},
		{"observer start --no-such-flag", true},
		{"observer service frobnicate", true},
	}
	for _, c := range cases {
		got := hintCheck(root, c.span)
		if (got != "") != c.wantBad {
			t.Errorf("hintCheck(%q) = %q, want bad=%v", c.span, got, c.wantBad)
		}
	}
	// The mention finder: backticks, <code>, and cue words; never bare prose.
	finder := []struct {
		text string
		want []string
	}{
		{"Investigate with `observer doctor db` first", []string{"observer doctor db"}},
		{"<code>observer apps on</code>", []string{"observer apps on"}},
		{"restart it (observer stop, then observer start).", []string{"observer stop", "observer start"}},
		{"Run observer init --guard to wire it", []string{"observer init --guard to wire it"}},
		{"the observer binary on PATH", nil},
		{"`observer x && observer y`", []string{"observer x", "observer y"}},
	}
	for _, f := range finder {
		var got []string
		for _, m := range hintMentions("t", f.text) {
			got = append(got, m.span)
		}
		if strings.Join(got, "|") != strings.Join(f.want, "|") {
			t.Errorf("hintMentions(%q) = %q, want %q", f.text, got, f.want)
		}
	}
	// The edition file rule: a file is left out only when the binary's own
	// tags exclude it on every platform; a plain build (no tags) scans every
	// file, omit twins included, as before.
	builds := []struct {
		line string
		tags string
		want bool
	}{
		{"", "", true},
		{"", "sbo_distro_managed,sbo_omit_remote", true},
		{"//go:build !sbo_omit_cloud_intelligence", "", true},
		{"//go:build !sbo_omit_cloud_intelligence", "sbo_distro_managed,sbo_omit_cloud_intelligence", false},
		{"//go:build sbo_omit_cloud_intelligence", "", true},
		{"//go:build sbo_omit_cloud_intelligence", "sbo_distro_managed,sbo_omit_cloud_intelligence", true},
		{"//go:build !sbo_omit_security && !sbo_omit_security_scan_actionlint", "sbo_omit_security_scan_actionlint", false},
		{"//go:build windows", "sbo_omit_remote", true},
		{"//go:build linux && !sbo_omit_remote", "sbo_omit_remote", false},
		{"//go:build !windows || !sbo_omit_remote", "sbo_omit_remote", true},
	}
	for _, b := range builds {
		var expr constraint.Expr
		if b.line != "" {
			var err error
			if expr, err = constraint.Parse(b.line); err != nil {
				t.Fatalf("%q: %v", b.line, err)
			}
		}
		tags := map[string]bool{}
		for _, tag := range strings.Split(b.tags, ",") {
			if tag != "" {
				tags[tag] = true
			}
		}
		if got := hintFileInBuild(expr, tags); got != b.want {
			t.Errorf("hintFileInBuild(%q, %q) = %v, want %v", b.line, b.tags, got, b.want)
		}
	}
	for span, want := range map[string]string{"observer cloud consent --session x": "cloud", "observer remote.": "remote", "observer": ""} {
		if got := hintVerb(span); got != want {
			t.Errorf("hintVerb(%q) = %q, want %q", span, got, want)
		}
	}
}
