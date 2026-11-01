package invariant

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// tool_home_literals_test.go is the surface-gap Wave 4 acceptance check
// (review section 3.5): a config writer resolves a tool's home through its
// agentconfig FileRow artifact (agentconfig.ResolveArtifact, which applies
// the relocation rules), never by joining a hard-coded "~/.codex"-style
// segment onto the home directory. The test collects every tool home
// segment the catalogue declares (the leading ".name" of each "~/.name/..."
// path) and counts the Go string literals in the writer packages that name
// one. Each count is held at or below the ratchet in
// toolHomeLiteralAllowance: a new literal fails the test, and a count that
// drops below its allowance fails too, so the allowance is lowered in the
// same change and never creeps back up. The remaining literals are the
// vendor-default fallbacks beside a resolved artifact and the readers
// tracked as surface-gap FU-70 and FU-71.

// toolHomeWriterDirs are the writer packages the check covers, walked
// recursively, relative to the repository root.
var toolHomeWriterDirs = []string{
	"internal/hook",
	"internal/proxyroute",
	"internal/mcpregister",
	"internal/mcp/locate",
}

// toolHomeWriterFiles are single writer files the check also covers,
// relative to the repository root: the cmd/observer files that write a
// tool's own config home (the Cline CLI providers.json, Hermes's
// config.yaml, the pi and prime-agent models.json through the launcher
// homes). A file list, not the whole package: the rest of cmd/observer
// names tool homes in help text and readers, which this ratchet does not
// govern (R-188 F9).
var toolHomeWriterFiles = []string{
	"cmd/observer/clinecli.go",
	"cmd/observer/hermes.go",
	"cmd/observer/launcher_homes.go",
	"cmd/observer/pi_route.go",
	"cmd/observer/prime-agent.go",
}

// genericHomeSegments are shared base directories, not one tool's home.
var genericHomeSegments = map[string]bool{
	".config": true, ".local": true, ".cache": true,
}

// toolHomeLiteralAllowance is the ratchet: file (slash-separated, relative
// to the repository root) -> home segment -> how many string literals in
// that file may still name it. Lower a count when a literal moves onto an
// artifact; never raise one.
var toolHomeLiteralAllowance = map[string]map[string]int{
	"cmd/observer/clinecli.go":                   {".cline": 2},
	"cmd/observer/hermes.go":                     {".hermes": 2},
	"cmd/observer/prime-agent.go":                {".prime": 2},
	"internal/hook/confighome.go":                {".claude": 1, ".codex": 1},
	"internal/hook/ibmbob_telemetry.go":          {".bob": 1},
	"internal/hook/pluginshim/pluginshim.go":     {".cline": 1, ".commandcode": 1, ".pi": 1},
	"internal/hook/register_cascade.go":          {".codeium": 2},
	"internal/hook/register_codex.go":            {".factory": 2},
	"internal/hook/register_commandcode.go":      {".commandcode": 2},
	"internal/hook/register_core.go":             {".codeium": 1, ".commandcode": 1, ".cursor": 1, ".factory": 1, ".gemini": 2, ".qoder": 1, ".qwen": 1},
	"internal/hook/register_crossos.go":          {".claude": 3, ".codex": 3, ".commandcode": 3, ".copilot": 1, ".cursor": 3, ".factory": 3, ".gemini": 3, ".qoder": 3, ".qwen": 3},
	"internal/hook/register_cursor.go":           {".cursor": 1},
	"internal/hook/register_kiro.go":             {".kiro": 1},
	"internal/hook/register_toolgate_vendors.go": {".agents": 1, ".autohand": 1, ".bob": 1, ".cline": 1, ".codebuddy": 1, ".codeium": 1, ".commandcode": 2, ".copilot": 3, ".deepagents": 1, ".dimcode": 1, ".dirac": 1, ".grok": 1, ".junie": 1, ".kimi-code": 1, ".kiro": 1, ".openinterpreter": 1, ".vibe": 1, ".zcode": 2},
	"internal/hook/register_vibe_cline.go":       {".cline": 1},
	"internal/hook/register_wave1021.go":         {".bob": 2, ".codebuddy": 1, ".deepagents": 2, ".dimcode": 1, ".dirac": 2},
	"internal/hook/toolaccount.go":               {".claude": 1, ".claude.json": 1},
	"internal/mcp/locate/locate.go":              {".claude.json": 1, ".cline": 2, ".codex": 1, ".commandcode": 1, ".cursor": 1, ".factory": 1},
	"internal/mcpregister/register.go":           {".claude": 1, ".cline": 1},
	"internal/proxyroute/codex.go":               {".codex": 1},
	"internal/proxyroute/windows.go":             {".claude": 6, ".codex": 6},
}

func TestToolHomeLiteralsInWritersOnlyShrink(t *testing.T) {
	segments := catalogueHomeSegments()
	if len(segments) < 10 {
		t.Fatalf("catalogue gave only %d tool home segments (%v); the agentconfig paths changed shape", len(segments), segments)
	}
	got := countToolHomeLiterals(t, segments)

	if os.Getenv("SBO_DUMP_TOOL_HOME_LITERALS") != "" {
		t.Log("\n" + renderToolHomeAllowance(got))
	}

	var problems []string
	for file, bySeg := range got {
		for seg, n := range bySeg {
			allowed := toolHomeLiteralAllowance[file][seg]
			if n > allowed {
				problems = append(problems, fmt.Sprintf("%s: %d literal(s) name %q, allowance %d: resolve the path through its agentconfig artifact (agentconfig.ResolveArtifact) instead", file, n, seg, allowed))
			}
		}
	}
	for file, bySeg := range toolHomeLiteralAllowance {
		for seg, allowed := range bySeg {
			if n := got[file][seg]; n < allowed {
				problems = append(problems, fmt.Sprintf("%s: %q now has %d literal(s), allowance %d: lower the allowance to %d", file, seg, n, allowed, n))
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// catalogueHomeSegments returns the ".name" first segment of every
// home-relative FileRow path in the catalogue, generic base dirs excluded.
func catalogueHomeSegments() []string {
	set := map[string]bool{}
	for _, row := range agentconfig.Files() {
		for _, p := range row.Paths.All() {
			p = strings.ReplaceAll(p, `\`, "/")
			if !strings.HasPrefix(p, "~/") {
				continue
			}
			seg := strings.SplitN(strings.TrimPrefix(p, "~/"), "/", 2)[0]
			if strings.HasPrefix(seg, ".") && len(seg) > 1 && !genericHomeSegments[seg] {
				set[seg] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// literalNamesSegment reports which segment a string literal names: the
// literal is the segment itself, starts with "<segment>/", or holds
// "~/<segment>" or "/<segment>/" inside a longer path.
func literalNamesSegment(lit string, segments []string) (string, bool) {
	lit = strings.ReplaceAll(lit, `\`, "/")
	for _, seg := range segments {
		if lit == seg || strings.HasPrefix(lit, seg+"/") ||
			strings.Contains(lit, "~/"+seg) || strings.Contains(lit, "/"+seg+"/") || strings.HasSuffix(lit, "/"+seg) {
			return seg, true
		}
	}
	return "", false
}

func countToolHomeLiterals(t *testing.T, segments []string) map[string]map[string]int {
	t.Helper()
	root := filepath.Join("..", "..")
	got := map[string]map[string]int{}
	fset := token.NewFileSet()
	countFile := func(path string) error {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if seg, ok := literalNamesSegment(s, segments); ok {
				if got[rel] == nil {
					got[rel] = map[string]int{}
				}
				got[rel][seg]++
			}
			return true
		})
		return nil
	}
	for _, dir := range toolHomeWriterDirs {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(dir)), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			return countFile(path)
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	for _, file := range toolHomeWriterFiles {
		if err := countFile(filepath.Join(root, filepath.FromSlash(file))); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
	}
	return got
}

// renderToolHomeAllowance prints counts as a Go map literal, for seeding
// or lowering toolHomeLiteralAllowance.
func renderToolHomeAllowance(got map[string]map[string]int) string {
	files := make([]string, 0, len(got))
	for f := range got {
		files = append(files, f)
	}
	sort.Strings(files)
	var b strings.Builder
	for _, f := range files {
		segs := make([]string, 0, len(got[f]))
		for s := range got[f] {
			segs = append(segs, s)
		}
		sort.Strings(segs)
		fmt.Fprintf(&b, "\t%q: {", f)
		for i, s := range segs {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q: %d", s, got[f][s])
		}
		b.WriteString("},\n")
	}
	return b.String()
}

func TestLiteralNamesSegment(t *testing.T) {
	segs := []string{".claude", ".claude.json", ".codex"}
	cases := []struct {
		lit, want string
		ok        bool
	}{
		{".codex", ".codex", true},
		{".claude/settings.json", ".claude", true},
		{"~/.codex/config.toml", ".codex", true},
		{`C:\Users\x\.claude\settings.json`, ".claude", true},
		{"/home/x/.codex", ".codex", true},
		{".claude.json", ".claude.json", true},
		{"codex", "", false},
		{"settings.json", "", false},
		{".codexrc", "", false},
	}
	for _, c := range cases {
		got, ok := literalNamesSegment(c.lit, segs)
		if ok != c.ok || got != c.want {
			t.Errorf("literalNamesSegment(%q) = %q, %v; want %q, %v", c.lit, got, ok, c.want, c.ok)
		}
	}
}
