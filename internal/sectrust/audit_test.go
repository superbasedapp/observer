package sectrust

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The tests in this file pin the fixes of the P-004 audit (plans decision
// log): files nothing judged are untrusted, a truncated read raises the
// verdict, and a command's digest covers the repository files it names.

// TestPaddedFilesAreUntrusted: a .claude/settings.json padded past the read
// cap hides its SessionStart hook from the rules, and a large bundled
// OpenCode plugin is never read; both are untrusted until their whole-file
// digest is accepted, then flagged.
func TestPaddedFilesAreUntrusted(t *testing.T) {
	pad := strings.Repeat(" ", MaxFileBytes)
	cases := map[string]fixture{
		"padded settings": {files: map[string]string{
			".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"` + pay + `"}]}]}` + pad + `}`,
		}},
		"large plugin": {files: map[string]string{
			".opencode/plugin/bundle.js": "export const P = async () => ({})\n//" + strings.Repeat("x", MaxFileBytes) + "\n",
		}},
		"unparseable settings": {files: map[string]string{
			".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"` + pay + `"}]}]}`,
		}},
	}
	for name, fx := range cases {
		t.Run(name, func(t *testing.T) {
			root := fx.build(t)
			res := check(t, root, "")
			if res.Verdict != VerdictUntrusted || len(res.Digests()) != 1 {
				t.Fatalf("verdict %s digests %v, want untrusted with one whole-file digest; %+v", res.Verdict, res.Digests(), res.Reasons)
			}
			if got := check(t, root, "", res.Digests()...); got.Verdict != VerdictFlagged {
				t.Fatalf("accepted: %s, want flagged", got.Verdict)
			}
			// Any change to the file is a new digest.
			for rel := range fx.files {
				p := filepath.Join(root, filepath.FromSlash(rel))
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, append(b, ' '), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := check(t, root, "", res.Digests()...); got.Verdict != VerdictUntrusted {
				t.Fatalf("changed after the accept: %s, want untrusted", got.Verdict)
			}
		})
	}
}

// TestTruncatedRaisesTheVerdict: a listing cut short is a reason (flagged
// for table files, untrusted for plugin code), so a padded directory cannot
// leave the verdict clean.
func TestTruncatedRaisesTheVerdict(t *testing.T) {
	prose := fixture{files: manyFiles(".claude/commands/c%02d.md", maxGlobFiles+1, "# c\n")}
	res := check(t, prose.build(t), "")
	if !res.Truncated || res.Verdict != VerdictFlagged || !slices.Contains(res.Codes(), "truncated") {
		t.Fatalf("padded commands: truncated %v verdict %s codes %v", res.Truncated, res.Verdict, res.Codes())
	}
	files := manyFiles(".opencode/plugin/p%02d.ts", maxGlobFiles+1, "export {}\n")
	code := fixture{files: files}
	res = check(t, code.build(t), "")
	if !res.Truncated || res.Verdict != VerdictUntrusted || !slices.Contains(res.Codes(), "truncated_code") {
		t.Fatalf("padded plugins: truncated %v verdict %s codes %v", res.Truncated, res.Verdict, res.Codes())
	}
	// Accepting every offered digest leaves the cut-short listing untrusted.
	if again := check(t, code.build(t), "", res.Digests()...); again.Verdict != VerdictUntrusted {
		t.Fatalf("accepting what was read lowered a truncated plugin listing to %s", again.Verdict)
	}
}

// TestDigestCoversNamedFiles: a command that runs a repository file asks
// again when that file changes, not only when the command text does.
func TestDigestCoversNamedFiles(t *testing.T) {
	cases := []struct {
		name, settings, script string
	}{
		{"hook with a relative script", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node .github/setup.js"}]}]}}`, ".github/setup.js"},
		{"hook with the project dir variable", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/x.sh"}]}]}}`, ".claude/hooks/x.sh"},
		{"mcp server argument", `{"mcpServers":{"dev":{"command":"node","args":["./tools/server.js"]}}}`, "tools/server.js"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := ".claude/settings.json"
			if strings.Contains(tc.settings, "mcpServers") {
				file = ".mcp.json"
			}
			root := fixture{files: map[string]string{file: tc.settings, tc.script: "// v1\n"}}.build(t)
			first := check(t, root, "")
			if len(first.Digests()) != 1 || len(first.Reasons) == 0 || !slices.Contains(first.Reasons[0].Files, tc.script) {
				t.Fatalf("first: %+v", first.Reasons)
			}
			if got := check(t, root, "", first.Digests()...); got.Verdict != VerdictFlagged {
				t.Fatalf("accepted: %s", got.Verdict)
			}
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(tc.script)), []byte("// v2, planted\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := check(t, root, "", first.Digests()...); got.Verdict != VerdictUntrusted {
				t.Fatalf("script changed under the accept: %s, want untrusted", got.Verdict)
			}
		})
	}
	t.Run("a command naming no file keeps its text-only digest", func(t *testing.T) {
		cmd := "npx prettier --write ."
		root := fixture{files: map[string]string{".claude/settings.json": `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"` + cmd + `"}]}]}}`}}.build(t)
		res := check(t, root, "")
		if want := Digest("hook_command", ".claude/settings.json", "hooks.Stop.0.hooks.0.command", cmd); len(res.Digests()) != 1 || res.Digests()[0] != want {
			t.Fatalf("digests %v, want %s", res.Digests(), want)
		}
	})
	t.Run("a named script linked outside the repository", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink fixtures need a POSIX file system")
		}
		fx := fixture{
			files: map[string]string{".claude/settings.json": `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh run.sh"}]}]}}`},
			links: map[string]string{"run.sh": "../outside.json"},
		}
		res := check(t, fx.build(t), "")
		if !slices.Contains(res.Codes(), "symlink_escape") {
			t.Fatalf("codes %v, want symlink_escape for the linked script", res.Codes())
		}
	})
}
