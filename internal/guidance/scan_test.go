package guidance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	testProjectRoot = "/repo/demo"
	testUserHome    = "/home/dev"
)

// testFS mounts the checked-in fixture tree at virtual absolute roots.
func testFS(t *testing.T) *memFS {
	t.Helper()
	m := newMemFS()
	m.mount(t, testProjectRoot, filepath.Join("..", "..", "testdata", "guidance", "project"))
	m.mount(t, testUserHome, filepath.Join("..", "..", "testdata", "guidance", "home"))
	return m
}

// testOptions is the posture the fixture tree is sized for: a 1 KiB file
// cap (CRUSH.md is deliberately larger) and a 2-level "**" cap
// (deep/a/b/CLAUDE.md is deliberately deeper).
func testOptions() Options {
	return Options{
		MaxFileBytes:     1024,
		MaxDepth:         2,
		IncludeUserScope: true,
		UserHome:         testUserHome,
	}
}

func scanFixture(t *testing.T, opts Options) Result {
	t.Helper()
	res, err := Scan(context.Background(), testProjectRoot, testFS(t), opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected scan errors: %v", res.Errors)
	}
	return res
}

func byTool(res Result, tool string) []File {
	var out []File
	for _, f := range res.Files {
		if f.Tool == tool {
			out = append(out, f)
		}
	}
	return out
}

func find(t *testing.T, res Result, tool, rel string) File {
	t.Helper()
	for _, f := range res.Files {
		if f.Tool == tool && f.RelPath == rel {
			return f
		}
	}
	t.Fatalf("no File for tool %q rel %q; have %v", tool, rel, relPaths(res, tool))
	return File{}
}

func relPaths(res Result, tool string) []string {
	var out []string
	for _, f := range res.Files {
		if tool == "" || f.Tool == tool {
			out = append(out, f.Tool+":"+f.RelPath)
		}
	}
	return out
}

// TestScanFixtureCounts is the table-driven core: for each tool the
// fixture tree exercises, the exact (kind -> count) shape the scanner
// must produce.
func TestScanFixtureCounts(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())

	cases := []struct {
		tool string
		want map[Kind]int
	}{
		{
			// Two project memories (root + sub/, NOT deep/ and NOT
			// node_modules/), two skills, one agent, one command, one
			// settings.json, plus the two user-scope files.
			tool: "claude-code",
			want: map[Kind]int{
				KindInstructions: 3, // CLAUDE.md, sub/CLAUDE.md, ~/.claude/CLAUDE.md
				KindSkill:        3, // foo, nameless, ~/.claude/skills/bar
				KindAgent:        1,
				KindCommand:      1,
				KindConfig:       1,
			},
		},
		{tool: "cursor", want: map[Kind]int{KindRule: 2}},
		{tool: "copilot", want: map[Kind]int{KindInstructions: 1}},
		{tool: "copilot-cli", want: map[Kind]int{KindInstructions: 1}},
		{tool: "codex", want: map[Kind]int{KindInstructions: 1}},
		{tool: "opencode", want: map[Kind]int{KindInstructions: 1}},
		// CRUSH.md exists but is over the 1 KiB cap, so crush sees nothing.
		{tool: "crush", want: map[Kind]int{}},
		// No GEMINI.md in the fixture tree.
		{tool: "gemini-cli", want: map[Kind]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			got := map[Kind]int{}
			for _, f := range byTool(res, tc.tool) {
				got[f.Kind]++
			}
			if len(got) != len(tc.want) {
				t.Fatalf("kind shape mismatch: got %v want %v (files %v)", got, tc.want, relPaths(res, tc.tool))
			}
			for k, n := range tc.want {
				if got[k] != n {
					t.Errorf("kind %s: got %d want %d (files %v)", k, got[k], n, relPaths(res, tc.tool))
				}
			}
		})
	}
}

// TestScanSkipsOversizeFile pins the size cap: the file is COUNTED, not
// silently dropped, so an operator can tell "no guidance" from "a
// guidance file too big to be guidance".
func TestScanSkipsOversizeFile(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1 (CRUSH.md is over the cap)", res.Skipped)
	}
	for _, f := range res.Files {
		if strings.HasSuffix(f.RelPath, "CRUSH.md") {
			t.Fatalf("oversize CRUSH.md was reported as a file: %+v", f)
		}
	}

	// Raise the cap and it becomes an ordinary crush instruction file.
	opts := testOptions()
	opts.MaxFileBytes = 1 << 20
	res = scanFixture(t, opts)
	if res.Skipped != 0 {
		t.Errorf("Skipped = %d with a 1 MiB cap, want 0", res.Skipped)
	}
	if got := len(byTool(res, "crush")); got != 1 {
		t.Errorf("crush files = %d, want 1 once the cap clears", got)
	}
}

// TestScanDepthCapAndSkipDirs pins the two things that keep "**" from
// walking a monorepo.
func TestScanDepthCapAndSkipDirs(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())
	for _, f := range res.Files {
		if strings.Contains(f.RelPath, "node_modules") {
			t.Errorf("node_modules was walked: %s", f.RelPath)
		}
		if strings.HasPrefix(f.RelPath, "deep/") {
			t.Errorf("depth cap (2) did not hold: %s", f.RelPath)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "testdata", "guidance", "project", "deep", "a", "b", "CLAUDE.md")); err != nil {
		t.Fatalf("the beyond-depth fixture is missing, so the cap was never tested: %v", err)
	}

	// Raising the cap must reach it — otherwise the assertion above would
	// pass for the wrong reason (e.g. a broken "**" walker).
	opts := testOptions()
	opts.MaxDepth = 4
	deeper := scanFixture(t, opts)
	found := false
	for _, f := range deeper.Files {
		if f.RelPath == "deep/a/b/CLAUDE.md" {
			found = true
		}
		if strings.Contains(f.RelPath, "node_modules") {
			t.Errorf("node_modules walked even at depth 4: %s", f.RelPath)
		}
	}
	if !found {
		t.Errorf("depth 4 did not reach deep/a/b/CLAUDE.md; files: %v", relPaths(deeper, "claude-code"))
	}
}

// TestScanFrontmatterAndNames covers the metadata half: front-matter
// extraction, the allow-list, and the three name-resolution tiers.
func TestScanFrontmatterAndNames(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())

	cases := []struct {
		name            string
		tool, rel       string
		wantName        string
		wantDescription string
		wantFM          map[string]string
		wantParseErr    bool
	}{
		{
			name: "skill name from front matter", tool: "claude-code", rel: ".claude/skills/foo/SKILL.md",
			wantName: "foo-skill", wantDescription: "Formats a foo before shipping it.",
			wantFM: map[string]string{"allowed-tools": "Read, Bash"},
		},
		{
			name: "skill name falls back to the directory", tool: "claude-code", rel: ".claude/skills/nameless/SKILL.md",
			wantName: "nameless", wantDescription: "No name key, so the directory names it.",
		},
		{
			name: "command name falls back to the stem", tool: "claude-code", rel: ".claude/commands/deploy.md",
			wantName: "deploy", wantDescription: "Deploys the service.",
			wantFM: map[string]string{"argument-hint": "[env]"},
		},
		{
			name: "agent carries model", tool: "claude-code", rel: ".claude/agents/reviewer.md",
			wantName: "reviewer", wantDescription: "Reviews a diff.",
			wantFM: map[string]string{"model": "opus"},
		},
		{
			name: "mdc rule flattens globs and alwaysApply", tool: "cursor", rel: ".cursor/rules/a.mdc",
			wantName: "a", wantDescription: "Go style rules.",
			wantFM: map[string]string{"globs": "**/*.go", "alwaysApply": "false"},
		},
		{
			// A malformed block still yields a body, so the file keeps a
			// body-derived description — the front-matter keys are what is
			// lost, and ParseErr says so.
			name: "broken front matter is reported, not dropped", tool: "cursor", rel: ".cursor/rules/broken.mdc",
			wantName: "broken", wantDescription: "Broken on purpose.", wantParseErr: true,
		},
		{
			name: "prose instructions describe themselves from the body", tool: "claude-code", rel: "CLAUDE.md",
			wantName: "CLAUDE", wantDescription: "Always run make lint before committing.",
		},
		{
			name: "user scope renders a ~/ path", tool: "claude-code", rel: "~/.claude/skills/bar/SKILL.md",
			wantName: "bar-skill", wantDescription: "A user-scope skill.",
		},
		{
			name: "json config carries no front matter", tool: "claude-code", rel: ".claude/settings.json",
			wantName: "settings",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := find(t, res, tc.tool, tc.rel)
			if f.Name != tc.wantName {
				t.Errorf("Name = %q want %q", f.Name, tc.wantName)
			}
			if f.Description != tc.wantDescription {
				t.Errorf("Description = %q want %q", f.Description, tc.wantDescription)
			}
			if tc.wantParseErr && f.ParseErr == "" {
				t.Errorf("ParseErr empty, want a reported failure")
			}
			if !tc.wantParseErr && f.ParseErr != "" {
				t.Errorf("ParseErr = %q, want none", f.ParseErr)
			}
			for k, v := range tc.wantFM {
				if f.Frontmatter[k] != v {
					t.Errorf("Frontmatter[%q] = %q want %q (all: %v)", k, f.Frontmatter[k], v, f.Frontmatter)
				}
			}
			for k := range f.Frontmatter {
				if !contains(KnownFrontmatterKeys(), k) && k != "instructions" {
					t.Errorf("Frontmatter carries un-allow-listed key %q", k)
				}
			}
		})
	}
}

// TestScanUserScopePaths pins the two halves of the user-scope contract:
// the "~/"-prefixed RelPath (so it can never be mistaken for a repo
// file) and the IncludeUserScope / UserHome gates.
func TestScanUserScopePaths(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())
	var user int
	for _, f := range res.Files {
		if f.Scope != ScopeUser {
			continue
		}
		user++
		if !strings.HasPrefix(f.RelPath, "~/") {
			t.Errorf("user-scope RelPath %q is not ~/-prefixed", f.RelPath)
		}
		if !strings.HasPrefix(f.AbsPath, testUserHome+"/") {
			t.Errorf("user-scope AbsPath %q is not under the home root", f.AbsPath)
		}
	}
	if user != 2 {
		t.Errorf("user-scope files = %d, want 2", user)
	}

	for _, tc := range []struct {
		name string
		opts func(Options) Options
	}{
		{"IncludeUserScope off", func(o Options) Options { o.IncludeUserScope = false; return o }},
		{"UserHome empty", func(o Options) Options { o.UserHome = ""; return o }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scanFixture(t, tc.opts(testOptions()))
			for _, f := range got.Files {
				if f.Scope == ScopeUser {
					t.Fatalf("user-scope file leaked with %s: %s", tc.name, f.RelPath)
				}
			}
		})
	}
}

// TestScanDedupesPerToolAndFansOutAcrossTools pins the intended shape:
// one file matched by two of ONE tool's rules appears once, while a file
// several tools read appears once PER TOOL.
func TestScanDedupesPerToolAndFansOutAcrossTools(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())

	// CLAUDE.md is matched by both "CLAUDE.md" and "**/CLAUDE.md".
	var rootMemory int
	for _, f := range res.Files {
		if f.Tool == "claude-code" && f.RelPath == "CLAUDE.md" {
			rootMemory++
		}
	}
	if rootMemory != 1 {
		t.Errorf("claude-code reported CLAUDE.md %d times, want 1 (the two rules must dedupe)", rootMemory)
	}

	// AGENTS.md fans out to every tool with a project-scope AGENTS.md row.
	want := map[string]bool{}
	for _, r := range Rules() {
		if r.Scope == ScopeProject && r.Glob == "AGENTS.md" {
			want[r.Tool] = true
		}
	}
	if len(want) < 10 {
		t.Fatalf("only %d tools declare AGENTS.md — the table looks broken", len(want))
	}
	got := map[string]int{}
	for _, f := range res.Files {
		if f.RelPath == "AGENTS.md" {
			got[f.Tool]++
		}
	}
	if len(got) != len(want) {
		t.Errorf("AGENTS.md reached %d tools, want %d", len(got), len(want))
	}
	for tool := range want {
		if got[tool] != 1 {
			t.Errorf("AGENTS.md for %s: %d rows, want exactly 1", tool, got[tool])
		}
	}
}

// TestScanHashesContentAndDropsBodies pins the privacy posture: the hash
// is real, and nothing longer than a capped description survives.
func TestScanHashesContentAndDropsBodies(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "guidance", "project", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sum := sha256.Sum256(raw)
	f := find(t, res, "claude-code", "CLAUDE.md")
	if f.ContentHash != hex.EncodeToString(sum[:]) {
		t.Errorf("ContentHash = %q, want the sha256 of the file bytes", f.ContentHash)
	}
	if f.SizeBytes != int64(len(raw)) {
		t.Errorf("SizeBytes = %d want %d", f.SizeBytes, len(raw))
	}
	for _, g := range res.Files {
		if len(g.Description) > maxDescriptionBytes {
			t.Errorf("%s description exceeds the cap (%d bytes)", g.RelPath, len(g.Description))
		}
		for k, v := range g.Frontmatter {
			if len(v) > maxFrontmatterValueBytes {
				t.Errorf("%s frontmatter[%s] exceeds the cap (%d bytes)", g.RelPath, k, len(v))
			}
		}
	}
}

// TestScanUserScopeOnly pins the once-per-pass user-scope mode: the home
// rules run, every project rule is skipped, and the gates still apply.
func TestScanUserScopeOnly(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.UserScopeOnly = true
	res := scanFixture(t, opts)
	if len(res.Files) == 0 {
		t.Fatal("user-scope-only scan returned nothing")
	}
	for _, f := range res.Files {
		if f.Scope != ScopeUser {
			t.Fatalf("project-scope file leaked into a user-scope-only pass: %s/%s", f.Tool, f.RelPath)
		}
	}
	// It is exactly the user half of a full pass — no more, no less.
	full := scanFixture(t, testOptions())
	var wantUser int
	for _, f := range full.Files {
		if f.Scope == ScopeUser {
			wantUser++
		}
	}
	if len(res.Files) != wantUser {
		t.Errorf("user-scope-only produced %d files, the full pass has %d user-scope files", len(res.Files), wantUser)
	}

	opts.IncludeUserScope = false
	if got := scanFixture(t, opts); len(got.Files) != 0 {
		t.Errorf("UserScopeOnly with IncludeUserScope=false produced %d files, want 0", len(got.Files))
	}
}

// TestScanKnownCacheReusesUnchangedRows pins the Known seam: a file whose
// size and mtime still match is NOT re-read, and its previous metadata is
// carried forward verbatim; anything that moved is re-read.
func TestScanKnownCacheReusesUnchangedRows(t *testing.T) {
	t.Parallel()
	base := scanFixture(t, testOptions())
	claude := find(t, base, "claude-code", "CLAUDE.md")

	known := map[string]KnownFile{
		claude.AbsPath: {
			SizeBytes:   claude.SizeBytes,
			ModTime:     claude.ModTime,
			ContentHash: "cached-hash",
			Name:        "cached-name",
			Description: "cached-description",
			Frontmatter: map[string]string{"model": "cached"},
		},
	}
	// A stale entry for a second file: same path, WRONG size, so it must be
	// re-read rather than trusted.
	agents := find(t, base, "codex", "AGENTS.md")
	known[agents.AbsPath] = KnownFile{
		SizeBytes:   agents.SizeBytes + 1,
		ModTime:     agents.ModTime,
		ContentHash: "stale-hash",
		Name:        "stale-name",
	}

	var reads int
	fsys := &countingFS{FS: testFS(t), reads: &reads}
	opts := testOptions()
	opts.Known = func(abs string) (KnownFile, bool) {
		k, ok := known[abs]
		return k, ok
	}
	res, err := Scan(context.Background(), testProjectRoot, fsys, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got := find(t, res, "claude-code", "CLAUDE.md")
	if got.ContentHash != "cached-hash" || got.Name != "cached-name" || got.Description != "cached-description" {
		t.Errorf("unchanged file was not served from the cache: %+v", got)
	}
	if got.Frontmatter["model"] != "cached" {
		t.Errorf("cached front matter lost: %v", got.Frontmatter)
	}
	if reads == 0 {
		t.Fatal("no file was read at all — the counting FS is not wired")
	}
	for _, f := range res.Files {
		if f.AbsPath == claude.AbsPath && f.Tool == "claude-code" && f.ContentHash != "cached-hash" {
			t.Errorf("a cached path was re-hashed: %+v", f)
		}
	}
	stale := find(t, res, "codex", "AGENTS.md")
	if stale.ContentHash == "stale-hash" || stale.Name == "stale-name" {
		t.Errorf("a size-mismatched cache entry was trusted: %+v", stale)
	}
	if stale.ContentHash != agents.ContentHash {
		t.Errorf("re-read hash = %q, want the real %q", stale.ContentHash, agents.ContentHash)
	}
}

// countingFS counts ReadFile calls so a cache hit is observable as an
// absence of I/O, not merely as a matching field.
type countingFS struct {
	FS
	reads *int
}

func (c *countingFS) ReadFile(p string) ([]byte, error) {
	*c.reads++
	return c.FS.ReadFile(p)
}

// TestOSFSRefusesSymlinkEscape is the containment pin for the REAL
// filesystem (the in-memory FS has no symlinks to escape through): a
// guidance-named symlink pointing outside the scan anchors is refused and
// SURFACED in Result.Errors, while an ordinary in-project symlink still
// resolves normally.
func TestOSFSRefusesSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if insideHome(t, outside) {
		t.Skip("the temp dir lives under the operator's home, which is itself an anchor")
	}

	secret := filepath.Join(outside, "secret.env")
	if err := os.WriteFile(secret, []byte("ANTHROPIC_API_KEY=sk-ant-api03-not-a-real-key\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	realBody := []byte("# Agents\n\nRun make lint before committing.\n")
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), realBody, 0o644); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}
	// An in-project symlink: legitimate, and must keep working.
	if err := os.Symlink("AGENTS.md", filepath.Join(root, "CLAUDE.md")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	// The escape.
	if err := os.Symlink(secret, filepath.Join(root, "GEMINI.md")); err != nil {
		t.Fatalf("symlink escape: %v", err)
	}
	// A dangling link is ordinary "not there", not a refusal.
	if err := os.Symlink(filepath.Join(outside, "gone.md"), filepath.Join(root, "QWEN.md")); err != nil {
		t.Fatalf("dangling symlink: %v", err)
	}

	res, err := Scan(context.Background(), root, OSFS(root), Options{
		MaxFileBytes: 1 << 20,
		MaxDepth:     2,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, f := range res.Files {
		if f.RelPath == "GEMINI.md" {
			t.Errorf("the escaping symlink was scanned: %+v", f)
		}
		if f.RelPath == "QWEN.md" {
			t.Errorf("the dangling symlink produced a file: %+v", f)
		}
		if strings.Contains(f.Description, "sk-ant") || strings.Contains(f.Name, "sk-ant") {
			t.Errorf("secret bytes leaked into metadata: %+v", f)
		}
	}
	var refused bool
	for _, e := range res.Errors {
		if strings.Contains(e, "GEMINI.md") {
			refused = true
		}
		if strings.Contains(e, "QWEN.md") {
			t.Errorf("a dangling symlink was reported as an error: %s", e)
		}
	}
	if !refused {
		t.Errorf("the refusal was not surfaced in Result.Errors: %v", res.Errors)
	}

	// The in-project symlink resolves and is hashed as its target's bytes.
	link := find(t, res, "claude-code", "CLAUDE.md")
	sum := sha256.Sum256(realBody)
	if link.ContentHash != hex.EncodeToString(sum[:]) {
		t.Errorf("in-project symlink hash = %q, want the target's sha256", link.ContentHash)
	}
	if link.SizeBytes != int64(len(realBody)) {
		t.Errorf("in-project symlink size = %d, want %d", link.SizeBytes, len(realBody))
	}
}

// insideHome reports whether p sits under the operator's home directory,
// which OSFS always adds as a second anchor.
func insideHome(t *testing.T, p string) bool {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		real = p
	}
	rel, err := filepath.Rel(home, real)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// TestScanIsSortedAndDeterministic pins the ordering contract the store's
// diffing relies on.
func TestScanIsSortedAndDeterministic(t *testing.T) {
	t.Parallel()
	a := scanFixture(t, testOptions())
	b := scanFixture(t, testOptions())
	if len(a.Files) != len(b.Files) {
		t.Fatalf("two scans of one tree disagree: %d vs %d files", len(a.Files), len(b.Files))
	}
	keys := make([]string, len(a.Files))
	for i, f := range a.Files {
		if b.Files[i].AbsPath != f.AbsPath || b.Files[i].Tool != f.Tool {
			t.Fatalf("scan order is not stable at %d: %s/%s vs %s/%s", i, f.Tool, f.AbsPath, b.Files[i].Tool, b.Files[i].AbsPath)
		}
		keys[i] = f.Tool + "\x00" + string(f.Kind) + "\x00" + f.RelPath
	}
	if !sort.StringsAreSorted(keys) {
		t.Errorf("Files are not sorted by (tool, kind, rel path)")
	}
}

// TestScanRejectsBadInput pins the two guard clauses.
func TestScanRejectsBadInput(t *testing.T) {
	t.Parallel()
	if _, err := Scan(context.Background(), testProjectRoot, nil, DefaultOptions()); err == nil {
		t.Error("nil FS accepted")
	}
	if _, err := Scan(context.Background(), "   ", newMemFS(), DefaultOptions()); err == nil {
		t.Error("empty project root accepted")
	}
}

// TestScanHonoursContextCancellation pins the ctx parameter.
func TestScanHonoursContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, testProjectRoot, testFS(t), testOptions()); err == nil {
		t.Error("cancelled context ignored")
	}
}

// TestDefaultOptions pins the shipped posture.
func TestDefaultOptions(t *testing.T) {
	t.Parallel()
	o := DefaultOptions()
	if o.MaxFileBytes != 512*1024 {
		t.Errorf("MaxFileBytes = %d want 512 KiB", o.MaxFileBytes)
	}
	if o.MaxDepth != 4 {
		t.Errorf("MaxDepth = %d want 4", o.MaxDepth)
	}
	if !o.IncludeUserScope {
		t.Error("IncludeUserScope should default on")
	}
	if o.UserHome != "" {
		t.Error("DefaultOptions must not resolve a home directory — the package is pure")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
