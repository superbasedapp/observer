package codexpatch

import (
	"strings"
	"testing"
)

const (
	decoyPatch = "*** Begin Patch\n*** Update File: /repo/DECOY.go\n@@\n-a\n+b\n*** End Patch"
	realPatch  = "*** Begin Patch\n*** Update File: /repo/REAL.go\n@@\n-a\n+b\n*** End Patch"
)

// quoteJS renders s as a double-quoted JavaScript string literal with
// its newlines escaped, the way live Codex programs hoist an envelope.
func quoteJS(s string) string {
	return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"`
}

// TestStringBindingIsPositionAndCommentAware is the WP-T6 finding F5
// guard, moved here with the decoder it pins (it used to run against
// internal/adapter/codex's parseUnifiedExec). Binding resolution used to
// take the FIRST textual `<ident> = "…"` in the program, scanning
// strings-aware but COMMENT-BLIND and with no notion of where the call
// is. Three shapes therefore resolved to a patch the call never received
// — and the patch decides the row's Target, i.e. which file we report as
// edited.
//
// Mutating StringBinding back to first-wins fails "reassignment";
// dropping either comment branch fails the decoy cases; dropping the
// `before` bound fails "assignment after the call".
func TestStringBindingIsPositionAndCommentAware(t *testing.T) {
	t.Parallel()
	const (
		decoy = decoyPatch
		real  = realPatch
	)
	q := quoteJS
	cases := []struct {
		name    string
		program string
		want    string // "" = must not resolve
	}{
		{
			name: "reassignment — the LAST binding before the call wins",
			program: `let patch = ` + q(decoy) + `;` + "\n" +
				`patch = ` + q(real) + `;` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		// The decoys below sit AFTER the real binding on purpose. A
		// decoy placed BEFORE it is masked by last-wins and proves
		// nothing about comment- or string-awareness — mutating either
		// branch away still passed that arrangement (measured
		// 2026-07-31). Positioned after, only genuine awareness keeps
		// the real value.
		{
			name: "line-commented decoy after the real binding is ignored",
			program: `let patch = ` + q(real) + `;` + "\n" +
				`// patch = ` + q(decoy) + `;` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		{
			name: "block-commented decoy after the real binding is ignored",
			program: `let patch = ` + q(real) + `;` + "\n" +
				`/* patch = ` + q(decoy) + `; */` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		{
			name: "a decoy binding inside an unrelated string literal is ignored",
			program: `let patch = ` + q(real) + `;` + "\n" +
				`const note = "later: patch = ` + strings.ReplaceAll(q(decoy), `"`, `\"`) + `;";` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		{
			name: "a decoy binding BEFORE the real one is overridden",
			program: `let patch = ` + q(decoy) + `;` + "\n" +
				`patch = ` + q(real) + `;` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		{
			name: "assignment AFTER the call cannot have supplied the argument",
			program: `await tools.apply_patch(patch);` + "\n" +
				`const patch = ` + q(decoy) + `;`,
			want: "",
		},
		{
			name: "a later NON-string assignment withdraws an earlier string",
			program: `let patch = ` + q(decoy) + `;` + "\n" +
				`patch = lines.join("\n");` + "\n" +
				`await tools.apply_patch(patch);`,
			want: "",
		},
		{
			name: "a comparison is not a binding",
			program: `const patch = ` + q(real) + `;` + "\n" +
				`if (patch === ` + q(decoy) + `) {}` + "\n" +
				`await tools.apply_patch(patch);`,
			want: real,
		},
		{
			name: "String.raw reassignment still wins",
			program: "let patch = " + q(decoy) + ";\n" +
				"patch = String.raw`*** Begin Patch\n*** Add File: /repo/RAW.go\n+const t = \"\\t\"\n*** End Patch`;\n" +
				"await tools.apply_patch(patch);",
			want: "*** Begin Patch\n*** Add File: /repo/RAW.go\n+const t = \"\\t\"\n*** End Patch",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractPatch(c.program)
			if got != c.want {
				t.Errorf("patch text = %q, want %q", got, c.want)
			}
			if strings.Contains(got, "DECOY") {
				t.Errorf("resolved the DECOY binding: %q", got)
			}
		})
	}
}

// TestExtractPatch is the whole-program entry point's table: every
// argument shape the live corpus passes to apply_patch, plus the shapes
// that must NOT resolve. The lines-of-code shape ladder calls this
// function directly, so a false positive here would invent added and
// removed lines for a program that patched nothing.
func TestExtractPatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		program string
		want    string
	}{
		{
			name: "inline string-literal argument",
			program: `text(await tools.apply_patch(` +
				quoteJS("*** Begin Patch\n*** Delete File: /repo/gone.go\n*** End Patch") + `));`,
			want: "*** Begin Patch\n*** Delete File: /repo/gone.go\n*** End Patch",
		},
		{
			name: "hoisted const binding — the dominant live shape",
			program: `const patch = ` + quoteJS(realPatch) + `;` + "\n" +
				`const result = await tools.apply_patch(patch);` + "\n" + `text(result);`,
			want: realPatch,
		},
		{
			name: "String.raw tagged template keeps escapes inert",
			program: "const patch = String.raw`*** Begin Patch\n*** Add File: /repo/raw.go\n" +
				"+package raw\n+const tab = \"\\t\"\n*** End Patch`;\n" +
				"text(await tools.apply_patch(patch));",
			want: "*** Begin Patch\n*** Add File: /repo/raw.go\n" +
				"+package raw\n+const tab = \"\\t\"\n*** End Patch",
		},
		{
			name: "decoy binding inside a // comment is ignored",
			program: `const patch = ` + quoteJS(realPatch) + `;` + "\n" +
				`// patch = ` + quoteJS(decoyPatch) + `;` + "\n" +
				`await tools.apply_patch(patch);`,
			want: realPatch,
		},
		{
			name: "decoy binding inside an unrelated string literal is ignored",
			program: `const patch = ` + quoteJS(realPatch) + `;` + "\n" +
				`const note = "later: patch = ` +
				strings.ReplaceAll(quoteJS(decoyPatch), `"`, `\"`) + `;";` + "\n" +
				`await tools.apply_patch(patch);`,
			want: realPatch,
		},
		{
			// The envelope itself embeds source that LOOKS like another
			// call. A raw scan would read the embedded text as the call
			// site and resolve nothing (or the wrong thing).
			name: "an apply_patch call embedded in the envelope is not a call",
			program: `const patch = "*** Begin Patch\n*** Update File: /repo/u.go\n` +
				`@@\n+\tawait tools.apply_patch(other)\n*** End Patch";` + "\n" +
				`text(await tools.apply_patch(patch));`,
			want: "*** Begin Patch\n*** Update File: /repo/u.go\n" +
				"@@\n+\tawait tools.apply_patch(other)\n*** End Patch",
		},
		{
			name: "re-binding — the last assignment before the call wins",
			program: `let patch = ` + quoteJS(decoyPatch) + `;` + "\n" +
				`patch = ` + quoteJS(realPatch) + `;` + "\n" +
				`await tools.apply_patch(patch);`,
			want: realPatch,
		},
		{
			name: "assignment AFTER the call site does not resolve",
			program: `await tools.apply_patch(patch);` + "\n" +
				`const patch = ` + quoteJS(realPatch) + `;`,
			want: "",
		},
		{
			name: "binding to a non-string expression yields nothing",
			program: `const patch = lines.join("\n");` + "\n" +
				`await tools.apply_patch(patch);`,
			want: "",
		},
		{
			name:    "a hoisted-array fan-out has no single argument",
			program: `const parts = ["a", "b"]; await tools.apply_patch(parts.join("\n"));`,
			want:    "",
		},
		{
			name:    "apply_patch mentioned but never called",
			program: `const fn = tools.apply_patch; text(typeof fn);`,
			want:    "",
		},
		{
			name:    "a program that patches nothing",
			program: `const r = await tools.exec_command({cmd:"go test ./..."}); text(r.output);`,
			want:    "",
		},
		{
			name:    "empty program",
			program: "",
			want:    "",
		},
		{
			name:    "garbage that is not JavaScript at all",
			program: "\x00\xff\xfe not javascript at all",
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractPatch(c.program); got != c.want {
				t.Errorf("ExtractPatch = %q, want %q", got, c.want)
			}
		})
	}
}

// TestExtractPatchMalformedIsSafe pins the failure mode: a truncated,
// unbalanced or otherwise malformed program must return an honest empty
// (or partial) result and never panic. Rollouts are appended to live and
// are routinely read mid-write.
func TestExtractPatchMalformedIsSafe(t *testing.T) {
	t.Parallel()
	programs := []string{
		`const patch = "*** Begin Patch\n*** Add File: /a\n+x`,
		`const patch = String.raw` + "`" + `*** Begin Patch`,
		`await tools.apply_patch(`,
		`await tools.apply_patch`,
		`apply_patch`,
		`/* unterminated comment await tools.apply_patch(patch)`,
		`// await tools.apply_patch(patch)`,
		`const patch = "\u00`,
		`const patch = "x\`,
		strings.Repeat("(", 5000),
		strings.Repeat(`"`, 5000),
		strings.Repeat("apply_patch(", 2000),
		strings.Repeat("a", ScanLimit+16),
	}
	for _, p := range programs {
		t.Run(strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return '.'
			}
			return r
		}, p[:min(40, len(p))]), func(t *testing.T) {
			t.Parallel()
			// The assertion is that this returns at all.
			_ = ExtractPatch(p)
		})
	}
}

// TestPatchArgument pins the argument resolver on its own, with the
// call offset supplied explicitly the way the Codex adapter's dispatcher
// scanner supplies it.
func TestPatchArgument(t *testing.T) {
	t.Parallel()
	program := `const patch = ` + quoteJS(realPatch) + `;` + "\n" +
		`const r = await tools.apply_patch(patch);`
	callAt := strings.Index(program, "tools.apply_patch")
	cases := []struct {
		name string
		args string
		at   int
		want string
	}{
		{"identifier resolved through the binding", "patch", callAt, realPatch},
		{"inline literal needs no binding", quoteJS(decoyPatch), callAt, decoyPatch},
		{"leading whitespace is tolerated", "  \n\tpatch", callAt, realPatch},
		{"empty argument list", "", callAt, ""},
		{"unbound identifier", "other", callAt, ""},
		{"non-identifier, non-literal argument", "42", callAt, ""},
		{"a call offset of zero admits no binding", "patch", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := PatchArgument(program, c.args, c.at); got != c.want {
				t.Errorf("PatchArgument(_, %q, %d) = %q, want %q", c.args, c.at, got, c.want)
			}
		})
	}
}

// TestStringBindingBounds pins the two edge cases of the `before` bound:
// a negative or over-long offset means "the whole program", not a panic
// and not an empty result.
func TestStringBindingBounds(t *testing.T) {
	t.Parallel()
	src := `const patch = ` + quoteJS(realPatch) + `;`
	for _, before := range []int{-1, len(src), len(src) + 1000} {
		if got := StringBinding(src, "patch", before); got != realPatch {
			t.Errorf("StringBinding(before=%d) = %q, want the real patch", before, got)
		}
	}
	if got := StringBinding(src, "missing", len(src)); got != "" {
		t.Errorf("StringBinding for an unbound identifier = %q, want empty", got)
	}
}

// TestStringField pins the object-literal field reader the Codex
// adapter uses for every non-patch inner call. Keys appear both bare and
// quoted in live programs, sometimes within one call, and a
// found-but-empty value must be distinguishable from a missing one —
// write_stdin polls with chars:"" in 513 of the 713 live rows.
func TestStringField(t *testing.T) {
	t.Parallel()
	const args = `{cmd:"sed -n '1,240p' PROGRESS.md","workdir":"/repo",` +
		`yield_time_ms:10000,chars:"",plan:[{step:"Read"}]}`
	cases := []struct {
		key    string
		want   string
		wantOK bool
	}{
		{"cmd", "sed -n '1,240p' PROGRESS.md", true},
		{"workdir", "/repo", true},
		{"chars", "", true},
		{"step", "Read", true},
		{"yield_time_ms", "", false},
		{"missing", "", false},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			t.Parallel()
			got, ok := StringField(args, c.key)
			if ok != c.wantOK {
				t.Fatalf("StringField(%q) ok = %v, want %v", c.key, ok, c.wantOK)
			}
			if got != c.want {
				t.Errorf("StringField(%q) = %q, want %q", c.key, got, c.want)
			}
		})
	}
}

// TestReadJSParenGroup pins the balanced-group reader the Codex adapter
// calls to slice a tool call's raw argument list. A parenthesis inside a
// string literal must never close the group, and a truncated group must
// yield honest partial source rather than panicking.
func TestReadJSParenGroup(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"simple group", `f({cmd:"x"})`, `{cmd:"x"}`},
		{"nested groups", `f(g(1), h(2))`, `g(1), h(2)`},
		{"a paren inside a literal does not close", `f("a) b")`, `"a) b"`},
		{"a comment inside the group", "f(/* ) */ 1)", "/* ) */ 1"},
		{"truncated group yields the remainder", `f({cmd:"x"`, `{cmd:"x"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, end := ReadJSParenGroup(c.src, strings.IndexByte(c.src, '('))
			if got != c.want {
				t.Errorf("group = %q, want %q", got, c.want)
			}
			if end > len(c.src) {
				t.Errorf("end = %d past len(src) = %d", end, len(c.src))
			}
		})
	}
}

// TestJSLexerPrimitives pins the small exported predicates the Codex
// adapter's own scanner branches on. Whole-token matching is what keeps
// `ALL_TOOLS` from reading as the `tools` dispatcher.
func TestJSLexerPrimitives(t *testing.T) {
	t.Parallel()
	for _, c := range []byte{'"', '\'', '`'} {
		if !IsJSQuote(c) {
			t.Errorf("IsJSQuote(%q) = false", c)
		}
	}
	for _, c := range []byte{'a', ' ', '\\', '0'} {
		if IsJSQuote(c) {
			t.Errorf("IsJSQuote(%q) = true", c)
		}
	}
	for _, c := range []byte{'a', 'Z', '_', '$', '7'} {
		if !IsJSIdentByte(c) {
			t.Errorf("IsJSIdentByte(%q) = false", c)
		}
	}
	for _, c := range []byte{'.', ' ', '-', '('} {
		if IsJSIdentByte(c) {
			t.Errorf("IsJSIdentByte(%q) = true", c)
		}
	}
	if name, end := ReadJSIdent("apply_patch(x)", 0); name != "apply_patch" || end != 11 {
		t.Errorf("ReadJSIdent = (%q, %d), want (apply_patch, 11)", name, end)
	}
	if name, end := ReadJSIdent("(x)", 0); name != "" || end != 0 {
		t.Errorf("ReadJSIdent at a non-ident = (%q, %d), want (\"\", 0)", name, end)
	}
	if got := SkipJSSpace("  \t\r\nx", 0); got != 5 {
		t.Errorf("SkipJSSpace = %d, want 5", got)
	}
	if got := SkipJSString(`"ab\"c" tail`, 0); got != 7 {
		t.Errorf("SkipJSString = %d, want 7", got)
	}
	if got := SkipJSString(`"unterminated`, 0); got != len(`"unterminated`) {
		t.Errorf("SkipJSString over an unterminated literal = %d, want end of source", got)
	}
}
