package policy

import (
	"regexp"
	"strings"
)

// Inline-script DELETES (T-317 follow-up, orchestrator ruling
// 2026-10-03).
//
// The read extractor (inlinescript.go) first skipped a literal passed
// to a delete call, so it would never be reported as a read. That left
// `python3 -c "import shutil; shutil.rmtree('/')"` judged by no rule at
// all. A delete target is now a DELETE: the recursive ones go through
// R-101's own catastrophicDeleteTarget (filesystem roots, the home
// directory in every spelling the shell rule knows, root-depth
// wildcards, the unresolved-variable arm) and its outside-the-project
// arm, and every delete target goes through the write rows that protect
// sensitive paths from `rm` (R-152 credentials, R-154 shell profiles,
// R-155 autostart paths, R-156 git hooks, R-160 observer config), with
// the same decisions those rows give the shell form. It is never a
// read.
//
// Like the read side this is a conservative operand extractor, not a
// parser. A delete call's target is taken only when its first argument
// is a string literal, or a literal wrapped in a known path-building
// call (`os.path.expanduser('~')`, `Path('~').expanduser()`,
// `File.expand_path('~')`). A target built at run time
// (`rmSync(process.env.HOME, ...)`, `os.path.join(base, 'x')`, an
// f-string, a template literal with ${...}) does not fire on its own:
// that residual is recorded in docs/guard.md.

// deleteRecursion says whether a delete call removes a whole tree.
type deleteRecursion int

const (
	// delOption removes a tree only when the call passes a recursive
	// option (`fs.rmSync(p, {recursive: true})`, Deno.removeSync).
	// Calls that have no such option (os.remove, unlink) never match
	// it, so they stay single-entry deletes.
	delOption deleteRecursion = iota
	// delTree always removes a tree (shutil.rmtree, FileUtils.rm_rf).
	delTree
)

// inlineDeleteCalls is the ONE table of delete calls the inline
// extractor recognises, keyed by the lowercased call name with the
// receiver dropped (`shutil.rmtree` -> rmtree, `fs.rmSync` -> rmsync,
// `FileUtils.rm_rf` -> rm_rf). No language switch: a name means the
// same thing wherever it appears.
var inlineDeleteCalls = map[string]deleteRecursion{
	// Python os / shutil / pathlib.
	"remove": delOption, "unlink": delOption, "rmdir": delOption,
	"removedirs": delOption, "rmtree": delTree,
	// Node / Deno / Bun.
	"unlinksync": delOption, "rm": delOption, "rmsync": delOption,
	"rmdirsync": delOption, "removesync": delOption, "rimraf": delTree,
	// Ruby File / FileUtils / Dir.
	"delete": delOption, "rm_f": delOption, "rm_r": delTree,
	"rm_rf": delTree, "remove_dir": delTree, "remove_entry": delTree,
	"remove_entry_secure": delTree,
	// Perl File::Path.
	"remove_tree": delTree,
	// Generic Windows-API spelling.
	"deletefile": delOption,
}

// pathWrapperCalls build a path from their first argument without
// changing which file it names; a literal inside one is still the
// delete target.
var pathWrapperCalls = map[string]bool{
	"expanduser": true, "expandvars": true, "abspath": true,
	"realpath": true, "normpath": true, "path": true, "purepath": true,
	"resolve": true, "expand_path": true, "absolute_path": true,
	"pathname": true, "fspath": true, "str": true,
}

// recursiveOption is a call's recursive flag (`{recursive: true}`,
// `recursive=True`).
var recursiveOption = regexp.MustCompile(`(?i)recursive\s*[:=]\s*true`)

// methodChain is what may follow a wrapper call: zero-argument method
// calls only (`.expanduser()`, `.resolve()`).
var methodChain = regexp.MustCompile(`^(\s*\.\s*[A-Za-z_]\w*\s*\(\s*\))*$`)

// psDeleteStaticCall is the PowerShell .NET delete shape the parsed
// units cannot see (Remove-Item already reaches R-101 as an ordinary
// unit): `[IO.File]::Delete(p)` and `[IO.Directory]::Delete(p, $true)`.
var psDeleteStaticCall = regexp.MustCompile(`(?i)\[(?:system\.)?io\.(file|directory)\]::delete\s*\(([^)]*)`)

// deleteCall is one recognised delete call in program text. target is
// "" when the argument is built at run time.
type deleteCall struct {
	target    string
	quote     byte
	recursive bool
}

// inlineDeleteTarget is one delete target ready for classification.
type inlineDeleteTarget struct {
	text      string
	kind      string
	recursive bool
	lit       []int // offsets of '$' that are literal text, not expansion
	dialect   Dialect
}

// scriptDeletes finds the recognised delete calls in program text and
// the byte spans of their argument lists (the read extractor skips
// every literal inside one).
func scriptDeletes(code string) ([]deleteCall, [][2]int) {
	var calls []deleteCall
	var spans [][2]int
	for i := 0; i < len(code); {
		c := code[i]
		if c == '\'' || c == '"' || c == '`' {
			_, _, after, ok := literalAt(code, i)
			if !ok {
				break
			}
			i = after
			continue
		}
		if !isIdentByte(c) || (i > 0 && isIdentByte(code[i-1])) {
			i++
			continue
		}
		j := i
		for j < len(code) && isIdentByte(code[j]) {
			j++
		}
		rec, ok := inlineDeleteCalls[lastComponent(code[i:j])]
		if !ok {
			i = j
			continue
		}
		dc, span, found := deleteCallAt(code, j, rec)
		if !found {
			i = j
			continue
		}
		calls = append(calls, dc)
		spans = append(spans, span)
		i = span[1]
	}
	return calls, spans
}

// deleteCallAt reads the argument of a delete call whose name ends at
// j: a parenthesised argument list, or (Perl/Ruby) one bare literal.
func deleteCallAt(code string, j int, rec deleteRecursion) (deleteCall, [2]int, bool) {
	k := j
	for k < len(code) && (code[k] == ' ' || code[k] == '\t') {
		k++
	}
	if k >= len(code) {
		return deleteCall{}, [2]int{}, false
	}
	switch code[k] {
	case '(':
		end := matchParen(code, k)
		args := code[k+1 : end]
		dc := deleteCall{recursive: rec == delTree || recursiveOption.MatchString(args)}
		dc.target, dc.quote, _ = pathArgLiteral(firstTopLevelArg(args))
		return dc, [2]int{k, minInt(end+1, len(code))}, true
	case '\'', '"':
		start, end, after, ok := literalAt(code, k)
		if !ok {
			return deleteCall{}, [2]int{}, false
		}
		return deleteCall{
			target: unescapeLiteral(code[start:end]), quote: code[k],
			recursive: rec == delTree,
		}, [2]int{k, after}, true
	}
	return deleteCall{}, [2]int{}, false
}

// pathArgLiteral resolves a delete call's first argument to the literal
// path it names: a string literal, or one wrapped in path-building
// calls. ok is false for anything built at run time.
func pathArgLiteral(arg string) (string, byte, bool) {
	for depth := 0; depth < 4; depth++ {
		arg = strings.TrimSpace(arg)
		if len(arg) < 2 {
			return "", 0, false
		}
		// Python string prefixes: raw/bytes/unicode are still literals,
		// an f-string is built at run time.
		if q := arg[1]; q == '\'' || q == '"' {
			switch arg[0] {
			case 'r', 'R', 'b', 'B', 'u', 'U':
				arg = arg[1:]
			case 'f', 'F':
				return "", 0, false
			}
		}
		if q := arg[0]; q == '\'' || q == '"' || q == '`' {
			start, end, after, ok := literalAt(arg, 0)
			if !ok || after != len(arg) {
				return "", 0, false
			}
			text := unescapeLiteral(arg[start:end])
			if q == '`' && strings.Contains(text, "${") {
				return "", 0, false
			}
			return text, q, true
		}
		j := 0
		for j < len(arg) && isIdentByte(arg[j]) {
			j++
		}
		if j == 0 || j >= len(arg) || arg[j] != '(' || !pathWrapperCalls[lastComponent(arg[:j])] {
			return "", 0, false
		}
		end := matchParen(arg, j)
		if end >= len(arg) || !methodChain.MatchString(arg[end+1:]) {
			return "", 0, false
		}
		arg = firstTopLevelArg(arg[j+1 : end])
	}
	return "", 0, false
}

// literalAt reads the string literal whose opening quote is at i
// (Python triple quotes included): the text span and the index just
// past the closing quote.
func literalAt(code string, i int) (start, end, after int, ok bool) {
	q := code[i]
	closer := string(q)
	start = i + 1
	if q != '`' && strings.HasPrefix(code[i:], strings.Repeat(string(q), 3)) {
		closer = strings.Repeat(string(q), 3)
		start = i + 3
	}
	end = literalEnd(code, start, closer)
	if end < 0 {
		return 0, 0, 0, false
	}
	return start, end, end + len(closer), true
}

// matchParen returns the index of the ')' closing the '(' at open,
// skipping string literals; len(code) when unbalanced.
func matchParen(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '\'', '"', '`':
			_, _, after, ok := literalAt(code, i)
			if !ok {
				return len(code)
			}
			i = after - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(code)
}

// firstTopLevelArg cuts an argument list at its first top-level comma.
func firstTopLevelArg(args string) string {
	depth := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case '\'', '"', '`':
			_, _, after, ok := literalAt(args, i)
			if !ok {
				return args
			}
			i = after - 1
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				return args[:i]
			}
		}
	}
	return args
}

// lastComponent lowercases an identifier path and keeps its last
// component (`shutil.rmtree` -> rmtree, `[IO.File]::Delete` -> delete).
func lastComponent(name string) string {
	if k := strings.LastIndexAny(name, ".:"); k >= 0 {
		name = name[k+1:]
	}
	return strings.ToLower(name)
}

// inSpans reports whether pos falls inside any [start, end) span.
func inSpans(pos int, spans [][2]int) bool {
	for _, s := range spans {
		if pos >= s[0] && pos < s[1] {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// literalDollars marks every '$' in a literal as literal text, except
// where the language interpolates it (a double-quoted Perl or PHP
// string), so R-101's unresolved-variable arm judges only real
// expansions.
func literalDollars(text string, quote byte, kind string) []int {
	if quote == '"' && (kind == "perl" || kind == "php") {
		return nil
	}
	var lit []int
	for i := 0; i < len(text); i++ {
		if text[i] == '$' {
			lit = append(lit, i)
		}
	}
	if lit == nil {
		return []int{}
	}
	return lit
}

// inlineDeleteTargets is the ONE entry both delete row families call:
// every delete target a unit's inline program text names, plus the
// PowerShell .NET delete calls in its own text.
func inlineDeleteTargets(ctx *MatchContext, cmd *Command) []inlineDeleteTarget {
	var out []inlineDeleteTarget
	programs, kind := inlinePrograms(ctx, cmd)
	for _, p := range programs {
		calls, _ := scriptDeletes(p)
		for _, dc := range calls {
			if dc.target == "" {
				continue
			}
			out = append(out, inlineDeleteTarget{
				text: dc.target, kind: kind, recursive: dc.recursive,
				lit: literalDollars(dc.target, dc.quote, kind), dialect: DialectPosix,
			})
		}
	}
	if !strings.Contains(cmd.Raw, "]::") {
		return out
	}
	for _, m := range psDeleteStaticCall.FindAllStringSubmatch(cmd.Raw, -1) {
		args := strings.Split(m[2], ",")
		target := strings.Trim(strings.TrimSpace(args[0]), `'"`)
		if target == "" {
			continue
		}
		recursive := strings.EqualFold(m[1], "directory") && len(args) > 1 &&
			(strings.EqualFold(strings.TrimSpace(args[1]), "$true") || strings.EqualFold(strings.TrimSpace(args[1]), "true"))
		out = append(out, inlineDeleteTarget{text: target, kind: "powershell", recursive: recursive, dialect: DialectPowerShell})
	}
	return out
}

// matchInlineDeleteCatastrophic is R-101's inline-script row: a
// RECURSIVE delete call whose literal target is a filesystem root, the
// home directory, a root-depth wildcard (catastrophicDeleteTarget, never
// exempt) or resolves outside the project (exempt under
// [guard.boundary].allow_paths, exactly like the shell row's safe
// pattern). The interpreter starts in the directory the unit runs in, so
// each target is judged from every anchor (cwdtrack.go, pass-2 M2-01:
// `cd ~ && python -c "shutil.rmtree('.')"`).
func matchInlineDeleteCatastrophic(ctx *MatchContext, cmd *Command) (bool, string) {
	return matchInlineDeleteTier(ctx, cmd, tierDeny)
}

// matchInlineDeleteTier reports the first recursive inline delete target
// whose classification from some anchor is exactly tier (tierDeny for
// R-101's inline row, tierAsk for R-102's unresolved-directory row).
func matchInlineDeleteTier(ctx *MatchContext, cmd *Command, tier deleteTier) (bool, string) {
	targets := inlineDeleteTargets(ctx, cmd)
	if len(targets) == 0 {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	for _, t := range targets {
		if !t.recursive {
			continue
		}
		op := operand{text: t.text, lit: t.lit}
		for _, a := range anchors {
			if got, why := dangerousDeleteTarget(ctx, op, t.dialect, a, true); got == tier {
				return true, anchorReason(a, why) + " (" + t.kind + " inline delete)"
			}
		}
	}
	return false, ""
}

// inlineDeletePathMatch builds the inline-delete row for a protected
// path table: any delete call (recursive or not) whose literal target
// is in the table, the inline mirror of shPathMatch(pats, true), which
// classifies `rm <path>` as a write.
func inlineDeletePathMatch(pats []pathPattern) MatchCmdFn {
	return func(ctx *MatchContext, cmd *Command) (bool, string) {
		targets := inlineDeleteTargets(ctx, cmd)
		if len(targets) == 0 {
			return false, ""
		}
		// The interpreter runs in the unit's directory: judge each literal
		// from every anchor (T-387), as the R-101 inline row does.
		anchors := unitAnchors(ctx, cmd)
		for _, t := range targets {
			for _, c := range unitPathCandidates(ctx, anchors, t.text) {
				if desc, ok := homePathPatternMatch(ctx, c.path, pats); ok {
					return true, movedReason(desc+" ("+t.text+", deleted by a "+t.kind+" inline script)", c.moved)
				}
			}
		}
		return false, ""
	}
}
