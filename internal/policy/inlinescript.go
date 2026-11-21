package policy

import (
	"regexp"
	"strings"
)

// Inline-script path operands (T-317).
//
// A live probe showed the gap this closes: after the guard asked on a
// `read` of a secret-shaped file, the model read the same file with
// `python3 -c "open('fake.pem').read()"`, and no rule classified it.
// The shell rows of R-152/R-153 scan a unit's POSITIONALS, and an
// interpreter one-liner carries its path inside the program text,
// which the parser keeps opaque on purpose (gap F1: the payload is
// exposed, never pretended-understood).
//
// This file does NOT parse Python/JS/Ruby/Perl/PHP/AppleScript. It is
// a conservative operand EXTRACTOR: it lifts the quoted string
// literals out of the program text an interpreter receives, keeps the
// ones that can name a file, and hands them to the SAME path
// classifiers the read/secret rules already use (sensitivePathPatterns
// for R-152, the secret-basename set for R-153). The rule fires only
// when an extracted literal hits one of those sets; a script with no
// such literal, or whose path is built at run time (a variable,
// concatenation, an environment lookup), does not fire on its own.
// That residual is documented in docs/guard.md ("What the guard does
// NOT do").
//
// The program text comes from four places, all data-driven:
//
//  1. a one-liner flag / subcommand from the interpreters table
//     (python -c, node -e/-p, ruby -e, perl -e/-ne, php -r,
//     deno eval, bun -e, osascript -e);
//  2. a heredoc on the interpreter unit itself (`python3 - <<EOF`);
//  3. the previous pipeline segment when it is a script feeder
//     (`echo CODE | node`, `cat <<EOF | python3`);
//  4. a .NET file-API static call in a PowerShell unit
//     (`[IO.File]::ReadAllText('...')`), the one PowerShell read
//     shape the parsed units cannot see (Get-Content, Copy-Item and
//     friends already reach R-152/R-153 as ordinary units).
//
// Deletes are classified separately (inlinedelete.go): a literal that
// is the target of a recognised delete call is a DELETE, judged by
// R-101's catastrophicDeleteTarget and by the write rows that protect
// sensitive paths, and is excluded from the read candidates here so a
// delete is never reported as a read.

// scriptFeederBases are the units whose arguments (or heredoc) become
// an interpreter's program when piped into it.
var scriptFeederBases = map[string]bool{
	"echo": true, "printf": true, "cat": true, "write-output": true,
}

// execCallees are the call names whose string argument is itself a
// shell command line, so its whitespace-separated words are operands
// in their own right (`os.system('cat .env')`, `execSync('cat .env')`,
// AppleScript `do shell script "cat ~/.ssh/id_rsa"`). Lowercased; the
// receiver (`os.`, `child_process.`) is ignored.
var execCallees = map[string]bool{
	"system": true, "popen": true, "run": true, "call": true,
	"check_call": true, "check_output": true, "getoutput": true,
	"getstatusoutput": true, "exec": true, "execsync": true,
	"spawn": true, "spawnsync": true, "shell_exec": true,
	"passthru": true, "proc_open": true, "script": true, "qx": true,
}

// psFileStaticCall matches a .NET file-API static call in a PowerShell
// unit's text and captures its argument list. Only the methods that
// READ (or copy out) a file's content are listed; the lexer has
// already stripped the quotes (and may split the closing paren off
// into its own unit when an argument list has a space), so the
// operand is the first comma-separated argument and the ')' is not
// required.
var psFileStaticCall = regexp.MustCompile(`(?i)\[(?:system\.)?io\.file\]::(?:readalltext|readallbytes|readalllines|readlines|openread|opentext|open|copy)\s*\(([^)]*)`)

// inlineOperand is one path candidate extracted from program text.
type inlineOperand struct {
	text string // the candidate path, as written in the program
	kind string // the interpreter kind, for the verdict detail
}

// interpreterFor resolves a canonical base to its interpreter row,
// tolerating a version suffix (python3.12 -> python3 -> python,
// php8.2 -> php).
func interpreterFor(base string) (interpreterSpec, bool) {
	if spec, ok := interpreters[base]; ok {
		return spec, true
	}
	trimmed := strings.TrimRight(base, "0123456789.")
	if trimmed != base && trimmed != "" {
		if spec, ok := interpreters[trimmed]; ok {
			return spec, true
		}
	}
	return interpreterSpec{}, false
}

// inlineCode returns every program text a unit passes on its own
// command line, per its interpreter row: one-liner flag values (all of
// them; osascript takes -e repeatedly), clustered short flags ending
// in a program letter, the "--flag=VALUE" form, and a subcommand's
// first operand. A "--" ends option scanning.
func inlineCode(cmd *Command, spec interpreterSpec) []string {
	var out []string
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		if t == "--" {
			break
		}
		if spec.sub != "" && t == spec.sub {
			for j := i + 1; j < len(argv); j++ {
				if !strings.HasPrefix(argv[j], "-") {
					out = append(out, argv[j])
					break
				}
			}
			break
		}
		if v, ok := flagProgram(t, spec); ok {
			if v != "" {
				out = append(out, v)
				continue
			}
			if i+1 < len(argv) {
				out = append(out, argv[i+1])
				i++
			}
		}
	}
	return out
}

// flagProgram classifies one argv token against an interpreter row.
// ok reports the token introduces program text; a non-empty v is an
// embedded value ("--eval=CODE"), an empty v means the next token.
func flagProgram(t string, spec interpreterSpec) (v string, ok bool) {
	for _, f := range spec.flags {
		if t == f {
			return "", true
		}
		if strings.HasPrefix(f, "--") && strings.HasPrefix(t, f+"=") {
			return t[len(f)+1:], true
		}
	}
	// A short-flag cluster ending in a program letter (-ne, -lne, -Ic).
	if spec.cluster != "" && len(t) > 2 && t[0] == '-' && t[1] != '-' {
		for i := 1; i < len(t); i++ {
			c := t[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return "", false
			}
		}
		if strings.IndexByte(spec.cluster, t[len(t)-1]) >= 0 {
			return "", true
		}
	}
	return "", false
}

// unitIndex finds cmd's position in ctx.Cmds (the engine hands MatchCmd
// a pointer into that slice); -1 when it is not there.
func unitIndex(ctx *MatchContext, cmd *Command) int {
	for i := range ctx.Cmds {
		if &ctx.Cmds[i] == cmd {
			return i
		}
	}
	return -1
}

// pipedScript returns the program text fed to cmd through a pipe: the
// arguments (and heredoc) of the nearest earlier unit at the same depth
// when both are pipeline segments and that unit is a script feeder.
func pipedScript(ctx *MatchContext, cmd *Command) string {
	if !cmd.Pipeline {
		return ""
	}
	i := unitIndex(ctx, cmd)
	for j := i - 1; j >= 0; j-- {
		prev := &ctx.Cmds[j]
		if prev.Depth != cmd.Depth {
			continue
		}
		if !prev.Pipeline || !scriptFeederBases[prev.Base] {
			return ""
		}
		var parts []string
		if prev.Base != "cat" { // cat's operands are FILES, not program text
			for _, a := range prev.Args() {
				if !strings.HasPrefix(a, "-") {
					parts = append(parts, a)
				}
			}
		}
		if prev.Heredoc != "" {
			parts = append(parts, prev.Heredoc)
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// inlineOperands is the T-317 extractor: every path candidate a unit's
// inline program text names, from the four sources in the file
// comment. It is the ONE entry both inline-script rule rows call.
func inlineOperands(ctx *MatchContext, cmd *Command) []inlineOperand {
	var out []inlineOperand
	programs, kind := inlinePrograms(ctx, cmd)
	for _, p := range programs {
		for _, c := range scriptPathCandidates(p) {
			out = append(out, inlineOperand{text: c, kind: kind})
		}
	}
	if !strings.Contains(cmd.Raw, "]::") {
		return out // cheap pre-filter: every unit of every shell event passes here
	}
	for _, m := range psFileStaticCall.FindAllStringSubmatch(cmd.Raw, -1) {
		arg := m[1]
		if i := strings.IndexByte(arg, ','); i >= 0 {
			arg = arg[:i]
		}
		arg = strings.Trim(strings.TrimSpace(arg), `'"`)
		if arg != "" {
			out = append(out, inlineOperand{text: arg, kind: "powershell"})
		}
	}
	return out
}

// inlinePrograms returns every program text the unit hands to an
// interpreter (sources 1-3 in the file comment) and the interpreter
// kind; nil for a unit that is not an interpreter. Shared by the read
// extractor and the delete extractor (inlinedelete.go).
func inlinePrograms(ctx *MatchContext, cmd *Command) ([]string, string) {
	spec, ok := interpreterFor(cmd.Base)
	if !ok {
		return nil, ""
	}
	programs := inlineCode(cmd, spec)
	if spec.stdin {
		if cmd.Heredoc != "" {
			programs = append(programs, cmd.Heredoc)
		}
		if p := pipedScript(ctx, cmd); p != "" {
			programs = append(programs, p)
		}
	}
	return programs, spec.kind
}

// scriptLiteral is one quoted string literal lifted out of program
// text, with the call it is an argument of (lowercased, receiver
// dropped), whether it is itself a command line (backticks), its
// quote character and the byte offset of its opening quote.
type scriptLiteral struct {
	text   string
	callee string
	exec   bool
	quote  byte
	pos    int
}

// scriptLiterals lifts the quoted literals ('...', "...", `...`, and
// Python's triple-quoted forms) out of program text. Backslash escapes
// are honoured for finding the closing quote; \\ \' \" and \` are
// unescaped, every other backslash is kept (a Windows path written
// 'C:\Users\u\.ssh\id_rsa' survives intact).
func scriptLiterals(code string) []scriptLiteral {
	var out []scriptLiteral
	for i := 0; i < len(code); i++ {
		q := code[i]
		if q != '\'' && q != '"' && q != '`' {
			continue
		}
		start := i + 1
		closer := string(q)
		if q != '`' && strings.HasPrefix(code[i:], strings.Repeat(string(q), 3)) {
			closer = strings.Repeat(string(q), 3)
			start = i + 3
		}
		end := literalEnd(code, start, closer)
		if end < 0 {
			break // unterminated: nothing reliable after this point
		}
		out = append(out, scriptLiteral{
			text:   unescapeLiteral(code[start:end]),
			callee: calleeBefore(code, i),
			exec:   q == '`',
			quote:  q,
			pos:    i,
		})
		i = end + len(closer) - 1
	}
	return out
}

// literalEnd finds the index of closer at or after start, skipping
// backslash-escaped characters; -1 when unterminated.
func literalEnd(code string, start int, closer string) int {
	for j := start; j < len(code); j++ {
		if code[j] == '\\' {
			j++
			continue
		}
		if strings.HasPrefix(code[j:], closer) {
			return j
		}
	}
	return -1
}

// unescapeLiteral resolves the four escapes that change which
// characters a path literal contains.
func unescapeLiteral(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\\'\"`", s[i+1]) >= 0 {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// calleeBefore returns the lowercased name of the call a literal at
// position i is the first argument of: skip whitespace, at most one
// '(', whitespace again, then read the identifier and keep its last
// component (`os.remove` -> remove, `[IO.File]::Delete` -> delete).
// "" when the literal is not directly preceded by a name.
func calleeBefore(code string, i int) string {
	j := i - 1
	for j >= 0 && (code[j] == ' ' || code[j] == '\t') {
		j--
	}
	if j >= 0 && code[j] == '(' {
		j--
		for j >= 0 && (code[j] == ' ' || code[j] == '\t') {
			j--
		}
	}
	end := j + 1
	for j >= 0 && isIdentByte(code[j]) {
		j--
	}
	name := code[j+1 : end]
	if k := strings.LastIndexAny(name, ".:"); k >= 0 {
		name = name[k+1:]
	}
	return strings.ToLower(name)
}

// isIdentByte reports an identifier (or receiver-path) byte.
func isIdentByte(c byte) bool {
	return c == '_' || c == '.' || c == ':' || c == '$' ||
		c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// scriptPathCandidates turns program text into READ path candidates:
//
//   - a literal inside the target argument of a recognised delete call
//     is skipped (it is a delete, classified by inlinedelete.go);
//   - a literal that is a command line (backticks, or the argument of
//     an exec call) contributes each of its words;
//   - any other literal contributes itself when it can name a file: no
//     whitespace, or a whitespace-bearing literal that starts with a
//     path anchor ("~/Library/Application Support/...");
//   - URLs and bare extensions ('.pem' in an endswith filter) never
//     qualify.
func scriptPathCandidates(code string) []string {
	var out []string
	_, spans := scriptDeletes(code)
	for _, lit := range scriptLiterals(code) {
		if inSpans(lit.pos, spans) {
			continue
		}
		t := strings.TrimSpace(lit.text)
		if lit.exec || execCallees[lit.callee] {
			for _, w := range strings.Fields(t) {
				if w = strings.Trim(w, `'"`); pathCandidate(w) {
					out = append(out, w)
				}
			}
			continue
		}
		if strings.ContainsAny(t, " \t\r\n") && !pathAnchored(t) {
			continue
		}
		if pathCandidate(t) {
			out = append(out, t)
		}
	}
	return out
}

// pathCandidate is the shape filter applied before classification.
func pathCandidate(t string) bool {
	if t == "" || len(t) > 4096 || strings.Contains(t, "://") {
		return false
	}
	return !bareExtension(t)
}

// bareExtension reports a lone extension literal ('.pem', '.key'),
// the shape of a suffix filter rather than a file. A name the secret
// set lists literally ('.env') is a real file and stays a candidate.
func bareExtension(t string) bool {
	if len(t) < 2 || t[0] != '.' || strings.ContainsAny(t, `/\`) || strings.Count(t, ".") != 1 {
		return false
	}
	for _, name := range secretFileBasenames {
		if !strings.Contains(name, "*") && strings.EqualFold(name, t) {
			return false
		}
	}
	return true
}

// pathAnchored reports a literal that starts like a path: absolute,
// home-relative, explicitly relative, or a Windows drive / UNC path.
func pathAnchored(t string) bool {
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") || strings.HasPrefix(t, `\\`) ||
		strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../") {
		return true
	}
	if _, ok := splitHomePrefix(t); ok {
		return true
	}
	return len(t) > 2 && t[1] == ':' && (t[2] == '\\' || t[2] == '/')
}

// matchInlineScriptSensitive is the R-152 inline-script row: a literal
// in interpreter program text that resolves into the sensitive
// credential/profile set. Direction is not inferred from program text,
// so every hit is judged as a READ (the less-alarming direction, the
// same default actionIsWrite applies to an unknown verb).
//
// The interpreter starts in the directory its unit runs in, so a relative
// literal is judged from every anchor (unitPathCandidates, T-387): `cd
// ~/.aws && python3 -c "open('credentials').read()"`.
func matchInlineScriptSensitive(ctx *MatchContext, cmd *Command) (bool, string) {
	ops := inlineOperands(ctx, cmd)
	if len(ops) == 0 {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	for _, op := range ops {
		for _, c := range unitPathCandidates(ctx, anchors, op.text) {
			if desc, ok := homePathPatternMatch(ctx, c.path, sensitivePathPatterns); ok {
				return true, movedReason(desc+" ("+op.text+", named in a "+op.kind+" inline script)", c.moved)
			}
		}
	}
	return false, ""
}

// matchInlineScriptSecret is the R-153 inline-script row: a literal in
// interpreter program text whose basename is in the secret-file set
// and is not a placeholder (.env.example). Judged from every anchor like
// the sensitive row above.
func matchInlineScriptSecret(ctx *MatchContext, cmd *Command) (bool, string) {
	ops := inlineOperands(ctx, cmd)
	if len(ops) == 0 {
		return false, ""
	}
	anchors := unitAnchors(ctx, cmd)
	for _, op := range ops {
		for _, c := range unitPathCandidates(ctx, anchors, op.text) {
			name := baseName(c.path)
			if secretBasename(name) && !exampleBasename(name) {
				return true, movedReason("secret file "+op.text+" (named in a "+op.kind+" inline script)", c.moved)
			}
		}
	}
	return false, ""
}
