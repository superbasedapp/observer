package policy

import "strings"

// psblock.go: PowerShell script blocks passed as arguments (T-388, the
// D-279 follow-up; docs/security.md GUARD-PSBLOCK-1), and the verdict
// calibration the operator ruled on them (T-525, D-338).
//
// THE GAP. A PowerShell script block is code a cmdlet runs:
//
//	Get-ChildItem | ForEach-Object { Remove-Item -Recurse -Force ~ }
//	1..3 | % { rm -r -fo ~ }
//	Invoke-Command -ScriptBlock { schtasks /Create ... }
//	Start-Job { Remove-Item -Recurse -Force ~ }
//
// The lexer reads `{` as an ordinary word, so the block became arguments
// of the cmdlet receiving it and no rule saw the command inside. A block
// that OPENS a unit (`& { ... }`, `if (...) { ... }`) was already
// analysed: the call operator and the parentheses are unit separators
// and leadingKeywords strips the `{`. docs/security.md H5b recorded
// `Invoke-Command -ScriptBlock` / `Start-Job -ScriptBlock` as a residual.
//
// THE FIX. Every PowerShell unit's arguments are scanned for a word that
// opens a block (starts with an unquoted `{`); the text up to its
// matching unquoted `}` is collected by brace depth across words and
// parsed as a nested PowerShell payload through unwrapPayload, the seam
// `powershell -Command` and Invoke-Expression already use, so the depth
// limit, the shared expansion budget and R-157's fail-closed signal apply
// unchanged. Every block is analysed, whichever cmdlet receives it and
// whether or not it runs: a filter block (`Where-Object { $_.Length -gt 1
// }`) parses into words no rule matches, and analysing a block that never
// runs errs toward analysing more, the direction this package takes
// everywhere.
//
// THE RULING (D-338, applied exactly):
//
//   - A brace inside a string literal is text, not a block. The lexer
//     records the braces it read from a quoted or escaped region
//     (ptoken.qbr, carried to Command.argvQuotedBraces), so
//     `Write-Output '{ rm -r ~ }'` and its double-quoted twin open no
//     block, and a quoted brace inside a real block neither opens nor
//     closes one. When a block body is re-parsed, every character the
//     lexer read as literal (a quoted brace, a single-quoted or escaped
//     `$`/`%`/backtick) is re-emitted inside single quotes (not behind a
//     backtick, which parseDepth strips as a substitution span), so the
//     nested parse sees the same literal facts the outer one did
//     (`% { Write-Output '{ rm -r ~ }' }` stays text, `% { Remove-Item
//     '$_' -Recurse }` names a directory called `$_`).
//   - A recursive delete whose target is the bare pipeline variable (`$_`,
//     or its alias `$PSItem`) of the script block it sits in is R-101's
//     ASK row, not its DENY row: the item is whatever the pipeline hands
//     the block, usually a child of a listing the agent chose, and the
//     guard cannot see it. Command.inScriptBlock marks the units parsed
//     directly from a block body; the same bare variable outside a block
//     keeps R-101's unexpanded-variable DENY, and `$_.FullName` resolves
//     as it always did.
//   - A function definition (`function NAME { ... }`, `filter NAME { ...
//     }`, also with the brace glued to the name) whose body nothing in the
//     line calls only defines the body: every verdict drawn from the body
//     is capped at ASK (Command.uncalledDef, applied in engine.go). A call
//     anywhere in the line (`function f { ... }; f`, `ls | f`) that is not
//     itself inside an uncalled definition lets the body's own verdict
//     stand (settleDefinitions).
//
// T-534 closed three residuals of that first cut:
//
//   - A parameter list written in parentheses after the name was misread:
//     spaced (`function f ($x) { ... }`) it was split off at the lexer, so
//     the body became an ordinary unit with no definition around it;
//     glued (`function f($x) { ... }`) it became part of the name `f($x)`,
//     so no call ever matched and a CALLED definition was capped at ASK.
//     blankPSDefinitionParams
//     blanks the list's own two parentheses before lexing (its words stay
//     arguments of the definition unit), so the body is a definition body
//     like `function f { ... }`. A list holding a nested unquoted
//     parenthesis (a default value that is an expression) is left as it
//     was: its inner units are still analysed, and the body keeps the
//     ordinary-unit verdict it had before T-388.
//   - A whitespace, separator or quote character inside one block word
//     can only have come from a quoted or escaped region (the lexer splits
//     on the unquoted ones), so it is re-emitted quoted too: a quoted `;`
//     no longer splits the re-parsed body (`% { Write-Output 'a; rm -r
//     ~' }` stays text).
//   - Escaped braces (`Write-Output `{ rm -r ~ `}`) are text: the
//     substitution strip no longer reads a backtick before a brace as a
//     span delimiter under PowerShell (parseDepth), so the lexer sees the
//     escaped braces, which it marks quoted. Other backtick spans are
//     still stripped as substitutions in every dialect (fail closed).
//
// Approximations (pinned by tests): a `;`, `|`, `&&`, `||`, `(` or `)`
// inside a block already split the line into units at the lexer, so the
// block text ends there and the statements after it are analysed as the
// ordinary units they already were. A block runs in the caller's
// runspace, so a directory change inside it moves the shell (`% {
// Set-Location ~ }; Remove-Item -Recurse *`): cwdtrack.go treats a unit
// carrying a block like an evaluator and makes the frame opaque when the
// block changes directories or creates links.

// psDefinitionKeywords are the PowerShell keywords that define a named
// function whose body is the script block after the name.
var psDefinitionKeywords = setOf("function", "filter")

// psDotSource is the dot-source operator, which runs a named function in
// the caller's scope (`. f`). The call operator `&` is a unit separator at
// the lexer, so `& f` already arrives as a unit whose command word is f.
const psDotSource = "."

// psPipelineItems are the spellings (lowercase) of the automatic variable
// that holds the current pipeline item inside a script block.
var psPipelineItems = setOf("$_", "$psitem")

// isPipelineItem reports whether word is the bare pipeline variable, read
// unquoted (a single-quoted `'$_'` names a file called $_).
func isPipelineItem(word string, lit []int) bool {
	if !psPipelineItems[strings.ToLower(word)] {
		return false
	}
	for _, o := range lit {
		if o == 0 {
			return false
		}
	}
	return true
}

// hasOffset reports whether offs (one word's offset list) holds o.
func hasOffset(offs []int, o int) bool {
	for _, x := range offs {
		if x == o {
			return true
		}
	}
	return false
}

// wordOffsets returns word i's entry of a per-word offset list, nil when
// the list does not run parallel to the words.
func wordOffsets(list [][]int, n, i int) []int {
	if len(list) != n {
		return nil
	}
	return list[i]
}

// psRequote reports whether a character inside one lexed word must be
// re-emitted quoted when a block body is re-parsed: whitespace, a unit
// separator or redirect, or a quote. Inside a single word each of these
// was read from a quoted or escaped region (the lexer splits on, or
// consumes, the unquoted ones), so re-emitting it bare would change the
// re-parse (T-534).
func psRequote(c byte) bool {
	return strings.IndexByte(" \t\r\n;|&<>()'\"", c) >= 0
}

// psQuoteByte writes c so the PowerShell lexer reads it back as one
// literal character: inside single quotes, or, for a single quote itself,
// inside double quotes.
func psQuoteByte(b *strings.Builder, c byte) {
	q := byte('\'')
	if c == '\'' {
		q = '"'
	}
	b.WriteByte(q)
	b.WriteByte(c)
	b.WriteByte(q)
}

// psScriptBlocks returns the body text of every script block among a
// PowerShell unit's arguments, outermost blocks only (a nested block is
// found when its parent's body is parsed). lits and qbr run parallel to
// argv (Command.ArgvLiterals, Command.argvQuotedBraces) and may be nil: a
// quoted brace never opens, closes or nests a block, and every literal
// character is re-emitted escaped in the body. An unclosed block runs to
// the end of the unit.
func psScriptBlocks(argv []string, lits, qbr [][]int) []string {
	return psScriptBlocksLost(argv, lits, qbr, nil)
}

// psScriptBlocksLost is psScriptBlocks for a unit whose argv holds words
// that were nothing but a command substitution (Command.lostArgs, NF-2):
// each such word is re-emitted as a substitution marker, so the nested
// parse of the block records the same lost word the outer parse did
// (`% { Remove-Item -Recurse (Join-Path $HOME $_) }` is R-102's
// substituted-operand ask, not a delete with no target).
func psScriptBlocksLost(argv []string, lits, qbr [][]int, lost map[int]bool) []string {
	n := len(argv)
	var out []string
	for i := 1; i < n; i++ {
		if !strings.HasPrefix(argv[i], "{") || hasOffset(wordOffsets(qbr, n, i), 0) {
			continue
		}
		var b strings.Builder
		depth, j, closed := 0, i, false
		for ; j < n && !closed; j++ {
			w := argv[j]
			wl, wq := wordOffsets(lits, n, j), wordOffsets(qbr, n, j)
			if j > i {
				b.WriteByte(' ')
			}
			if lost[j] {
				b.WriteByte(subMarker)
				continue
			}
			for k := 0; k < len(w); k++ {
				c := w[k]
				quoted := hasOffset(wq, k)
				switch {
				case c == '{' && !quoted:
					depth++
					if j == i && k == 0 {
						continue // the block's own opening brace
					}
				case c == '}' && !quoted:
					depth--
					if depth == 0 {
						closed = true
					}
				}
				if closed {
					break
				}
				if quoted || hasOffset(wl, k) || psRequote(c) {
					// Re-quoted: the nested parse reads the same literal
					// character the outer lexer did.
					psQuoteByte(&b, c)
					continue
				}
				b.WriteByte(c)
			}
		}
		if body := strings.TrimSpace(b.String()); body != "" {
			out = append(out, body)
		}
		i = j - 1
	}
	return out
}

// splitGluedDefinition splits a definition whose block is glued to the
// name (`function f{rm -r ~}` lexes as `function`, `f{rm`, ...) into the
// name word and a word that opens the block, keeping the per-word offset
// lists aligned. Any other argv is returned unchanged.
func splitGluedDefinition(argv []string, lits, qbr [][]int) ([]string, [][]int, [][]int) {
	n := len(argv)
	if n < 2 {
		return argv, lits, qbr
	}
	w, wq := argv[1], wordOffsets(qbr, n, 1)
	p := -1
	for k := 1; k < len(w); k++ {
		if w[k] == '{' && !hasOffset(wq, k) {
			p = k
			break
		}
	}
	if p < 0 {
		return argv, lits, qbr
	}
	split := func(offs []int) (head, tail []int) {
		for _, o := range offs {
			if o < p {
				head = append(head, o)
			} else {
				tail = append(tail, o-p)
			}
		}
		return head, tail
	}
	na := append([]string{argv[0], w[:p], w[p:]}, argv[2:]...)
	realign := func(list [][]int) [][]int {
		if len(list) != n {
			return nil
		}
		h, t := split(list[1])
		return append([][]int{list[0], h, t}, list[2:]...)
	}
	return na, realign(lits), realign(qbr)
}

// unwrapScriptBlocks parses every script-block argument of a PowerShell
// unit as a nested PowerShell payload and marks the unit as carrying one.
// The units parsed directly from a block body are marked inScriptBlock,
// and every unit nested in a function definition's body records the
// function's name (defIn) for settleDefinitions. Any other dialect is
// untouched: `find . -exec rm {} \;` has a `{}` word that is not code.
func unwrapScriptBlocks(cmd *Command, st parseState) []Command {
	if cmd.Dialect != DialectPowerShell {
		return nil
	}
	argv, lits, qbr := cmd.Argv, cmd.ArgvLiterals, cmd.argvQuotedBraces
	lost := make(map[int]bool, len(cmd.lostArgs))
	for _, i := range cmd.lostArgs {
		lost[i] = true
	}
	name := ""
	if psDefinitionKeywords[cmd.Base] && len(argv) > 1 {
		n := len(argv)
		argv, lits, qbr = splitGluedDefinition(argv, lits, qbr)
		if len(argv) > n {
			// argv[1] was split in two: every later word moved up one.
			moved := make(map[int]bool, len(lost))
			for i := range lost {
				if i >= 2 {
					i++
				}
				moved[i] = true
			}
			lost = moved
		}
		name = canonicalBase(argv[1], DialectPowerShell)
	}
	blocks := psScriptBlocksLost(argv, lits, qbr, lost)
	if len(blocks) == 0 {
		return nil
	}
	cmd.scriptBlock = true
	var out []Command
	for _, body := range blocks {
		nested := unwrapPayload(cmd, body, DialectPowerShell, "powershell", st)
		for i := range nested {
			if nested[i].Depth == st.depth+1 {
				nested[i].inScriptBlock = true
			}
			if name != "" {
				nested[i].defIn = append(nested[i].defIn, name)
			}
		}
		out = append(out, nested...)
	}
	return out
}

// psWordBoundary reports whether c ends the word before it, for the
// definition-keyword scan.
func psWordBoundary(c byte) bool {
	return strings.IndexByte(" \t\r\n;|&{}()", c) >= 0
}

// blankPSDefinitionParams blanks the two parentheses of a parenthesised
// parameter list in a PowerShell function definition (`function f($x) {`,
// `filter f ($a, $b) {`) so the lexer keeps the definition one unit and
// its block a definition body (T-534). Only a list followed by a `{` and
// holding no nested unquoted parenthesis is touched; quotes and backtick
// escapes are honoured; every other byte is unchanged, so the parameter
// words are still the definition unit's arguments.
func blankPSDefinitionParams(s string) string {
	low := strings.ToLower(s)
	if !strings.Contains(low, "function") && !strings.Contains(low, "filter") {
		return s
	}
	b := []byte(s)
	inS, inD := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
			continue
		case c == '`':
			i++
			continue
		case inD:
			if c == '"' {
				inD = false
			}
			continue
		case c == '\'':
			inS = true
			continue
		case c == '"':
			inD = true
			continue
		}
		if i > 0 && !psWordBoundary(b[i-1]) {
			continue
		}
		for kw := range psDefinitionKeywords {
			n := len(kw)
			if i+n >= len(b) || !strings.EqualFold(string(b[i:i+n]), kw) || (b[i+n] != ' ' && b[i+n] != '\t') {
				continue
			}
			if open, closing, ok := psParamList(b, i+n); ok {
				b[open], b[closing] = ' ', ' '
				i = closing
			}
		}
	}
	return string(b)
}

// psParamList finds the parameter list of a definition whose keyword ends
// at k: blanks, a name, optional blanks, `(`, a list with no nested
// unquoted parenthesis, `)`, optional blanks, `{`. It returns the offsets
// of the two parentheses.
func psParamList(b []byte, k int) (open, closing int, ok bool) {
	skip := func(j int) int {
		for j < len(b) && (b[j] == ' ' || b[j] == '\t') {
			j++
		}
		return j
	}
	j := skip(k)
	start := j
	for j < len(b) && strings.IndexByte(" \t\r\n;|&{}()'\"`", b[j]) < 0 {
		j++
	}
	if j == start {
		return 0, 0, false
	}
	j = skip(j)
	if j >= len(b) || b[j] != '(' {
		return 0, 0, false
	}
	open = j
	inS, inD := false, false
	for j = open + 1; j < len(b); j++ {
		c := b[j]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case c == '`':
			j++
		case inD:
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '(':
			return 0, 0, false
		case c == ')':
			e := skip(j + 1)
			if e < len(b) && b[e] == '{' {
				return open, j, true
			}
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// psCalledName is the function name a PowerShell unit invokes: its
// command word, or the operand of a dot-source. "" for other dialects.
func psCalledName(c *Command) string {
	if c.Dialect != DialectPowerShell {
		return ""
	}
	if c.Base == psDotSource {
		if len(c.Argv) < 2 {
			return ""
		}
		return canonicalBase(c.Argv[1], DialectPowerShell)
	}
	return c.Base
}

// settleDefinitions marks the units of every function body that nothing
// in the command line calls (Command.uncalledDef). A function is called
// when some unit invokes its name from outside its own body, and that
// unit itself runs: it sits in no definition, or only in definitions that
// are called. The called set is a fixed point, so `function f {...};
// function g { f }` leaves f uncalled until the line also calls g.
func settleDefinitions(cmds []Command) []Command {
	defined := map[string]bool{}
	for i := range cmds {
		for _, n := range cmds[i].defIn {
			defined[n] = true
		}
	}
	if len(defined) == 0 {
		return cmds
	}
	called := map[string]bool{}
	runs := func(c *Command) bool {
		for _, n := range c.defIn {
			if !called[n] {
				return false
			}
		}
		return true
	}
	for changed := true; changed; {
		changed = false
		for i := range cmds {
			c := &cmds[i]
			n := psCalledName(c)
			if !defined[n] || called[n] || containsString(c.defIn, n) || !runs(c) {
				continue
			}
			called[n] = true
			changed = true
		}
	}
	for i := range cmds {
		cmds[i].uncalledDef = ""
		for _, n := range cmds[i].defIn {
			if !called[n] {
				cmds[i].uncalledDef = n
				break
			}
		}
	}
	return cmds
}

// containsString reports whether list holds s.
func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
