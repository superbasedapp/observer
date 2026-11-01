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
}

// psHereBody is the substitution pass over a here-string body: apostrophes
// are text there, so they must not open a quote that hides a later
// substitution. A single-quoted body does not expand in PowerShell; its
// substitutions are still stripped and analysed (more, never less), which
// keeps this pass from depending on where the lexer thinks a quote is.
func psHereBody(body string, o stripOpts) (string, []string, bool) {
	o.noSingle = true
	return stripSubstitutionsOpts(body, o)
}
