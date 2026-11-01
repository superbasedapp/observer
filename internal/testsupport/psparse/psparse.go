// Package psparse is a test helper: a strict reader of the one command
// shape Observer writes for a host that runs a hook command string through
// `powershell.exe -NoProfile -Command "<command>"` (Codex on Windows,
// FU-162). It accepts a command PowerShell parses as ONE native command
// invocation and returns that invocation's argv; it refuses anything
// PowerShell would read differently from the literal text.
//
// Accepted: an optional leading call operator `&`; then words separated by
// spaces, each one bare (no character PowerShell treats specially), a
// single-quoted literal (” is a quote inside it), or a double-quoted string
// with no `$`, backtick or double quote inside. A command that starts with a
// quoted word and no call operator is refused: PowerShell reads it as a
// string expression, not a program to run.
package psparse

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// bareSpecial are the characters PowerShell reads specially in an unquoted
// command-mode word: statement and pipeline separators, grouping, variables,
// the escape character, redirection, splatting, comments, the array
// operator, and the quote characters (ASCII and the typographic ones
// PowerShell also accepts).
const bareSpecial = ";|&(){}$`<>@#,'\"\u2018\u2019\u201a\u201b\u201c\u201d\u201e"

// singleQuotes are the characters PowerShell accepts as a single quote.
const singleQuotes = "'\u2018\u2019\u201a\u201b"

// doubleQuotes are the characters PowerShell accepts as a double quote.
const doubleQuotes = "\"\u201c\u201d\u201e"

// Parse returns the argv of the one native command cmd invokes in
// PowerShell, or an error naming why PowerShell would read cmd otherwise.
func Parse(cmd string) ([]string, error) {
	if strings.ContainsAny(cmd, "\r\n") {
		return nil, errors.New("psparse: a line break ends the statement")
	}
	rest := strings.TrimLeft(cmd, " \t")
	if after, ok := strings.CutPrefix(rest, "& "); ok {
		rest = strings.TrimLeft(after, " \t")
	} else if r, _ := utf8.DecodeRuneInString(rest); strings.ContainsRune(singleQuotes+doubleQuotes, r) {
		return nil, errors.New("psparse: a command that starts with a quoted string is a string expression in PowerShell; it needs the call operator &")
	}
	var argv []string
	for rest != "" {
		var word string
		var err error
		r, _ := utf8.DecodeRuneInString(rest)
		switch {
		case strings.ContainsRune(singleQuotes, r):
			word, rest, err = singleQuoted(rest)
		case r == '"':
			word, rest, err = doubleQuoted(rest)
		default:
			word, rest, err = bare(rest)
		}
		if err != nil {
			return nil, err
		}
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return nil, fmt.Errorf("psparse: %q runs into the next word", word)
		}
		argv = append(argv, word)
		rest = strings.TrimLeft(rest, " \t")
	}
	if len(argv) == 0 {
		return nil, errors.New("psparse: empty command")
	}
	return argv, nil
}

// singleQuoted reads a single-quoted literal at the start of s: every
// character is literal, and a doubled quote is one quote.
func singleQuoted(s string) (word, rest string, err error) {
	var b strings.Builder
	_, n := utf8.DecodeRuneInString(s)
	for i := n; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if strings.ContainsRune(singleQuotes, r) {
			if next, m := utf8.DecodeRuneInString(s[i+n:]); m > 0 && strings.ContainsRune(singleQuotes, next) {
				b.WriteRune(r)
				i += n + m
				continue
			}
			return b.String(), s[i+n:], nil
		}
		b.WriteRune(r)
		i += n
	}
	return "", "", errors.New("psparse: unterminated single-quoted string")
}

// doubleQuoted reads a double-quoted string at the start of s that
// PowerShell keeps literal: no $, backtick or other double quote inside.
func doubleQuoted(s string) (word, rest string, err error) {
	end := strings.IndexByte(s[1:], '"')
	if end < 0 {
		return "", "", errors.New("psparse: unterminated double-quoted string")
	}
	inner := s[1 : 1+end]
	if strings.ContainsAny(inner, "$`\u201c\u201d\u201e") {
		return "", "", fmt.Errorf("psparse: %q expands $ or a backtick inside double quotes", inner)
	}
	return inner, s[2+end:], nil
}

// bare reads an unquoted word at the start of s.
func bare(s string) (word, rest string, err error) {
	end := strings.IndexAny(s, " \t")
	if end < 0 {
		end = len(s)
	}
	word = s[:end]
	if strings.ContainsAny(word, bareSpecial) {
		return "", "", fmt.Errorf("psparse: unquoted %q holds a character PowerShell reads specially", word)
	}
	return word, s[end:], nil
}
