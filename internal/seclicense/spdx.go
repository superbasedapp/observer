package seclicense

import (
	"strings"
)

// Class is the closed licence class vocabulary.
type Class string

// The Class values, most permissive first (classRank).
const (
	ClassPermissive      Class = "permissive"
	ClassWeakCopyleft    Class = "weak_copyleft"
	ClassStrongCopyleft  Class = "strong_copyleft"
	ClassNetworkCopyleft Class = "network_copyleft"
	ClassSourceAvailable Class = "source_available"
	ClassProprietary     Class = "proprietary"
	ClassUnknown         Class = "unknown"
)

// Classes returns the closed class vocabulary, most permissive first.
func Classes() []Class {
	return []Class{
		ClassPermissive, ClassWeakCopyleft, ClassStrongCopyleft,
		ClassNetworkCopyleft, ClassSourceAvailable, ClassProprietary,
		ClassUnknown,
	}
}

// classRank orders the classes for OR (lowest wins) and AND (highest
// wins). Unknown ranks last: an AND with an unknown part cannot be vouched
// for, while an OR with a known alternative can.
func classRank(c Class) int {
	for i, v := range Classes() {
		if v == c {
			return i
		}
	}
	return len(Classes())
}

// ProprietaryID is the id Normalize gives a package that declares it is
// not licensed for reuse (npm "UNLICENSED", "proprietary").
const ProprietaryID = "LicenseRef-proprietary"

// SeeFileID is the id Normalize gives npm's "SEE LICENSE IN <file>": the
// licence is a custom text the reader does not open, so its class is
// unknown.
const SeeFileID = "LicenseRef-see-license-file"

// classRow is one row of the class table: an SPDX id and its class.
type classRow struct {
	ID    string
	Class Class
}

// classTable is the licence class table, one row per SPDX id. An id not
// listed here (and not matched by classPrefixTable) is ClassUnknown.
var classTable = []classRow{
	// Permissive.
	{"MIT", ClassPermissive},
	{"MIT-0", ClassPermissive},
	{"ISC", ClassPermissive},
	{"BSD-2-Clause", ClassPermissive},
	{"BSD-3-Clause", ClassPermissive},
	{"Apache-2.0", ClassPermissive},
	{"0BSD", ClassPermissive},
	{"Zlib", ClassPermissive},
	{"Unlicense", ClassPermissive},
	{"CC0-1.0", ClassPermissive},
	{"Python-2.0", ClassPermissive},
	{"PSF-2.0", ClassPermissive},
	{"BlueOak-1.0.0", ClassPermissive},
	{"BSL-1.0", ClassPermissive},
	{"WTFPL", ClassPermissive},
	{"Unicode-DFS-2016", ClassPermissive},
	{"Unicode-3.0", ClassPermissive},
	{"CC-BY-4.0", ClassPermissive},
	// Weak copyleft.
	{"MPL-2.0", ClassWeakCopyleft},
	{"LGPL-2.0-only", ClassWeakCopyleft},
	{"LGPL-2.0-or-later", ClassWeakCopyleft},
	{"LGPL-2.1-only", ClassWeakCopyleft},
	{"LGPL-2.1-or-later", ClassWeakCopyleft},
	{"LGPL-3.0-only", ClassWeakCopyleft},
	{"LGPL-3.0-or-later", ClassWeakCopyleft},
	{"EPL-1.0", ClassWeakCopyleft},
	{"EPL-2.0", ClassWeakCopyleft},
	{"CDDL-1.0", ClassWeakCopyleft},
	// Strong copyleft.
	{"GPL-1.0-only", ClassStrongCopyleft},
	{"GPL-1.0-or-later", ClassStrongCopyleft},
	{"GPL-2.0-only", ClassStrongCopyleft},
	{"GPL-2.0-or-later", ClassStrongCopyleft},
	{"GPL-3.0-only", ClassStrongCopyleft},
	{"GPL-3.0-or-later", ClassStrongCopyleft},
	// Network copyleft.
	{"AGPL-1.0-only", ClassNetworkCopyleft},
	{"AGPL-3.0-only", ClassNetworkCopyleft},
	{"AGPL-3.0-or-later", ClassNetworkCopyleft},
	{"SSPL-1.0", ClassNetworkCopyleft},
	{"OSL-3.0", ClassNetworkCopyleft},
	// Source-available.
	{"BUSL-1.1", ClassSourceAvailable},
	{"Elastic-2.0", ClassSourceAvailable},
	{"Commons-Clause", ClassSourceAvailable},
	{"LicenseRef-Commons-Clause", ClassSourceAvailable},
	// Proprietary.
	{ProprietaryID, ClassProprietary},
}

// classPrefixTable classifies id families by prefix, after classTable.
var classPrefixTable = []classRow{
	{"PolyForm-", ClassSourceAvailable},
}

// exceptionClassTable lists the WITH exceptions that change the base id's
// class. Every other exception keeps it (a GPL linking exception is still
// GPL for this check). The Commons Clause, written as an exception, takes
// away the base licence's commercial rights.
var exceptionClassTable = []classRow{
	{"Commons-Clause", ClassSourceAvailable},
	{"LicenseRef-Commons-Clause", ClassSourceAvailable},
}

// deprecatedTable maps deprecated SPDX ids to their current forms.
var deprecatedTable = []struct{ From, To string }{
	{"GPL-1.0", "GPL-1.0-only"},
	{"GPL-1.0+", "GPL-1.0-or-later"},
	{"GPL-2.0", "GPL-2.0-only"},
	{"GPL-2.0+", "GPL-2.0-or-later"},
	{"GPL-3.0", "GPL-3.0-only"},
	{"GPL-3.0+", "GPL-3.0-or-later"},
	{"LGPL-2.0", "LGPL-2.0-only"},
	{"LGPL-2.0+", "LGPL-2.0-or-later"},
	{"LGPL-2.1", "LGPL-2.1-only"},
	{"LGPL-2.1+", "LGPL-2.1-or-later"},
	{"LGPL-3.0", "LGPL-3.0-only"},
	{"LGPL-3.0+", "LGPL-3.0-or-later"},
	{"AGPL-1.0", "AGPL-1.0-only"},
	{"AGPL-3.0", "AGPL-3.0-only"},
	{"AGPL-3.0+", "AGPL-3.0-or-later"},
}

// aliasTable maps a free-text licence name (compared case-insensitively,
// white space collapsed) to its SPDX id. A name that is ambiguous (plain
// "BSD", "GPL", "LGPL") is deliberately absent: it stays as written and
// classifies unknown.
var aliasTable = []struct{ Alias, ID string }{
	{"mit license", "MIT"},
	{"the mit license", "MIT"},
	{"mit licence", "MIT"},
	{"mit/x11", "MIT"},
	{"expat", "MIT"},
	{"apache 2.0", "Apache-2.0"},
	{"apache 2", "Apache-2.0"},
	{"apache-2", "Apache-2.0"},
	{"apache2", "Apache-2.0"},
	{"apache license 2.0", "Apache-2.0"},
	{"apache license, version 2.0", "Apache-2.0"},
	{"apache license version 2.0", "Apache-2.0"},
	{"apache license (2.0)", "Apache-2.0"},
	{"apache-2.0 license", "Apache-2.0"},
	{"apache software license 2.0", "Apache-2.0"},
	{"asl 2.0", "Apache-2.0"},
	{"new bsd", "BSD-3-Clause"},
	{"new bsd license", "BSD-3-Clause"},
	{"modified bsd", "BSD-3-Clause"},
	{"bsd-3", "BSD-3-Clause"},
	{"bsd 3-clause", "BSD-3-Clause"},
	{"3-clause bsd", "BSD-3-Clause"},
	{"bsd-3-clause license", "BSD-3-Clause"},
	{"simplified bsd", "BSD-2-Clause"},
	{"freebsd", "BSD-2-Clause"},
	{"bsd-2", "BSD-2-Clause"},
	{"bsd 2-clause", "BSD-2-Clause"},
	{"2-clause bsd", "BSD-2-Clause"},
	{"isc license", "ISC"},
	{"isc license (iscl)", "ISC"},
	{"unlicense", "Unlicense"},
	{"the unlicense", "Unlicense"},
	{"unlicensed", ProprietaryID},
	{"proprietary", ProprietaryID},
	{"commercial", ProprietaryID},
	{"cc0", "CC0-1.0"},
	{"cc0 1.0", "CC0-1.0"},
	{"cc0 1.0 universal", "CC0-1.0"},
	{"psf", "PSF-2.0"},
	{"psf license", "PSF-2.0"},
	{"python software foundation license", "PSF-2.0"},
	{"zlib license", "Zlib"},
	{"boost software license 1.0", "BSL-1.0"},
	{"gplv2", "GPL-2.0-only"},
	{"gpl-2", "GPL-2.0-only"},
	{"gpl v2", "GPL-2.0-only"},
	{"gpl 2", "GPL-2.0-only"},
	{"gnu gpl v2", "GPL-2.0-only"},
	{"gplv2+", "GPL-2.0-or-later"},
	{"gpl-2+", "GPL-2.0-or-later"},
	{"gplv3", "GPL-3.0-only"},
	{"gpl-3", "GPL-3.0-only"},
	{"gpl v3", "GPL-3.0-only"},
	{"gpl 3", "GPL-3.0-only"},
	{"gnu gpl v3", "GPL-3.0-only"},
	{"gnu gplv3", "GPL-3.0-only"},
	{"gnu general public license v3", "GPL-3.0-only"},
	{"gplv3+", "GPL-3.0-or-later"},
	{"gpl-3+", "GPL-3.0-or-later"},
	{"gnu gpl v3+", "GPL-3.0-or-later"},
	{"lgplv2", "LGPL-2.0-only"},
	{"lgplv2+", "LGPL-2.0-or-later"},
	{"lgplv2.1", "LGPL-2.1-only"},
	{"lgpl 2.1", "LGPL-2.1-only"},
	{"lgplv2.1+", "LGPL-2.1-or-later"},
	{"lgplv3", "LGPL-3.0-only"},
	{"lgpl-3", "LGPL-3.0-only"},
	{"lgpl v3", "LGPL-3.0-only"},
	{"lgplv3+", "LGPL-3.0-or-later"},
	{"agplv3", "AGPL-3.0-only"},
	{"agpl-3", "AGPL-3.0-only"},
	{"agpl v3", "AGPL-3.0-only"},
	{"gnu agpl v3", "AGPL-3.0-only"},
	{"agplv3+", "AGPL-3.0-or-later"},
	{"mpl 2.0", "MPL-2.0"},
	{"mpl-2", "MPL-2.0"},
	{"mpl2", "MPL-2.0"},
	{"mozilla public license 2.0", "MPL-2.0"},
	{"eclipse public license 2.0", "EPL-2.0"},
	{"epl 2.0", "EPL-2.0"},
	{"eclipse public license 1.0", "EPL-1.0"},
	{"server side public license", "SSPL-1.0"},
	{"sspl", "SSPL-1.0"},
	{"elastic license 2.0", "Elastic-2.0"},
	{"elv2", "Elastic-2.0"},
	{"business source license 1.1", "BUSL-1.1"},
	{"bsl 1.1", "BUSL-1.1"},
	{"commons clause", "Commons-Clause"},
}

// canonical maps a lower-cased known id (class table rows, exceptions,
// deprecated ids, deprecated targets) to its SPDX spelling.
var canonical = buildCanonical()

func buildCanonical() map[string]string {
	m := map[string]string{}
	for _, r := range classTable {
		m[strings.ToLower(r.ID)] = r.ID
	}
	for _, r := range exceptionClassTable {
		m[strings.ToLower(r.ID)] = r.ID
	}
	for _, r := range deprecatedTable {
		m[strings.ToLower(r.To)] = r.To
	}
	for _, r := range deprecatedTable {
		m[strings.ToLower(r.From)] = r.To
	}
	for _, r := range aliasTable {
		m[r.Alias] = r.ID
	}
	return m
}

// collapse lower-cases s and collapses its white space.
func collapse(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// normalizeID normalizes one licence name (no operators) to its SPDX id,
// or returns it trimmed when it is not one Observer knows.
func normalizeID(raw string) string {
	s := strings.Join(strings.Fields(raw), " ")
	if s == "" {
		return ""
	}
	if isSeeFile(s) {
		return SeeFileID
	}
	if id, ok := canonical[collapse(s)]; ok {
		return id
	}
	return s
}

// isSeeFile reports npm's "SEE LICENSE IN <file>" form.
func isSeeFile(s string) bool {
	low := collapse(s)
	return strings.HasPrefix(low, "see license in") || strings.HasPrefix(low, "see licence in")
}

// token kinds of the expression lexer.
const (
	tokID = iota
	tokAnd
	tokOr
	tokWith
	tokOpen
	tokClose
)

type token struct {
	kind int
	text string
}

// lex splits an expression into operators, parentheses and id phrases.
// Consecutive words that are not operators join into one phrase ("Apache
// License 2.0"), so aliases with spaces survive. "/" is the legacy Cargo
// spelling of OR ("MIT/Apache-2.0").
func lex(s string) []token {
	var out []token
	var words []string
	flush := func() {
		if len(words) > 0 {
			out = append(out, token{kind: tokID, text: strings.Join(words, " ")})
			words = nil
		}
	}
	s = strings.NewReplacer("(", " ( ", ")", " ) ", "/", " OR ").Replace(s)
	for _, w := range strings.Fields(s) {
		switch strings.ToUpper(w) {
		case "AND":
			flush()
			out = append(out, token{kind: tokAnd, text: "AND"})
		case "OR":
			flush()
			out = append(out, token{kind: tokOr, text: "OR"})
		case "WITH":
			flush()
			out = append(out, token{kind: tokWith, text: "WITH"})
		case "(":
			flush()
			out = append(out, token{kind: tokOpen, text: "("})
		case ")":
			flush()
			out = append(out, token{kind: tokClose, text: ")"})
		default:
			words = append(words, w)
		}
	}
	flush()
	return out
}

// hasOperator reports whether s has an expression operator or parenthesis.
func hasOperator(s string) bool {
	for _, t := range lex(s) {
		if t.kind != tokID {
			return true
		}
	}
	return false
}

// Normalize maps a declared licence to an SPDX id or SPDX expression. An
// alias maps through aliasTable, a deprecated id to its current form, and
// an expression keeps its shape with each id normalized and the operators
// upper-cased. An unrecognized name is returned trimmed (it classifies
// unknown); "" stays "".
func Normalize(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// A whole-string alias first: "Apache License, Version 2.0" holds no
	// operator, but "GNU GPL v3+" and friends must not be split.
	if id, ok := canonical[collapse(s)]; ok {
		return id
	}
	if isSeeFile(s) {
		return SeeFileID
	}
	if !hasOperator(s) {
		return normalizeID(s)
	}
	toks := lex(s)
	parts := make([]string, 0, len(toks))
	for _, t := range toks {
		if t.kind == tokID {
			parts = append(parts, normalizeID(t.text))
			continue
		}
		parts = append(parts, t.text)
	}
	out := strings.Join(parts, " ")
	out = strings.ReplaceAll(out, "( ", "(")
	out = strings.ReplaceAll(out, " )", ")")
	return out
}

// node is a parsed licence expression.
type node struct {
	op       int // tokID, tokAnd, tokOr, tokWith
	id       string
	children []*node
}

// parser is a recursive-descent parser over SPDX precedence: WITH binds
// tightest, then AND, then OR.
type parser struct {
	toks []token
	pos  int
	bad  bool
}

func (p *parser) peek() (token, bool) {
	if p.pos >= len(p.toks) {
		return token{}, false
	}
	return p.toks[p.pos], true
}

func (p *parser) parseOr() *node {
	left := p.parseAnd()
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			return left
		}
		p.pos++
		right := p.parseAnd()
		left = &node{op: tokOr, children: []*node{left, right}}
	}
}

func (p *parser) parseAnd() *node {
	left := p.parseWith()
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokAnd {
			return left
		}
		p.pos++
		right := p.parseWith()
		left = &node{op: tokAnd, children: []*node{left, right}}
	}
}

func (p *parser) parseWith() *node {
	base := p.parseAtom()
	t, ok := p.peek()
	if !ok || t.kind != tokWith {
		return base
	}
	p.pos++
	exc, ok := p.peek()
	if !ok || exc.kind != tokID {
		p.bad = true
		return base
	}
	p.pos++
	return &node{op: tokWith, id: normalizeID(exc.text), children: []*node{base}}
}

func (p *parser) parseAtom() *node {
	t, ok := p.peek()
	if !ok {
		p.bad = true
		return &node{op: tokID}
	}
	switch t.kind {
	case tokID:
		p.pos++
		return &node{op: tokID, id: normalizeID(t.text)}
	case tokOpen:
		p.pos++
		n := p.parseOr()
		if c, ok := p.peek(); !ok || c.kind != tokClose {
			p.bad = true
			return n
		}
		p.pos++
		return n
	default:
		p.bad = true
		p.pos++
		return &node{op: tokID}
	}
}

// parse parses an expression; ok is false for "" or a malformed one.
func parse(expr string) (*node, bool) {
	toks := lex(expr)
	if len(toks) == 0 {
		return nil, false
	}
	p := &parser{toks: toks}
	n := p.parseOr()
	if p.bad || p.pos != len(p.toks) {
		return nil, false
	}
	return n, true
}

// ClassOf returns the class of one SPDX id (no operators): its class
// table row, then a prefix row, else ClassUnknown. The id is normalized
// first, so an alias classifies like its SPDX id.
func ClassOf(id string) Class {
	id = normalizeID(id)
	for _, r := range classTable {
		if strings.EqualFold(r.ID, id) {
			return r.Class
		}
	}
	low := strings.ToLower(id)
	for _, r := range classPrefixTable {
		if strings.HasPrefix(low, strings.ToLower(r.ID)) {
			return r.Class
		}
	}
	return ClassUnknown
}

// exceptionClass returns the class a WITH exception imposes, if any.
func exceptionClass(exc string) (Class, bool) {
	for _, r := range exceptionClassTable {
		if strings.EqualFold(r.ID, exc) {
			return r.Class, true
		}
	}
	return "", false
}

// classOfNode is the class of a parsed expression.
func classOfNode(n *node) Class {
	switch n.op {
	case tokID:
		return ClassOf(n.id)
	case tokWith:
		if c, ok := exceptionClass(n.id); ok {
			return c
		}
		return classOfNode(n.children[0])
	case tokOr:
		a, b := classOfNode(n.children[0]), classOfNode(n.children[1])
		if classRank(b) < classRank(a) {
			return b
		}
		return a
	case tokAnd:
		a, b := classOfNode(n.children[0]), classOfNode(n.children[1])
		if classRank(b) > classRank(a) {
			return b
		}
		return a
	}
	return ClassUnknown
}

// Classify returns the class of a licence id or expression: for OR the
// most permissive alternative, for AND the least permissive part, and for
// WITH the base id's class (unless exceptionClassTable lists the
// exception). An empty or malformed expression is ClassUnknown.
func Classify(expr string) Class {
	n, ok := parse(Normalize(expr))
	if !ok {
		return ClassUnknown
	}
	return classOfNode(n)
}
