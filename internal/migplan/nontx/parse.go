package nontx

import (
	"fmt"
	"strings"
)

// Kind is an allowed statement kind of a non-transactional step.
type Kind string

// The allowed kinds, one per row of the kinds table.
const (
	// KindCreateIndex is CREATE [UNIQUE] INDEX CONCURRENTLY with a name.
	KindCreateIndex Kind = "create-index-concurrently"
	// KindDropIndex is DROP INDEX CONCURRENTLY of one index.
	KindDropIndex Kind = "drop-index-concurrently"
	// KindReindexIndex is REINDEX INDEX CONCURRENTLY of one index.
	KindReindexIndex Kind = "reindex-index-concurrently"
	// KindReindexTable is REINDEX TABLE CONCURRENTLY of one table.
	KindReindexTable Kind = "reindex-table-concurrently"
)

// Probe is what the runner reads from the catalogue before each attempt.
type Probe string

const (
	// ProbeIndex reads the named index: whether it exists, whether it is
	// valid, and (for a CREATE) whether it sits on the statement's table.
	ProbeIndex Probe = "index"
	// ProbeLeftovers lists the invalid _ccnew/_ccold indexes an interrupted
	// REINDEX CONCURRENTLY left on the target.
	ProbeLeftovers Probe = "leftovers"
)

// Statement is the one statement of a non-transactional step.
type Statement struct {
	Kind Kind
	// Text is the statement as written, without its terminating semicolon.
	Text string
	// Probe names the catalogue read Resume needs.
	Probe Probe
	// Index is the index the statement creates, drops or rebuilds, as SQL
	// name text (quoted parts kept quoted, schema-qualified when the
	// statement qualifies it); empty for REINDEX TABLE. A CREATE INDEX on a
	// schema-qualified table names its index in that schema, so Index carries
	// the table's schema.
	Index string
	// Table is the table a CREATE INDEX or REINDEX TABLE names, as SQL name
	// text; empty otherwise.
	Table string
}

// Header is one SET statement of a non-transactional step.
type Header struct {
	// Text is the statement as written.
	Text string
	// Param is the parameter it sets, folded (always a plain lower-case name
	// from the header table); the runner resets it when the step ends,
	// because outside a transaction a SET outlives the step on the session.
	Param string
}

// Step is a parsed non-transactional step, in execution order: Before, then
// Statement, then After.
type Step struct {
	Before    []Header
	Statement Statement
	After     []Header
}

// Params lists the parameters the step's headers set, in order, each once.
func (s Step) Params() []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range append(append([]Header(nil), s.Before...), s.After...) {
		if !seen[h.Param] {
			seen[h.Param] = true
			out = append(out, h.Param)
		}
	}
	return out
}

// headerParams are the parameters a header SET may set: migcheck's header
// classes (lock_timeout, statement_timeout and its harmless session set). A
// SET of anything else is a statement, and so is refused.
var headerParams = map[string]bool{
	"lock_timeout": true, "statement_timeout": true, "search_path": true,
	"client_min_messages": true, "idle_in_transaction_session_timeout": true,
	"maintenance_work_mem": true, "work_mem": true,
}

// kindRule is one row of the kinds table.
type kindRule struct {
	kind Kind
	// shape is the accepted grammar, for errors and for the reader.
	shape string
	match func(ts []token) bool
	parse func(ts []token) (Statement, error)
}

// kinds is THE table of allowed statement kinds, walked top-down, first
// match wins. match only recognises the statement; parse checks the whole
// shape and refuses what the runner cannot resume.
var kinds = []kindRule{
	{
		kind:  KindCreateIndex,
		shape: "CREATE [UNIQUE] INDEX CONCURRENTLY [IF NOT EXISTS] name ON [ONLY] table ...",
		match: func(ts []token) bool { return at(ts, 0, "CREATE", "INDEX") || at(ts, 0, "CREATE", "UNIQUE", "INDEX") },
		parse: parseCreateIndex,
	},
	{
		kind:  KindDropIndex,
		shape: "DROP INDEX CONCURRENTLY [IF EXISTS] name [RESTRICT]",
		match: func(ts []token) bool { return at(ts, 0, "DROP", "INDEX") },
		parse: parseDropIndex,
	},
	{
		kind:  KindReindexIndex,
		shape: "REINDEX [(options)] INDEX CONCURRENTLY name",
		match: func(ts []token) bool { return at(ts, reindexTarget(ts), "INDEX") },
		parse: func(ts []token) (Statement, error) { return parseReindex(ts, KindReindexIndex) },
	},
	{
		kind:  KindReindexTable,
		shape: "REINDEX [(options)] TABLE CONCURRENTLY name",
		match: func(ts []token) bool { return at(ts, reindexTarget(ts), "TABLE") },
		parse: func(ts []token) (Statement, error) { return parseReindex(ts, KindReindexTable) },
	},
}

// Shapes lists the accepted grammar of every allowed kind, in table order.
func Shapes() []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k.shape)
	}
	return out
}

// Parse reads a non-transactional step's SQL. It refuses a step that does not
// hold exactly one statement of an allowed kind besides its SET headers.
func Parse(sql string) (Step, error) {
	stmts, err := split(sql)
	if err != nil {
		return Step{}, fmt.Errorf("nontx.Parse: %w", err)
	}
	var (
		step  Step
		found bool
	)
	for _, st := range stmts {
		if h, ok := header(st); ok {
			if found {
				step.After = append(step.After, h)
			} else {
				step.Before = append(step.Before, h)
			}
			continue
		}
		if found {
			return Step{}, fmt.Errorf("nontx.Parse: a non-transactional step holds exactly one statement besides its SET headers; found another: %s", excerpt(st.text))
		}
		s, err := classify(st)
		if err != nil {
			return Step{}, err
		}
		step.Statement, found = s, true
	}
	if !found {
		return Step{}, fmt.Errorf("nontx.Parse: a non-transactional step holds exactly one statement besides its SET headers; found none")
	}
	return step, nil
}

// classify walks the kinds table for one statement.
func classify(st statement) (Statement, error) {
	for _, k := range kinds {
		if !k.match(st.toks) {
			continue
		}
		s, err := k.parse(st.toks)
		if err != nil {
			return Statement{}, fmt.Errorf("nontx.Parse: %s (accepted: %s): %w", excerpt(st.text), k.shape, err)
		}
		s.Kind, s.Text = k.kind, st.text
		return s, nil
	}
	return Statement{}, fmt.Errorf("nontx.Parse: %s is not an allowed non-transactional statement (allowed: %s)", excerpt(st.text), strings.Join(Shapes(), "; "))
}

// header recognises a SET [SESSION|LOCAL] of a header parameter.
func header(st statement) (Header, bool) {
	ts := st.toks
	if !at(ts, 0, "SET") {
		return Header{}, false
	}
	i := 1
	if at(ts, i, "SESSION") || at(ts, i, "LOCAL") {
		i++
	}
	if i >= len(ts) || !ts[i].isName() {
		return Header{}, false
	}
	if !headerParams[fold(ts[i])] {
		return Header{}, false
	}
	return Header{Text: st.text, Param: fold(ts[i])}, true
}

func parseCreateIndex(ts []token) (Statement, error) {
	i := 1
	if at(ts, i, "UNIQUE") {
		i++
	}
	i++ // INDEX
	if !at(ts, i, "CONCURRENTLY") {
		return Statement{}, fmt.Errorf("CONCURRENTLY is required")
	}
	i = skipWords(ts, i+1, "IF", "NOT", "EXISTS")
	if at(ts, i, "ON") || i >= len(ts) || !ts[i].isName() {
		return Statement{}, fmt.Errorf("the index needs a name: an unnamed index cannot be found again, so an interrupted run could not be resumed")
	}
	index := ts[i].text
	if i+1 < len(ts) && ts[i+1].isPunct(".") {
		return Statement{}, fmt.Errorf("CREATE INDEX takes an unqualified index name (the index goes in its table's schema)")
	}
	i++
	if !at(ts, i, "ON") {
		return Statement{}, fmt.Errorf("ON table is required after the index name")
	}
	i = skipWords(ts, i+1, "ONLY")
	parts, _ := qualifiedName(ts, i)
	if len(parts) == 0 {
		return Statement{}, fmt.Errorf("ON needs a table name")
	}
	if len(parts) > 1 {
		index = strings.Join(parts[:len(parts)-1], ".") + "." + index
	}
	return Statement{Probe: ProbeIndex, Index: index, Table: strings.Join(parts, ".")}, nil
}

func parseDropIndex(ts []token) (Statement, error) {
	i := 2
	if !at(ts, i, "CONCURRENTLY") {
		return Statement{}, fmt.Errorf("CONCURRENTLY is required")
	}
	i = skipWords(ts, i+1, "IF", "EXISTS")
	parts, next := qualifiedName(ts, i)
	if len(parts) == 0 {
		return Statement{}, fmt.Errorf("an index name is required")
	}
	next = skipWords(ts, next, "RESTRICT")
	if next != len(ts) {
		return Statement{}, fmt.Errorf("exactly one index, optionally RESTRICT (DROP INDEX CONCURRENTLY takes one index and no CASCADE)")
	}
	return Statement{Probe: ProbeIndex, Index: strings.Join(parts, ".")}, nil
}

// reindexTarget returns the index of a REINDEX statement's target keyword
// (past a parenthesised option list), or -1 when ts is not a REINDEX.
func reindexTarget(ts []token) int {
	if !at(ts, 0, "REINDEX") {
		return -1
	}
	i := 1
	if i < len(ts) && ts[i].isPunct("(") {
		depth := 0
		for ; i < len(ts); i++ {
			switch {
			case ts[i].isPunct("("):
				depth++
			case ts[i].isPunct(")"):
				depth--
			}
			if depth == 0 {
				return i + 1
			}
		}
		return -1
	}
	return i
}

func parseReindex(ts []token, kind Kind) (Statement, error) {
	i := reindexTarget(ts)
	if i > 1 {
		for _, t := range ts[1:i] {
			if t.isWord("CONCURRENTLY") {
				return Statement{}, fmt.Errorf("write CONCURRENTLY after the target keyword, not as an option")
			}
		}
	}
	i++ // INDEX or TABLE
	if !at(ts, i, "CONCURRENTLY") {
		return Statement{}, fmt.Errorf("CONCURRENTLY is required")
	}
	parts, next := qualifiedName(ts, i+1)
	if len(parts) == 0 || next != len(ts) {
		return Statement{}, fmt.Errorf("exactly one name is required")
	}
	name := strings.Join(parts, ".")
	if kind == KindReindexIndex {
		return Statement{Probe: ProbeLeftovers, Index: name}, nil
	}
	return Statement{Probe: ProbeLeftovers, Table: name}, nil
}

// at reports whether ts[i:] starts with the keyword sequence words.
func at(ts []token, i int, words ...string) bool {
	if i < 0 || i+len(words) > len(ts) {
		return false
	}
	for k, w := range words {
		if !ts[i+k].isWord(w) {
			return false
		}
	}
	return true
}

// skipWords returns i advanced past the keyword sequence words when ts[i:]
// starts with it, else i.
func skipWords(ts []token, i int, words ...string) int {
	if at(ts, i, words...) {
		return i + len(words)
	}
	return i
}

// qualifiedName reads a possibly schema-qualified name at ts[i] and returns
// its parts as written and the index after it.
func qualifiedName(ts []token, i int) ([]string, int) {
	if i >= len(ts) || !ts[i].isName() {
		return nil, i
	}
	parts := []string{ts[i].text}
	i++
	for i+1 < len(ts) && ts[i].isPunct(".") && ts[i+1].isName() {
		parts = append(parts, ts[i+1].text)
		i += 2
	}
	return parts, i
}

// fold returns the identifier a name token names, folded the way PostgreSQL
// folds it: unquoted to lower case, quoted verbatim.
func fold(t token) string {
	if t.kind == tokWord {
		return strings.ToLower(t.text)
	}
	s := strings.TrimPrefix(strings.TrimPrefix(t.text, "U&"), "u&")
	if len(s) >= 2 {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `""`, `"`)
}

// excerpt is a statement with its whitespace collapsed, truncated for an
// error message.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const limit = 120
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "..."
	}
	return s
}
