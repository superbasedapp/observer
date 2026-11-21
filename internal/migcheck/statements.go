package migcheck

import (
	"fmt"
	"strings"
)

// StatementInfo is one classified statement (or one action of a multi-action
// ALTER TABLE) of a step, for readers that need to know what a step does to
// which table without re-parsing it: the upgrade preflight's lock and time
// estimate (cmd/observer-org). Rule is the statement table's row id, so the
// one classification stays here.
type StatementInfo struct {
	// Rule is the id of the statementRules row that matched, e.g. "create-index".
	Rule string
	// Table is the table the statement acts on, folded; "" when it names none.
	Table string
	// Excerpt is a one-line excerpt of the statement.
	Excerpt string
	// Rewrite is true when the statement rewrites a populated table.
	Rewrite bool
	// NewTable is true when the step creates Table itself, so it is empty.
	NewTable bool
	// Concurrently is true for CREATE/DROP INDEX and REINDEX ... CONCURRENTLY.
	Concurrently bool
	// UsingIndex is true for ADD CONSTRAINT ... USING INDEX.
	UsingIndex bool
	// NotValid is true for ADD CONSTRAINT ... NOT VALID.
	NotValid bool
	// InDoBlock is true when the statement was read out of a DO block's body
	// (recognised textually; dynamic EXECUTE inside the block stays invisible).
	InDoBlock bool
}

// Statements classifies the statements of one step with the same table
// Analyze uses, in source order. A DO block contributes its own statements
// (InDoBlock) after the DO unit itself. It returns an error when the SQL
// cannot be tokenized.
func Statements(sql string) ([]StatementInfo, error) {
	_, s := checkStep(Step{Lineage: "statements", SQL: sql}, newLineageState(), nil)
	if s == nil {
		return nil, fmt.Errorf("migcheck.Statements: the step cannot be tokenized")
	}
	var out []StatementInfo
	for _, u := range s.units {
		out = append(out, info(u, s, false))
		if u.rule != "do-block" {
			continue
		}
		inner, err := doBlockUnits(u)
		if err != nil {
			return nil, fmt.Errorf("migcheck.Statements: %w", err)
		}
		for _, iu := range inner {
			out = append(out, info(iu, s, true))
		}
	}
	return out, nil
}

// info renders a classified unit.
func info(u *unit, s *stepState, inDo bool) StatementInfo {
	table := u.table
	switch u.rule {
	case "create-index":
		table = nameAfter(u.toks, "ON")
	case "create-table":
		table, _ = createdTable(u.toks)
	default:
		if table == "" {
			table = u.target
		}
	}
	return StatementInfo{
		Rule: u.rule, Table: table, Excerpt: u.excerpt, Rewrite: u.rewrite,
		NewTable: s.isNew(table), InDoBlock: inDo,
		Concurrently: findAt(u.toks, 0, "CONCURRENTLY") >= 0,
		UsingIndex:   findAt(u.toks, 0, "USING", "INDEX") >= 0,
		NotValid:     findAt(u.toks, 0, "NOT", "VALID") >= 0,
	}
}

// doStarts are the words a DO body's statement of interest starts with; the
// body's control flow (IF, LOOP, DECLARE, EXECUTE) is not read.
var doStarts = map[string]bool{"ALTER": true, "CREATE": true, "DROP": true, "UPDATE": true, "DELETE": true}

// doBlockUnits classifies the plain statements of a DO block's dollar-quoted
// body: the tokens up to the first statement word (BEGIN, DECLARE ...) are
// dropped, and a statement that does not start with a statement word is
// skipped.
func doBlockUnits(do *unit) ([]*unit, error) {
	var body string
	for _, t := range do.toks {
		if t.kind == tokDollar {
			body = t.text
		}
	}
	if len(body) < 4 {
		return nil, nil
	}
	open := strings.Index(body[1:], "$") + 2 // past "$tag$"
	tag := body[:open]
	if !strings.HasSuffix(body, tag) || len(body) < 2*len(tag) {
		return nil, nil
	}
	body = body[open : len(body)-len(tag)]
	lx, err := lex(body)
	if err != nil {
		return nil, fmt.Errorf("DO block body: %w", err)
	}
	s := &stepState{lin: newLineageState(), newTables: map[string]bool{}}
	var units []*unit
	for i, stmt := range lx.stmts {
		toks := stmt.toks
		for len(toks) > 0 && !(toks[0].kind == tokWord && doStarts[toks[0].up]) {
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		stmt = statement{toks: toks, start: toks[0].pos, end: toks[len(toks)-1].end}
		units = append(units, splitUnits(body, i, stmt)...)
	}
	for _, u := range units {
		if t, ok := createdTable(u.toks); ok {
			s.newTables[t] = true
		}
	}
	for _, u := range units {
		for _, r := range statementRules {
			if !r.match(u) {
				continue
			}
			u.rule, u.class = r.id, r.class
			if r.check != nil {
				r.check(u, s)
			}
			break
		}
	}
	return units, nil
}
