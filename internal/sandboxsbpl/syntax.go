package sandboxsbpl

import (
	"fmt"
	"strconv"
	"strings"
)

// syntax.go is the strict SBPL checker the oracle tests and the driver run
// over every generated profile (sandbox plan v2 section 13 P5 acceptance:
// "SBPL syntax accepted by a parser"). It accepts only the subset this
// package emits, so a generator change that produces a form nobody has
// reviewed fails here, and it lints the safety rules no profile may break
// (deny by default, no unfiltered allow of a write or a connection, no
// connection beyond localhost, no undefined parameter).

// Node is one parsed SBPL expression: an atom (a symbol, a number or a
// string) or a list.
type Node struct {
	Atom   string
	String bool
	List   []Node
	IsList bool
	// Line is the 1-based line the node starts on.
	Line int
}

func (n Node) head() string {
	if !n.IsList || len(n.List) == 0 || n.List[0].IsList || n.List[0].String {
		return ""
	}
	return n.List[0].Atom
}

// Parse reads SBPL text into top-level forms. Comments run from ';' to the
// end of the line. Regex literals (#"...") and any other reader syntax are
// refused: the generator never emits them.
func Parse(text string) ([]Node, error) {
	p := &parser{s: text, line: 1}
	var out []Node
	for {
		p.skip()
		if p.i >= len(p.s) {
			return out, nil
		}
		n, err := p.expr()
		if err != nil {
			return nil, err
		}
		if !n.IsList {
			return nil, fmt.Errorf("line %d: a top-level atom %q", n.Line, n.Atom)
		}
		out = append(out, n)
	}
}

type parser struct {
	s    string
	i    int
	line int
}

func (p *parser) skip() {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '\n':
			p.line++
			p.i++
		case c == ' ' || c == '\t' || c == '\r':
			p.i++
		case c == ';':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *parser) expr() (Node, error) {
	p.skip()
	if p.i >= len(p.s) {
		return Node{}, fmt.Errorf("line %d: unexpected end of profile", p.line)
	}
	switch p.s[p.i] {
	case '(':
		return p.list()
	case ')':
		return Node{}, fmt.Errorf("line %d: unbalanced ')'", p.line)
	case '"':
		return p.str()
	case '#':
		return Node{}, fmt.Errorf("line %d: reader syntax '#' (a regex literal or a boolean) is not accepted", p.line)
	}
	return p.atom()
}

func (p *parser) list() (Node, error) {
	line := p.line
	p.i++
	n := Node{IsList: true, Line: line}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return Node{}, fmt.Errorf("line %d: unbalanced '('", line)
		}
		if p.s[p.i] == ')' {
			p.i++
			return n, nil
		}
		child, err := p.expr()
		if err != nil {
			return Node{}, err
		}
		n.List = append(n.List, child)
	}
}

func (p *parser) str() (Node, error) {
	line := p.line
	p.i++
	var sb strings.Builder
	for p.i < len(p.s) {
		ch := p.s[p.i]
		switch {
		case ch == '"':
			p.i++
			return Node{Atom: sb.String(), String: true, Line: line}, nil
		case ch == '\\':
			if p.i+1 >= len(p.s) || (p.s[p.i+1] != '"' && p.s[p.i+1] != '\\') {
				return Node{}, fmt.Errorf("line %d: only \\\" and \\\\ escapes are accepted", line)
			}
			sb.WriteByte(p.s[p.i+1])
			p.i += 2
		case ch < 0x20:
			return Node{}, fmt.Errorf("line %d: a control character inside a string", line)
		default:
			sb.WriteByte(ch)
			p.i++
		}
	}
	return Node{}, fmt.Errorf("line %d: unterminated string", line)
}

func (p *parser) atom() (Node, error) {
	line := p.line
	start := p.i
	for p.i < len(p.s) && !strings.ContainsRune("()\"; \t\n\r", rune(p.s[p.i])) {
		p.i++
	}
	atom := p.s[start:p.i]
	for _, r := range atom {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '*' || r == '_') {
			return Node{}, fmt.Errorf("line %d: symbol %q has a character outside [a-z0-9-*_]", line, atom)
		}
	}
	return Node{Atom: atom, Line: line}, nil
}

// knownOps is the closed operation vocabulary the checker accepts.
var knownOps = map[string]bool{
	"default": true, "process-exec": true, "process-fork": true, "process-info*": true,
	"signal": true, "sysctl-read": true, "ipc-posix-shm*": true, "ipc-posix-sem": true,
	"ipc-posix-shm-read-data": true, "ipc-posix-shm-read-metadata": true,
	"user-preference-read": true, "mach-lookup": true,
	"file-read*": true, "file-read-data": true, "file-read-metadata": true,
	"file-write*": true, "file-write-data": true, "file-ioctl": true,
	"network-outbound": true, "network*": true, "network-inbound": true, "network-bind": true,
}

// Rule is one checked allow or deny form.
type Rule struct {
	Allow   bool
	Ops     []string
	Filters []Filter
	Line    int
}

// Filter is one checked filter. Kind is literal, subpath, path-literal
// (always under remote unix-socket), remote-ip, target, global-name or
// ipc-posix-name.
// Value holds the string, or the parameter name when Param is true.
type Filter struct {
	Kind  string
	Value string
	Param bool
}

// Check parses text and checks it against the accepted subset and the
// safety lint. params are the -D parameters the profile runs with; every
// parameter it references must be defined and every defined one used.
func Check(text string, params map[string]string) ([]Rule, error) {
	forms, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if len(forms) < 2 {
		return nil, fmt.Errorf("a profile needs (version 1) and (deny default)")
	}
	if v := forms[0]; v.head() != "version" || len(v.List) != 2 || v.List[1].Atom != "1" || v.List[1].String {
		return nil, fmt.Errorf("line %d: the first form must be (version 1)", forms[0].Line)
	}
	used := map[string]bool{}
	var rules []Rule
	for _, f := range forms[1:] {
		r, err := checkRule(f, params, used)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if r := rules[0]; r.Allow || len(r.Ops) != 1 || r.Ops[0] != "default" || len(r.Filters) != 0 {
		return nil, fmt.Errorf("line %d: the second form must be (deny default)", r.Line)
	}
	for name := range params {
		if !used[name] {
			return nil, fmt.Errorf("parameter %q is defined but never used", name)
		}
	}
	return rules, lint(rules)
}

func checkRule(f Node, params map[string]string, used map[string]bool) (Rule, error) {
	r := Rule{Line: f.Line}
	switch f.head() {
	case "allow":
		r.Allow = true
	case "deny":
	default:
		return r, fmt.Errorf("line %d: only (allow ...) and (deny ...) forms are accepted, got %q", f.Line, f.head())
	}
	rest := f.List[1:]
	for len(rest) > 0 && !rest[0].IsList {
		if rest[0].String || !knownOps[rest[0].Atom] {
			return r, fmt.Errorf("line %d: unknown operation %q", f.Line, rest[0].Atom)
		}
		r.Ops = append(r.Ops, rest[0].Atom)
		rest = rest[1:]
	}
	if len(r.Ops) == 0 {
		return r, fmt.Errorf("line %d: a rule without an operation", f.Line)
	}
	for _, x := range rest {
		flt, err := checkFilter(x, params, used)
		if err != nil {
			return r, err
		}
		r.Filters = append(r.Filters, flt)
	}
	return r, nil
}

// stringArg reads a string or (param "NAME") argument.
func stringArg(n Node, params map[string]string, used map[string]bool) (string, bool, error) {
	if n.String {
		return n.Atom, false, nil
	}
	if n.head() == "param" && len(n.List) == 2 && n.List[1].String {
		name := n.List[1].Atom
		if _, ok := params[name]; !ok {
			return "", false, fmt.Errorf("line %d: parameter %q is not defined", n.Line, name)
		}
		used[name] = true
		return name, true, nil
	}
	return "", false, fmt.Errorf("line %d: expected a string or (param \"NAME\")", n.Line)
}

func checkFilter(n Node, params map[string]string, used map[string]bool) (Filter, error) {
	if !n.IsList || len(n.List) < 2 {
		return Filter{}, fmt.Errorf("line %d: a filter must be a list with an argument", n.Line)
	}
	switch h := n.head(); h {
	case "literal", "subpath":
		if len(n.List) != 2 {
			return Filter{}, fmt.Errorf("line %d: (%s X) takes one argument", n.Line, h)
		}
		v, isParam, err := stringArg(n.List[1], params, used)
		if err != nil {
			return Filter{}, err
		}
		if !isParam && !strings.HasPrefix(v, "/dev/") {
			return Filter{}, fmt.Errorf("line %d: a path filter must be a parameter or a /dev path, got %q", n.Line, v)
		}
		return Filter{Kind: h, Value: v, Param: isParam}, nil
	case "global-name":
		if len(n.List) != 2 || !n.List[1].String || !validMachName(n.List[1].Atom) {
			return Filter{}, fmt.Errorf("line %d: (global-name \"name\")", n.Line)
		}
		return Filter{Kind: h, Value: n.List[1].Atom}, nil
	case "ipc-posix-name":
		if len(n.List) != 2 || !n.List[1].String || !validMachName(n.List[1].Atom) {
			return Filter{}, fmt.Errorf("line %d: (ipc-posix-name \"name\")", n.Line)
		}
		return Filter{Kind: h, Value: n.List[1].Atom}, nil
	case "target":
		if len(n.List) != 2 || n.List[1].String || n.List[1].Atom != "same-sandbox" {
			return Filter{}, fmt.Errorf("line %d: only (target same-sandbox) is accepted", n.Line)
		}
		return Filter{Kind: h, Value: "same-sandbox"}, nil
	case "remote":
		return checkRemoteFilter(n, params, used)
	default:
		return Filter{}, fmt.Errorf("line %d: unknown filter %q", n.Line, h)
	}
}

// checkRemoteFilter is checkFilter's (remote KIND ARG) case.
func checkRemoteFilter(n Node, params map[string]string, used map[string]bool) (Filter, error) {
	if len(n.List) != 3 || n.List[1].IsList || n.List[1].String {
		return Filter{}, fmt.Errorf("line %d: (remote KIND ARG)", n.Line)
	}
	switch n.List[1].Atom {
	case "ip":
		if !n.List[2].String {
			return Filter{}, fmt.Errorf("line %d: (remote ip \"host:port\")", n.Line)
		}
		return Filter{Kind: "remote-ip", Value: n.List[2].Atom}, nil
	case "unix-socket":
		pl := n.List[2]
		if pl.head() != "path-literal" || len(pl.List) != 2 {
			return Filter{}, fmt.Errorf("line %d: (remote unix-socket (path-literal X))", n.Line)
		}
		v, isParam, err := stringArg(pl.List[1], params, used)
		if err != nil {
			return Filter{}, err
		}
		if !isParam {
			return Filter{}, fmt.Errorf("line %d: a unix socket path must be a parameter", n.Line)
		}
		return Filter{Kind: "path-literal", Value: v, Param: true}, nil
	}
	return Filter{}, fmt.Errorf("line %d: unknown remote kind %q", n.Line, n.List[1].Atom)
}

// lint applies the safety rules every profile must keep.
func lint(rules []Rule) error {
	for i, r := range rules {
		if i > 0 && r.Allow && hasOp(r, "default") {
			return fmt.Errorf("line %d: (allow default) is forbidden", r.Line)
		}
		if !r.Allow {
			continue
		}
		for _, op := range r.Ops {
			if err := lintAllowOp(r, op); err != nil {
				return err
			}
		}
	}
	return nil
}

// lintAllowOp is lint's check of one operation an allow rule names.
func lintAllowOp(r Rule, op string) error {
	switch {
	case op == "network*" || op == "network-inbound" || op == "network-bind":
		return fmt.Errorf("line %d: allowing %s is forbidden: the box connects out to its own endpoints only", r.Line, op)
	case op == "network-outbound":
		if len(r.Filters) == 0 {
			return fmt.Errorf("line %d: an unfiltered network-outbound allow", r.Line)
		}
		for _, f := range r.Filters {
			if f.Kind == "remote-ip" {
				if err := localhostPort(f.Value); err != nil {
					return fmt.Errorf("line %d: %w", r.Line, err)
				}
			} else if f.Kind != "path-literal" {
				return fmt.Errorf("line %d: network-outbound filtered by %s", r.Line, f.Kind)
			}
		}
	case op == "file-write*" || op == "file-write-data":
		if len(r.Filters) == 0 {
			return fmt.Errorf("line %d: an unfiltered file write allow", r.Line)
		}
	case op == "mach-lookup":
		if len(r.Filters) == 0 {
			return fmt.Errorf("line %d: an unfiltered mach-lookup allow", r.Line)
		}
	case strings.HasPrefix(op, "ipc-posix-shm"):
		if op != "ipc-posix-shm-read-data" && op != "ipc-posix-shm-read-metadata" {
			return fmt.Errorf("line %d: allowing %s is forbidden: a box reads named segments only", r.Line, op)
		}
		if len(r.Filters) == 0 {
			return fmt.Errorf("line %d: an unfiltered POSIX shared-memory allow", r.Line)
		}
		for _, f := range r.Filters {
			if f.Kind != "ipc-posix-name" {
				return fmt.Errorf("line %d: POSIX shared memory filtered by %s", r.Line, f.Kind)
			}
		}
	case op == "signal" || op == "process-info*":
		if len(r.Filters) != 1 || r.Filters[0].Kind != "target" {
			return fmt.Errorf("line %d: %s must be limited to (target same-sandbox)", r.Line, op)
		}
	}
	return nil
}

func hasOp(r Rule, op string) bool {
	for _, o := range r.Ops {
		if o == op {
			return true
		}
	}
	return false
}

// localhostPort accepts "localhost:N" with a numeric port in range only (no
// wildcard host, no wildcard port): the shape that keeps a box off every
// other address, a provider's literal IP included.
func localhostPort(v string) error {
	host, port, ok := strings.Cut(v, ":")
	if !ok || host != "localhost" {
		return fmt.Errorf("remote ip %q: only localhost is accepted", v)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("remote ip %q: the port must be a number in range", v)
	}
	return nil
}
