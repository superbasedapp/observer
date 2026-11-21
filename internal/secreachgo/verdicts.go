package secreachgo

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Advisory is one advisory the scan matched against one Go package of the
// binary: its id and aliases, and the package (a module path, or
// "stdlib") and version the binary's build info names.
type Advisory struct {
	ID      string
	Aliases []string
	Module  string
	Version string
}

// Input is one binary's check.
type Input struct {
	// Advisories are the matched advisories of the binary's packages.
	Advisories []Advisory
	// Records are the OSV records read for them, by id (ParseRecord); an
	// id with no record adds nothing.
	Records map[string]RecordImports
	// Traces are govulncheck's findings for the binary (ParseStream).
	Traces []Trace
	// Failed is set when the check did not run to the end (or the binary
	// is stripped): every group is unknown.
	Failed secreach.Reason
}

// group is one flaw of one package: advisories joined by shared ids.
type group struct {
	module, version string
	ids             []string
}

// Verdicts decides every advisory group of the binary and returns one
// record per id of each group that has a claim (called, not called or
// unknown), sorted by module, version and id. A group's verdict combines
// its members that list imports for the module, through combineRows; a
// member that lists none (a GitHub advisory in the Go export) adds nothing.
func Verdicts(in Input) []secreach.SymbolRecord {
	var out []secreach.SymbolRecord
	for _, g := range groups(in.Advisories) {
		var vs []memberVerdict
		for _, id := range g.ids {
			rec, ok := in.Records[id]
			if !ok {
				continue
			}
			mi, ok := rec.Modules[g.module]
			if !ok || len(mi.Packages) == 0 {
				continue
			}
			f, sym := facts(in, id, g.module, mi)
			vs = append(vs, memberVerdict{verdict: secreach.DecideSymbol(f), symbol: sym})
		}
		v, sym := combine(vs)
		if v == secreach.VerdictNone {
			continue
		}
		for _, id := range g.ids {
			out = append(out, secreach.SymbolRecord{ID: id, Module: g.module, Version: g.version, Verdict: v, Symbol: sym})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ID < b.ID
	})
	return out
}

// facts builds one member record's facts from the stream.
func facts(in Input, id, module string, mi ModuleImports) (secreach.SymbolFacts, string) {
	f := secreach.SymbolFacts{Failed: in.Failed, ListsImports: true}
	withSymbols := map[string]bool{}
	for _, p := range mi.Packages {
		if len(p.Symbols) > 0 {
			f.ListsSymbols = true
			withSymbols[p.Path] = true
		} else {
			f.PackageWithoutSymbols = true
		}
	}
	symbol := ""
	for _, t := range in.Traces {
		if t.OSV != id || t.Module != module {
			continue
		}
		f.Analysed = true
		if t.Level() == "symbol" && withSymbols[t.Package] {
			if !f.SymbolTrace || qualified(t) < symbol {
				symbol = qualified(t)
			}
			f.SymbolTrace = true
		}
	}
	return f, symbol
}

// qualified is a trace's function with its package's last element
// ("jwt.MapClaims.VerifyAudience").
func qualified(t Trace) string {
	pkg := t.Package
	for i := len(pkg) - 1; i >= 0; i-- {
		if pkg[i] == '/' {
			pkg = pkg[i+1:]
			break
		}
	}
	if pkg == "" {
		return t.Symbol()
	}
	return pkg + "." + t.Symbol()
}

type memberVerdict struct {
	verdict secreach.SymbolVerdict
	symbol  string
}

// combineRows is the group table, walked top-down: the first verdict some
// member gave decides (called first; a member that could not decide or
// made no claim keeps the group from "not called").
var combineRows = []secreach.SymbolVerdict{
	secreach.VerdictCalled,
	secreach.VerdictUnknown,
	secreach.VerdictNone,
	secreach.VerdictNotCalled,
}

func combine(vs []memberVerdict) (secreach.SymbolVerdict, string) {
	if len(vs) == 0 {
		return secreach.VerdictNone, ""
	}
	for _, row := range combineRows {
		for _, v := range vs {
			if v.verdict == row {
				return row, v.symbol
			}
		}
	}
	return secreach.VerdictNone, ""
}

// groups joins the advisories of each (module, version) by shared ids
// (an advisory's id and its aliases, transitively), as depscan's alias
// grouping does for findings.
func groups(advs []Advisory) []group {
	type key struct{ module, version string }
	parent := map[key]map[string]string{}
	var find func(m map[string]string, x string) string
	find = func(m map[string]string, x string) string {
		if p, ok := m[x]; !ok || p == x {
			m[x] = x
			return x
		}
		r := find(m, m[x])
		m[x] = r
		return r
	}
	union := func(m map[string]string, a, b string) {
		ra, rb := find(m, a), find(m, b)
		if ra == rb {
			return
		}
		if ra < rb {
			m[rb] = ra
		} else {
			m[ra] = rb
		}
	}
	for _, a := range advs {
		if a.ID == "" || a.Module == "" {
			continue
		}
		k := key{a.Module, a.Version}
		m := parent[k]
		if m == nil {
			m = map[string]string{}
			parent[k] = m
		}
		find(m, a.ID)
		for _, al := range a.Aliases {
			if al != "" {
				union(m, a.ID, al)
			}
		}
	}
	keys := make([]key, 0, len(parent))
	for k := range parent {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].module != keys[j].module {
			return keys[i].module < keys[j].module
		}
		return keys[i].version < keys[j].version
	})
	var out []group
	for _, k := range keys {
		m := parent[k]
		members := map[string][]string{}
		for id := range m {
			r := find(m, id)
			members[r] = append(members[r], id)
		}
		roots := make([]string, 0, len(members))
		for r := range members {
			roots = append(roots, r)
		}
		sort.Strings(roots)
		for _, r := range roots {
			ids := members[r]
			sort.Strings(ids)
			out = append(out, group{module: k.module, version: k.version, ids: ids})
		}
	}
	return out
}
