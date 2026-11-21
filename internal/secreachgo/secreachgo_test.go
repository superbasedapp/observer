package secreachgo

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// TestInspectTestBinary: `go test` links its binary with -s -w, so the
// running test binary is a stripped canary of the host's format.
func TestInspectTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no test executable: %v", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = f.Close() }()
	got := Inspect(f)
	want := map[string]Format{"linux": FormatELF, "windows": FormatPE, "darwin": FormatMachO}[runtime.GOOS]
	if want != "" && got.Format != want {
		t.Fatalf("format %q, want %q", got.Format, want)
	}
	if got.Checkable {
		t.Skip("this toolchain kept the test binary's symbols; the toolchain test covers both shapes")
	}
	if got.Reason != secreach.ReasonStripped {
		t.Fatalf("stripped test binary: %+v", got)
	}
}

func TestInspectFormats(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want Inspection
	}{
		{"nothing", nil, Inspection{Format: FormatUnknown, Reason: secreach.ReasonUnsupportedBinary}},
		{"a script", []byte("#!/bin/sh\necho hi\n"), Inspection{Format: FormatUnknown, Reason: secreach.ReasonUnsupportedBinary}},
		{"webassembly", []byte("\x00asm\x01\x00\x00\x00"), Inspection{Format: FormatUnknown, Reason: secreach.ReasonUnsupportedBinary}},
		{"universal mach-o", []byte("\xca\xfe\xba\xbe\x00\x00\x00\x02"), Inspection{Format: FormatUnknown, Reason: secreach.ReasonUnsupportedBinary}},
		{"an ELF header only", append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 57)...), Inspection{Format: FormatELF, Reason: secreach.ReasonStripped}},
		{"a PE stub only", append([]byte("MZ"), make([]byte, 62)...), Inspection{Format: FormatPE, Reason: secreach.ReasonStripped}},
		{"a mach-o header only", append([]byte("\xcf\xfa\xed\xfe"), make([]byte, 28)...), Inspection{Format: FormatMachO, Reason: secreach.ReasonStripped}},
	}
	for _, tc := range cases {
		if got := Inspect(bytes.NewReader(tc.head)); got != tc.want {
			t.Errorf("%s: Inspect = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

const recordF4 = `{"id":"GO-2021-0113","aliases":["CVE-2021-38561","GHSA-ppp9-7jff-5vj2"],"summary":"never read",
"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"},"ecosystem_specific":{"imports":[
 {"path":"golang.org/x/text/language","symbols":["Parse","MatchStrings"]},
 {"path":"golang.org/x/text/language","symbols":["Parse"]},
 {"path":"golang.org/x/text/internal/language","symbols":["Parse"]}]}},
 {"package":{"ecosystem":"npm","name":"golang.org/x/text"},"ecosystem_specific":{"imports":[{"path":"x","symbols":["Y"]}]}}]}`

func TestParseRecord(t *testing.T) {
	r, err := ParseRecord([]byte(recordF4))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "GO-2021-0113" || len(r.Aliases) != 2 {
		t.Fatalf("ids: %+v", r)
	}
	mi := r.Modules["golang.org/x/text"]
	if len(r.Modules) != 1 || len(mi.Packages) != 2 {
		t.Fatalf("modules: %+v", r.Modules)
	}
	if p := mi.Packages[1]; p.Path != "golang.org/x/text/language" || strings.Join(p.Symbols, ",") != "MatchStrings,Parse" {
		t.Fatalf("merged package: %+v", p)
	}
	// A package listed once with symbols and once without is the whole
	// package.
	r2, err := ParseRecord([]byte(`{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"m"},"ecosystem_specific":{"imports":[{"path":"m/p","symbols":["F"]},{"path":"m/p"}]}},{"package":{"ecosystem":"Go","name":"n"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p := r2.Modules["m"].Packages[0]; len(p.Symbols) != 0 {
		t.Fatalf("whole package: %+v", p)
	}
	if mi, ok := r2.Modules["n"]; !ok || len(mi.Packages) != 0 {
		t.Fatalf("module with no imports: %+v %v", mi, ok)
	}
	if _, err := ParseRecord([]byte("{")); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

const stream = `{"config":{"protocol_version":"v1.0.0","scan_mode":"binary"}}
{"progress":{"message":"Scanning your binary for known vulnerabilities..."}}
{"osv":{"id":"GO-1","summary":"never read"}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/m","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/m","version":"v1.0.0","package":"example.com/m/p"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/m","version":"v1.0.0","package":"example.com/m/p","function":"Bad","receiver":"*T"}]}}
{"finding":{"osv":"","trace":[{"module":"x"}]}}
{"finding":{"osv":"GO-2","trace":[]}}
`

func TestParseStream(t *testing.T) {
	tr, err := ParseStream(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 3 {
		t.Fatalf("traces: %+v", tr)
	}
	if tr[0].Level() != "module" || tr[1].Level() != "package" || tr[2].Level() != "symbol" || tr[2].Symbol() != "T.Bad" || qualified(tr[2]) != "p.T.Bad" {
		t.Fatalf("levels: %+v", tr)
	}
	if _, err := ParseStream(strings.NewReader(`{"finding":`)); err == nil {
		t.Fatal("a cut stream was accepted")
	}
}

// rec builds a parsed record for module example.com/m.
func rec(id string, pkgs ...PackageSymbols) RecordImports {
	return RecordImports{ID: id, Modules: map[string]ModuleImports{"example.com/m": {Packages: pkgs}}}
}

func trace(id, pkg, fn string) Trace {
	return Trace{OSV: id, Module: "example.com/m", Version: "v1.0.0", Package: pkg, Function: fn}
}

// TestVerdicts covers RG-0's fixture shapes: a listed symbol called (f1),
// the package linked but the symbol not (f2, f7), a package-only record
// (f5), a record without imports (f6), a GitHub alias riding its Go group,
// a mixed record, a record govulncheck did not report, and a failed run.
func TestVerdicts(t *testing.T) {
	sym := func(p string, s ...string) PackageSymbols { return PackageSymbols{Path: p, Symbols: s} }
	adv := func(id string, aliases ...string) Advisory {
		return Advisory{ID: id, Aliases: aliases, Module: "example.com/m", Version: "v1.0.0"}
	}
	in := Input{
		Advisories: []Advisory{
			adv("GO-1", "GHSA-1"), adv("GHSA-1", "GO-1"), // called, with its alias
			adv("GO-2"), // package linked, symbol not
			adv("GO-3"), // package-only record
			adv("GO-4"), // no imports
			adv("GO-5"), // mixed, the listed symbol called
			adv("GO-6"), // mixed, nothing called
			adv("GO-7"), // not reported by govulncheck
			adv("GO-8"), // no record read
		},
		Records: map[string]RecordImports{
			"GO-1":   rec("GO-1", sym("example.com/m/p", "Bad")),
			"GHSA-1": {ID: "GHSA-1", Modules: map[string]ModuleImports{"example.com/m": {}}},
			"GO-2":   rec("GO-2", sym("example.com/m/p", "Other")),
			"GO-3":   rec("GO-3", sym("example.com/m/q")),
			"GO-4":   {ID: "GO-4", Modules: map[string]ModuleImports{"example.com/m": {}}},
			"GO-5":   rec("GO-5", sym("example.com/m/p", "Bad"), sym("example.com/m/q")),
			"GO-6":   rec("GO-6", sym("example.com/m/p", "Other"), sym("example.com/m/q")),
			"GO-7":   rec("GO-7", sym("example.com/m/p", "Bad")),
		},
		Traces: []Trace{
			trace("GO-1", "", ""), trace("GO-1", "example.com/m/p", ""), trace("GO-1", "example.com/m/p", "Bad"),
			trace("GHSA-1", "example.com/m/p", "Init"),
			trace("GO-2", "", ""), trace("GO-2", "example.com/m/p", ""),
			trace("GO-3", "example.com/m/q", "init"),
			trace("GO-4", "example.com/m/p", "Bad"),
			trace("GO-5", "example.com/m/p", "Bad"), trace("GO-5", "example.com/m/q", "init"),
			trace("GO-6", "example.com/m/q", "init"),
		},
	}
	got := map[string]secreach.SymbolRecord{}
	for _, r := range Verdicts(in) {
		got[r.ID] = r
	}
	want := map[string]secreach.SymbolVerdict{
		"GO-1": secreach.VerdictCalled, "GHSA-1": secreach.VerdictCalled,
		"GO-2": secreach.VerdictNotCalled,
		"GO-5": secreach.VerdictCalled,
	}
	if len(got) != len(want) {
		t.Fatalf("records: %+v", got)
	}
	for id, v := range want {
		if got[id].Verdict != v || got[id].Version != "v1.0.0" {
			t.Errorf("%s: %+v, want %q", id, got[id], v)
		}
	}
	if got["GO-1"].Symbol != "p.Bad" {
		t.Errorf("called symbol: %+v", got["GO-1"])
	}
	in.Failed = secreach.ReasonStripped
	for _, r := range Verdicts(in) {
		if r.Verdict != secreach.VerdictUnknown {
			t.Errorf("failed run: %+v", r)
		}
	}
}

func TestCombineRowsOrder(t *testing.T) {
	cases := []struct {
		in   []secreach.SymbolVerdict
		want secreach.SymbolVerdict
	}{
		{nil, secreach.VerdictNone},
		{[]secreach.SymbolVerdict{secreach.VerdictNotCalled, secreach.VerdictCalled}, secreach.VerdictCalled},
		{[]secreach.SymbolVerdict{secreach.VerdictNotCalled, secreach.VerdictUnknown}, secreach.VerdictUnknown},
		{[]secreach.SymbolVerdict{secreach.VerdictNotCalled, secreach.VerdictNone}, secreach.VerdictNone},
		{[]secreach.SymbolVerdict{secreach.VerdictNotCalled}, secreach.VerdictNotCalled},
	}
	for _, tc := range cases {
		vs := make([]memberVerdict, 0, len(tc.in))
		for _, v := range tc.in {
			vs = append(vs, memberVerdict{verdict: v})
		}
		if got, _ := combine(vs); got != tc.want {
			t.Errorf("combine(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
