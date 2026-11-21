package secreachgo

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// scannerJSON is a hand-written osv-scanner v2.6 --format json result of
// one go.mod run with --call-analysis=go, shaped like RG-0's fixtures f1
// to f5 (no path, environment or account in it).
const scannerJSON = `{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[
 {"package":{"name":"github.com/dgrijalva/jwt-go","version":"3.2.0+incompatible","ecosystem":"Go"},
  "groups":[{"ids":["GHSA-w73w-5m7g-f7qc","GO-2020-0017"],"aliases":["CVE-2020-26160","GHSA-w73w-5m7g-f7qc","GO-2020-0017"],
   "experimental_analysis":{"GO-2020-0017":{"called":true,"unimportant":false}},"max_severity":"7.5"}]},
 {"package":{"name":"golang.org/x/text","version":"0.3.5","ecosystem":"Go"},
  "groups":[{"ids":["GO-2021-0113"],"aliases":["GO-2021-0113"],"experimental_analysis":{"GO-2021-0113":{"called":false}}},
            {"ids":["GO-2022-1059"],"aliases":["GO-2022-1059"]}]},
 {"package":{"name":"golang.org/x/crypto","version":"0.0.0-20191206172530-e9b2fee46413","ecosystem":"Go"},
  "groups":[{"ids":["GO-2022-0229"],"aliases":["GO-2022-0229"],"experimental_analysis":{"GO-2022-0229":{"called":true}}}]},
 {"package":{"name":"stdlib","version":"1.27.0","ecosystem":"Go"},
  "groups":[{"ids":["GO-2026-1111"],"aliases":["GO-2026-1111"],"experimental_analysis":{"GO-2026-1111":{"called":false}}}]},
 {"package":{"name":"left-pad","version":"1.3.0","ecosystem":"npm"},
  "groups":[{"ids":["GHSA-npm"],"experimental_analysis":{"GHSA-npm":{"called":true}}}]}
]}]}`

func mods(mod string, pkgs ...PackageSymbols) map[string]ModuleImports {
	return map[string]ModuleImports{mod: {Packages: pkgs}}
}

func TestParseScannerOutput(t *testing.T) {
	gs, err := ParseScannerOutput([]byte(scannerJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 5 {
		t.Fatalf("groups = %d, want 5 (no npm group): %+v", len(gs), gs)
	}
	if gs[0].Module != "github.com/dgrijalva/jwt-go" || !gs[0].Analysis["GO-2020-0017"] {
		t.Errorf("first group = %+v", gs[0])
	}
	for _, g := range gs {
		if g.Module == "golang.org/x/text" && g.IDs[0] == "GO-2022-1059" && g.Analysis != nil {
			t.Errorf("a group without analysis kept one: %+v", g)
		}
	}
	if _, err := ParseScannerOutput([]byte("{")); err == nil {
		t.Error("broken JSON parsed")
	}
}

func TestSourceVerdicts(t *testing.T) {
	gs, err := ParseScannerOutput([]byte(scannerJSON))
	if err != nil {
		t.Fatal(err)
	}
	recs := map[string]RecordImports{
		"GO-2020-0017": {ID: "GO-2020-0017", Modules: mods("github.com/dgrijalva/jwt-go", PackageSymbols{Path: "github.com/dgrijalva/jwt-go", Symbols: []string{"MapClaims.VerifyAudience"}})},
		// A GitHub alias in the Go export lists no imports: it adds nothing.
		"GHSA-w73w-5m7g-f7qc": {ID: "GHSA-w73w-5m7g-f7qc", Modules: map[string]ModuleImports{"github.com/dgrijalva/jwt-go": {}}},
		"GO-2021-0113":        {ID: "GO-2021-0113", Modules: mods("golang.org/x/text", PackageSymbols{Path: "golang.org/x/text/language", Symbols: []string{"Parse"}})},
		// No analysis entry for this record: no claim.
		"GO-2022-1059": {ID: "GO-2022-1059", Modules: mods("golang.org/x/text", PackageSymbols{Path: "golang.org/x/text/language", Symbols: []string{"MatchStrings"}})},
		// Package only: osv-scanner's "called" is the package's init.
		"GO-2022-0229": {ID: "GO-2022-0229", Modules: mods("golang.org/x/crypto", PackageSymbols{Path: "golang.org/x/crypto/cryptobyte"})},
		"GO-2026-1111": {ID: "GO-2026-1111", Modules: mods("stdlib", PackageSymbols{Path: "net/http", Symbols: []string{"Serve"}})},
	}
	got := SourceVerdicts(SourceInput{Groups: gs, Records: recs})
	want := []secreach.SymbolRecord{
		{ID: "CVE-2020-26160", Module: "github.com/dgrijalva/jwt-go", Version: "3.2.0+incompatible", Verdict: secreach.VerdictCalled},
		{ID: "GHSA-w73w-5m7g-f7qc", Module: "github.com/dgrijalva/jwt-go", Version: "3.2.0+incompatible", Verdict: secreach.VerdictCalled},
		{ID: "GO-2020-0017", Module: "github.com/dgrijalva/jwt-go", Version: "3.2.0+incompatible", Verdict: secreach.VerdictCalled},
		{ID: "GO-2021-0113", Module: "golang.org/x/text", Version: "0.3.5", Verdict: secreach.VerdictNotCalled},
		{ID: "GO-2026-1111", Module: "stdlib", Version: "1.27.0", Verdict: secreach.VerdictNotCalled, AssumedGo: "1.27.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SourceVerdicts =\n%+v\nwant\n%+v", got, want)
	}
}

// TestSourceFactsMixedRecord: a record listing a whole package beside a
// package with symbols gets no claim either way.
func TestSourceFactsMixedRecord(t *testing.T) {
	mi := ModuleImports{Packages: []PackageSymbols{{Path: "m/a", Symbols: []string{"F"}}, {Path: "m/b"}}}
	for _, called := range []bool{true, false} {
		g := SourceGroup{Module: "m", IDs: []string{"GO-1"}, Analysis: map[string]bool{"GO-1": called}}
		if v := secreach.DecideSymbol(sourceFacts(g, "GO-1", mi)); v != secreach.VerdictNone {
			t.Errorf("called=%v: verdict %q, want no claim", called, v)
		}
	}
}

// TestRunRules has one case per runRules row, in table order.
func TestRunRules(t *testing.T) {
	ok := RunFacts{Exited: true}
	cases := []struct {
		row  string
		f    RunFacts
		want secreach.Reason
	}{
		{"timed out", RunFacts{TimedOut: true, Killed: true}, secreach.ReasonTimedOut},
		{"killed under the memory cap", RunFacts{Killed: true}, secreach.ReasonOutOfMemory},
		{"output or task cap", RunFacts{Capped: true}, secreach.ReasonSymbolCheckFailed},
		{"no toolchain", RunFacts{Exited: true, Stderr: "Skipping call analysis on Go code since Go is not installed.\n"}, secreach.ReasonNoToolchain},
		{"ran", ok, ""},
		{"ran", RunFacts{Exited: true, Stderr: "Scanned go.mod file and found 3 packages\n"}, ""},
		{"out of memory", RunFacts{Stderr: "fatal error: runtime: out of memory\n"}, secreach.ReasonOutOfMemory},
		{"out of memory", RunFacts{Exited: true, Stderr: "Failed to run code analysis (govulncheck) on 'go.mod' because signal: killed\n"}, secreach.ReasonOutOfMemory},
		{"toolchain too old", RunFacts{Exited: true, Stderr: "Failed to run code analysis (govulncheck) on 'go.mod' because go: go.mod requires go >= 1.99.0 (running go 1.27.3; GOTOOLCHAIN=local)\n"}, secreach.ReasonToolchainTooOld},
		{"modules missing", RunFacts{Exited: true, Stderr: "Failed to run code analysis (govulncheck) on 'go.mod' because example.com/m@v1.0.0: module lookup disabled by GOPROXY=off\n"}, secreach.ReasonModulesMissing},
		{"failed", RunFacts{Exited: true, Stderr: "Failed to run code analysis (govulncheck) on 'go.mod' because exit status 1\n"}, secreach.ReasonSymbolCheckFailed},
		{"failed", RunFacts{}, secreach.ReasonSymbolCheckFailed},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.row] = true
		if got := ClassifyRun(tc.f); got != tc.want {
			t.Errorf("%s: ClassifyRun(%+v) = %q, want %q", tc.row, tc.f, got, tc.want)
		}
	}
	for _, r := range runRules {
		if !seen[r.Name] {
			t.Errorf("runRules row %q has no test case", r.Name)
		}
	}
}

func TestGoModIDs(t *testing.T) {
	got := GoModIDs([]SourceGroup{{IDs: []string{"GO-2", "GHSA-a"}, Aliases: []string{"CVE-1", "GO-2"}}, {IDs: []string{"GO-1"}}})
	if want := []string{"CVE-1", "GHSA-a", "GO-1", "GO-2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("GoModIDs = %v, want %v", got, want)
	}
}
