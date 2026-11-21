package secreachsvc

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func binRun(target string, v secreach.SymbolVerdict) secreach.SymbolRun {
	return secreach.SymbolRun{Source: secreach.SourceGovulncheckBinary, Target: target, Records: []secreach.SymbolRecord{
		{ID: "GO-2020-0017", Module: "github.com/dgrijalva/jwt-go", Version: "v3.2.0+incompatible", Verdict: v, Symbol: "jwt.MapClaims.VerifyAudience"},
	}}
}

func TestReplaceAndLoadSymbolRuns(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	src := secreach.SymbolRun{Source: secreach.SourceGovulncheckSource, Target: "go.mod", Reason: secreach.ReasonOutOfMemory}
	if err := ReplaceSymbolRuns(dir, hashA, secreach.SourceGovulncheckSource, []string{"go.mod"}, []secreach.SymbolRun{src}, now); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceSymbolRuns(dir, hashA, secreach.SourceGovulncheckBinary, nil, []secreach.SymbolRun{binRun("bin/a", secreach.VerdictCalled), binRun("bin/b", secreach.VerdictNotCalled)}, now); err != nil {
		t.Fatal(err)
	}
	got := LoadSymbolRuns(dir, hashA)
	if len(got) != 3 || got[0].Target != "bin/a" || got[2].Source != secreach.SourceGovulncheckSource {
		t.Fatalf("runs: %+v", got)
	}
	// A later scan replaces every binary check and keeps the source one.
	if err := ReplaceSymbolRuns(dir, hashA, secreach.SourceGovulncheckBinary, nil, []secreach.SymbolRun{binRun("bin/b", secreach.VerdictCalled)}, now); err != nil {
		t.Fatal(err)
	}
	got = LoadSymbolRuns(dir, hashA)
	if len(got) != 2 || got[0].Target != "bin/b" || got[0].Records[0].Verdict != secreach.VerdictCalled {
		t.Fatalf("after replace: %+v", got)
	}
	b, err := os.ReadFile(SymbolPath(dir, hashA))
	if err != nil || !strings.Contains(string(b), `"ran_at":"2026-11-04T12:00:00Z"`) || strings.Contains(string(b), dir) {
		t.Fatalf("file: %s %v", b, err)
	}
	// Clearing both sources removes the file.
	for _, s := range []string{secreach.SourceGovulncheckBinary, secreach.SourceGovulncheckSource} {
		if err := ReplaceSymbolRuns(dir, hashA, s, nil, nil, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(SymbolPath(dir, hashA)); !os.IsNotExist(err) {
		t.Fatalf("file left: %v", err)
	}
	if LoadSymbolRuns(dir, hashA) != nil {
		t.Fatal("runs after clearing")
	}
}

func TestSymbolPathRefusesOtherNames(t *testing.T) {
	for _, h := range []string{"", "../x", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 63) + "/"} {
		if SymbolPath("/s", h) != "" {
			t.Errorf("SymbolPath accepted %q", h)
		}
	}
	if err := ReplaceSymbolRuns(t.TempDir(), "../x", secreach.SourceGovulncheckBinary, nil, nil, time.Now()); err == nil {
		t.Error("a bad hash was written")
	}
}

func TestCleanSymbolRun(t *testing.T) {
	bad := []secreach.SymbolRun{
		{Source: "osv-scanner", Target: "bin/a"},
		{Source: secreach.SourceGovulncheckBinary, Target: "/abs/bin"},
		{Source: secreach.SourceGovulncheckBinary, Target: "../out/bin"},
		{Source: secreach.SourceGovulncheckBinary, Target: `bin\a`},
		{Source: secreach.SourceGovulncheckBinary, Target: "C:/x"},
		{Source: secreach.SourceGovulncheckBinary, Target: "bin/./a"},
		{Source: secreach.SourceGovulncheckBinary, Target: "bin/a", Reason: "engine said: something"},
	}
	for _, r := range bad {
		if _, ok := CleanSymbolRun(r); ok {
			t.Errorf("accepted %+v", r)
		}
	}
	r := binRun("bin/a", secreach.VerdictCalled)
	r.Records = append(r.Records,
		secreach.SymbolRecord{ID: "GO 1; rm -rf", Module: "m", Verdict: secreach.VerdictCalled},
		secreach.SymbolRecord{ID: "GO-1", Module: "m", Verdict: "reachable"},
		secreach.SymbolRecord{ID: "GO-1", Module: "m", Verdict: secreach.VerdictCalled, Symbol: "a b"},
		secreach.SymbolRecord{ID: "GO-1", Module: "stdlib", Version: "1.27.3", Verdict: secreach.VerdictNotCalled},
	)
	c, ok := CleanSymbolRun(r)
	if !ok || len(c.Records) != 2 || c.Records[1].Module != "stdlib" {
		t.Fatalf("clean: %+v %v", c, ok)
	}
}
