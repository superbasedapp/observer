//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// gomatch_test.go: SECP-43, the Go modules whose path has a capital letter.
// Tiny synthetic Go exports only; the real export is ~13 MB and is never
// loaded by a unit test.

const (
	// azRec is a record for a mixed-case module: affected from the start up
	// to (excluding) 1.6.0, shaped like the real export's GO-2024-2918.
	azRec = `{"id":"GO-2024-2918","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-35255","GHSA-rg2h-7jwp-rmcm"],
"affected":[{"package":{"ecosystem":"Go","name":"github.com/Azure/azure-sdk-for-go/sdk/azidentity"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.6.0"}]}]}],
"database_specific":{"severity":"MODERATE"}}`
	// azVersionsRec lists the mixed-case module's exact versions only.
	azVersionsRec = `{"id":"GO-2099-0001","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Go","name":"github.com/BurntSushi/toml"},"versions":["1.2.0","1.3.0"]}]}`
	// azWithdrawn must never match.
	azWithdrawn = `{"id":"GO-2099-0002","modified":"2024-01-01T00:00:00Z","withdrawn":"2024-02-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Go","name":"github.com/Azure/azure-sdk-for-go/sdk/azidentity"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	// lowerRec is the all-lower-case module the existing path already matches.
	lowerRec = `{"id":"GO-2022-1059","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2022-32149"],
"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.3.8"}]}]}],
"database_specific":{"severity":"HIGH"}}`
	// otherCaseRec names the same module in another case: raw equality is
	// case-sensitive, so it must not match.
	otherCaseRec = `{"id":"GO-2099-0003","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Go","name":"github.com/azure/azure-sdk-for-go/sdk/azidentity"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
)

func goInventory(pkgs ...Package) *Inventory {
	for i := range pkgs {
		pkgs[i].Ecosystem = "Go"
	}
	return NewInventory(pkgs)
}

func goDB(t *testing.T) string {
	t.Helper()
	db := t.TempDir()
	writeDB(t, db, "Go", map[string]string{
		"GO-2024-2918.json": azRec, "GO-2099-0001.json": azVersionsRec, "GO-2099-0002.json": azWithdrawn,
		"GO-2022-1059.json": lowerRec, "GO-2099-0003.json": otherCaseRec, "junk.txt": "not a record",
	})
	return db
}

func vulnKeys(inv *Inventory, res MatchResult) []string {
	var out []string
	for _, v := range res.Vulns {
		out = append(out, inv.Packages[v.Index].Name+"="+v.ID)
	}
	slices.Sort(out)
	return out
}

// TestGoMixedCaseModulesMatch is the SECP-43 regression: before the repair
// osvlocal never matched a module path with a capital letter.
func TestGoMixedCaseModulesMatch(t *testing.T) {
	inv := goInventory(
		Package{Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v0.0.1"},
		Package{Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v1.6.0"}, // fixed: clean
		Package{Name: "github.com/BurntSushi/toml", Version: "v1.3.0"},                       // exact versions entry
		Package{Name: "github.com/BurntSushi/toml", Version: "v1.4.0"},                       // not listed
		Package{Name: "golang.org/x/text", Version: "v0.3.5"},
	)
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "Go", Indices: []int{0, 1, 2, 3, 4}}, MatchOptions{DBDir: goDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"github.com/Azure/azure-sdk-for-go/sdk/azidentity=GO-2024-2918",
		"github.com/BurntSushi/toml=GO-2099-0001",
		"golang.org/x/text=GO-2022-1059",
	}
	if got := vulnKeys(inv, res); !slices.Equal(got, want) {
		t.Fatalf("matches %v, want %v", got, want)
	}
	for _, v := range res.Vulns {
		if v.ID == "GO-2024-2918" && (v.Index != 0 || v.Severity != "MODERATE" || !slices.Contains(v.Aliases, "CVE-2024-35255")) {
			t.Errorf("mixed-case finding lost index, severity or aliases: %+v", v)
		}
	}
}

// TestGoLowerCaseMatchesExactlyOnce pins the dedupe: an all-lower-case
// module is osvlocal's, and the supplement must not report it twice.
func TestGoLowerCaseMatchesExactlyOnce(t *testing.T) {
	inv := goInventory(Package{Name: "golang.org/x/text", Version: "v0.3.5"})
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "Go", Indices: []int{0}, Canary: &Canary{Name: "golang.org/x/text", Version: "v0.3.5"}}, MatchOptions{DBDir: goDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulns) != 1 || res.Vulns[0].ID != "GO-2022-1059" || !res.CanaryHit {
		t.Fatalf("got %+v canary=%v, want exactly GO-2022-1059 and a canary hit", res.Vulns, res.CanaryHit)
	}
}

// TestGoMixedCaseCanary: a canary named in mixed case matches too.
func TestGoMixedCaseCanary(t *testing.T) {
	inv := goInventory(Package{Name: "golang.org/x/text", Version: "v0.3.8"})
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "Go", Indices: []int{0}, Canary: &Canary{Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v0.0.1"}}, MatchOptions{DBDir: goDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CanaryHit || len(res.Vulns) != 0 {
		t.Fatalf("got %+v canary=%v, want a canary hit and no vulns", res.Vulns, res.CanaryHit)
	}
}

// TestGoMixedCaseMissingDatabase: no export is ErrNoDatabase, as before.
func TestGoMixedCaseMissingDatabase(t *testing.T) {
	inv := goInventory(Package{Name: "github.com/Azure/x", Version: "v1.0.0"})
	if _, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "Go", Indices: []int{0}}, MatchOptions{DBDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no local OSV database") {
		t.Fatalf("err=%v, want ErrNoDatabase", err)
	}
}

func TestHasUpper(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{{"golang.org/x/text", false}, {"github.com/Azure/x", true}, {"", false}, {"github.com/foo/ÄBC", true}} {
		if got := hasUpper(c.in); got != c.want {
			t.Errorf("hasUpper(%q)=%v, want %v", c.in, got, c.want)
		}
	}
}

// TestExtractedGoModuleMatches runs the whole path: a go.mod through the
// gomod extractor, then Match, so the raw module path the extractor reports
// is what the repair compares.
func TestExtractedGoModuleMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/Azure/azure-sdk-for-go/sdk/azidentity v0.0.1\n\tgolang.org/x/text v0.3.5\n)\n")
	writeFile(t, root, "go.sum", "github.com/Azure/azure-sdk-for-go/sdk/azidentity v0.0.1 h1:AAAA=\ngithub.com/Azure/azure-sdk-for-go/sdk/azidentity v0.0.1/go.mod h1:AAAA=\ngolang.org/x/text v0.3.5 h1:AAAA=\ngolang.org/x/text v0.3.5/go.mod h1:AAAA=\n")
	inv, err := Extract(context.Background(), root, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "Go", Indices: indices(inv, "Go")}, MatchOptions{DBDir: goDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github.com/Azure/azure-sdk-for-go/sdk/azidentity=GO-2024-2918", "golang.org/x/text=GO-2022-1059"}
	if got := vulnKeys(inv, res); !slices.Equal(got, want) {
		t.Fatalf("matches %v, want %v (packages %+v)", got, want, inv.Packages)
	}
}

// TestMergeGoMixedCaseDedupes: when osvlocal (a fixed SCALIBR) already
// reported the advisory for the package, the supplement adds nothing.
func TestMergeGoMixedCaseDedupes(t *testing.T) {
	inv := goInventory(Package{Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v0.0.1"})
	req := MatchRequest{Ecosystem: "Go", Indices: []int{0}}
	prior := MatchResult{Matcher: "vulnmatch/osvlocal", Vulns: []Vuln{{ID: "GO-2024-2918", Index: 0, Severity: "MODERATE"}}}
	res, err := mergeGoMixedCase(context.Background(), prior, inv, req, MatchOptions{DBDir: goDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulns) != 1 || res.Matcher != "vulnmatch/osvlocal" {
		t.Fatalf("got %+v, want the one prior finding", res)
	}
}
