package secdepdetail

import (
	"reflect"
	"testing"
)

const reachGoRecord = `{"id":"GO-2024-0001","aliases":["CVE-2024-1","GHSA-aaaa-bbbb-cccc"],
"summary":"prose that is never read here",
"affected":[
 {"package":{"ecosystem":"Go","name":"golang.org/x/net"},
  "ecosystem_specific":{"imports":[{"path":"golang.org/x/net/html","symbols":["Parse"]},{"path":"golang.org/x/net/html"},{"path":"bad path"},{"path":"golang.org/x/net/http2"}]}},
 {"package":{"ecosystem":"Go","name":"golang.org/x/text"},
  "ecosystem_specific":{"imports":[{"path":"golang.org/x/text/language"}]}}
]}`

func TestParseAffectedImports(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		pkg   Package
		want  AffectedImports
		isErr bool
	}{
		{
			name: "the entries naming the package, deduplicated and charset-checked",
			raw:  reachGoRecord,
			pkg:  Package{"Go", "golang.org/x/net", "v0.1.0"},
			want: AffectedImports{
				ID: "GO-2024-0001", Aliases: []string{"CVE-2024-1", "GHSA-aaaa-bbbb-cccc"}, MatchesPackage: true,
				ImportPaths: []string{"golang.org/x/net/html", "golang.org/x/net/http2"},
			},
		},
		{
			name: "a record that does not name the package",
			raw:  reachGoRecord,
			pkg:  Package{"Go", "golang.org/x/crypto", "v0.1.0"},
			want: AffectedImports{ID: "GO-2024-0001", Aliases: []string{"CVE-2024-1", "GHSA-aaaa-bbbb-cccc"}},
		},
		{
			name: "a record that lists no imports",
			raw:  `{"id":"GO-2024-0002","affected":[{"package":{"ecosystem":"Go","name":"github.com/a/b"}}]}`,
			pkg:  Package{"Go", "github.com/a/b", "v1.0.0"},
			want: AffectedImports{ID: "GO-2024-0002", MatchesPackage: true},
		},
		{name: "not JSON", raw: `{`, pkg: Package{"Go", "x", "1"}, isErr: true},
		{name: "no valid id", raw: `{"id":"a/b"}`, pkg: Package{"Go", "x", "1"}, isErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAffectedImports([]byte(tc.raw), tc.pkg)
			if tc.isErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLookupAffectedImports(t *testing.T) {
	alias := `{"id":"GHSA-aaaa-bbbb-cccc","aliases":["GO-2024-0001"],"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"}}]}`
	db := map[string]string{"GO-2024-0001": reachGoRecord, "GHSA-aaaa-bbbb-cccc": alias}
	lookup := func(eco, id string) ([]byte, error) {
		if eco != "Go" {
			return nil, ErrDatabaseNotInstalled
		}
		if r, ok := db[id]; ok {
			return []byte(r), nil
		}
		return nil, ErrRecordNotFound
	}
	dep := Input{
		Category: "vulnerable_dependency", Evidence: "Go golang.org/x/net@v0.1.0",
		RuleID: "GO-2024-0001", Message: "Known vulnerability in a Go dependency (GO-2024-0001, GHSA-aaaa-bbbb-cccc).",
		LookupRecord: lookup,
	}
	cases := []struct {
		name    string
		in      Input
		ok      bool
		wantIDs []string
	}{
		{name: "one record per alias group, the one listing import paths (the GO record replaces the GHSA read first)", in: dep, ok: true, wantIDs: []string{"GO-2024-0001"}},
		{name: "not a dependency finding", in: Input{Category: "secret", Evidence: "Go x@1"}, ok: false},
		{name: "no lookup", in: Input{Category: dep.Category, Evidence: dep.Evidence, RuleID: dep.RuleID}, ok: true},
		{name: "database not installed", in: Input{Category: dep.Category, Evidence: "npm lodash@1.0.0", RuleID: "GHSA-aaaa-bbbb-cccc", LookupRecord: lookup}, ok: true},
		{name: "a record not in the database", in: Input{Category: dep.Category, Evidence: dep.Evidence, RuleID: "GO-2099-9999", LookupRecord: lookup}, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, recs, ok := LookupAffectedImports(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			var ids []string
			for _, r := range recs {
				ids = append(ids, r.ID)
			}
			if !reflect.DeepEqual(ids, tc.wantIDs) {
				t.Fatalf("ids = %v, want %v", ids, tc.wantIDs)
			}
			if ok && pkg.Name == "" {
				t.Fatalf("ok with no package")
			}
		})
	}
}

// reachRustRecord is a RUSTSEC-shaped record (synthetic ids and names).
const reachRustRecord = `{"id":"RUSTSEC-2099-0001","aliases":["GHSA-rrrr-ssss-tttt"],
"affected":[
 {"package":{"ecosystem":"crates.io","name":"smallvec"},
  "ecosystem_specific":{"affects":{"arch":[],"os":[],"functions":["smallvec::SmallVec::insert_many","smallvec::SmallVec::insert_many","not a path","smallvec::SmallVec<T>::grow","single"]}}}
]}`

func TestParseAffectedFunctions(t *testing.T) {
	got, err := ParseAffectedImports([]byte(reachRustRecord), Package{"crates.io", "smallvec", "1.6.0"})
	if err != nil {
		t.Fatal(err)
	}
	want := AffectedImports{
		ID: "RUSTSEC-2099-0001", Aliases: []string{"GHSA-rrrr-ssss-tttt"}, MatchesPackage: true,
		Functions: []string{"smallvec::SmallVec::insert_many"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestLookupAffectedFunctionsKeepsTheDetailedRecord(t *testing.T) {
	ghsa := `{"id":"GHSA-rrrr-ssss-tttt","aliases":["RUSTSEC-2099-0001"],"affected":[{"package":{"ecosystem":"crates.io","name":"smallvec"}}]}`
	db := map[string]string{"RUSTSEC-2099-0001": reachRustRecord, "GHSA-rrrr-ssss-tttt": ghsa}
	lookup := func(_, id string) ([]byte, error) {
		if r, ok := db[id]; ok {
			return []byte(r), nil
		}
		return nil, ErrRecordNotFound
	}
	_, recs, ok := LookupAffectedImports(Input{
		Category: "vulnerable_dependency", Evidence: "crates.io smallvec@1.6.0",
		RuleID: "GHSA-rrrr-ssss-tttt", Message: "Known vulnerability (GHSA-rrrr-ssss-tttt, RUSTSEC-2099-0001).",
		LookupRecord: lookup,
	})
	if !ok || len(recs) != 1 || recs[0].ID != "RUSTSEC-2099-0001" || len(recs[0].Functions) != 1 {
		t.Fatalf("recs = %+v, ok %v; want the RUSTSEC record with its function", recs, ok)
	}
}
