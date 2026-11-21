package secdepdetail

import (
	"errors"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestParsePackage: only a dependency finding's evidence is read, split on
// the last '@' so a scoped npm name keeps its own.
func TestParsePackage(t *testing.T) {
	dep := string(policy.FindingVulnerableDependency)
	cases := []struct {
		name, cat, ev string
		want          Package
		ok            bool
	}{
		{"plain", dep, "npm lodash@4.17.20", Package{"npm", "lodash", "4.17.20"}, true},
		{"scoped", dep, "npm @scope/pkg@1.2.3", Package{"npm", "@scope/pkg", "1.2.3"}, true},
		{"maven", dep, "Maven org.apache.logging.log4j:log4j-core@2.14.1", Package{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"}, true},
		{"crates", dep, "crates.io time@0.1.42", Package{"crates.io", "time", "0.1.42"}, true},
		{"secret category", string(policy.FindingSecret), "npm lodash@4.17.20", Package{}, false},
		{"no version", dep, "npm lodash", Package{}, false},
		{"scope only", dep, "npm @scope/pkg", Package{}, false},
		{"empty version", dep, "npm lodash@", Package{}, false},
		{"no ecosystem", dep, "lodash@1", Package{}, false},
		{"traversal ecosystem", dep, "../x lodash@1", Package{}, false},
		{"ecosystem with a space", dep, "GitHub Actions tj-actions/changed-files@v45.0.0", Package{"GitHub Actions", "tj-actions/changed-files", "v45.0.0"}, true},
		{"double space", dep, "GitHub  Actions a/b@v1", Package{}, false},
		{"leading space", dep, " npm lodash@1", Package{}, false},
	}
	for _, c := range cases {
		got, ok := ParsePackage(c.cat, c.ev)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v,%v want %+v,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestAdvisoryIDs: the rule id first, then the message's charset-checked
// ids, the elided tail dropped.
func TestAdvisoryIDs(t *testing.T) {
	got := AdvisoryIDs("CVE-2021-23337", "Known vulnerability in a npm dependency (CVE-2021-23337, GHSA-35jh-r3h4-6jhm, bad<id> and 3 more).")
	if !reflect.DeepEqual(got, []string{"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}) {
		t.Fatalf("ids: %v", got)
	}
	if got := AdvisoryIDs("", "no list"); len(got) != 0 {
		t.Fatalf("ids from nothing: %v", got)
	}
}

const buildLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": { "dependencies": { "lodash": "^4.17.20" } },
    "node_modules/lodash": {
      "version": "4.17.20"
    }
  }
}`

// TestBuild composes the package, the location, the relationship, the
// deduplicated local advisories and the fix.
func TestBuild(t *testing.T) {
	ghsa := `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command Injection",
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	// A second record of the same flaw (shares the CVE): deduplicated.
	dup := `{"id":"OSV-2021-1","aliases":["CVE-2021-23337"],"affected":[]}`
	var looked []string
	in := Input{
		Category: string(policy.FindingVulnerableDependency),
		Evidence: "npm lodash@4.17.20",
		RuleID:   "CVE-2021-23337",
		Message:  "Known vulnerability in a npm dependency (CVE-2021-23337, GHSA-35jh-r3h4-6jhm, OSV-2021-1).",
		RelPath:  "web/package-lock.json",
		ReadFile: func(rel string) ([]byte, error) {
			if rel != "web/package-lock.json" {
				t.Fatalf("read %q", rel)
			}
			return []byte(buildLock), nil
		},
		LookupRecord: func(eco, id string) ([]byte, error) {
			looked = append(looked, id)
			switch id {
			case "GHSA-35jh-r3h4-6jhm":
				return []byte(ghsa), nil
			case "OSV-2021-1":
				return []byte(dup), nil
			}
			return nil, ErrRecordNotFound
		},
	}
	d, ok := Build(in)
	if !ok {
		t.Fatal("not built")
	}
	if d.Package != (Package{"npm", "lodash", "4.17.20"}) || d.Relationship.Relationship != RelDirect || d.Scope != ScopeRuntime {
		t.Fatalf("package/relationship: %+v", d)
	}
	if !d.Location.Found || d.Location.StartLine != 5 || d.Location.EndLine != 7 {
		t.Fatalf("location: %+v", d.Location)
	}
	if d.AdvisorySource != SourceLocalDatabase || len(d.Advisories) != 1 || d.Advisories[0].ID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("advisories: %s %+v", d.AdvisorySource, d.Advisories)
	}
	// The GHSA is looked up first; the CVE its aliases name is never asked.
	if !reflect.DeepEqual(looked, []string{"GHSA-35jh-r3h4-6jhm", "OSV-2021-1"}) {
		t.Fatalf("lookups: %v", looked)
	}
	if d.SuggestedVersion != "4.17.21" || !reflect.DeepEqual(d.FixedVersions, []string{"4.17.21"}) {
		t.Fatalf("fix: %+v", d)
	}
}

// TestBuildHonestAbsences: every read that cannot answer says so.
func TestBuildHonestAbsences(t *testing.T) {
	base := Input{
		Category: string(policy.FindingVulnerableDependency), Evidence: "npm lodash@4.17.20",
		RuleID: "GHSA-35jh-r3h4-6jhm", Message: "Known vulnerability in a npm dependency (GHSA-35jh-r3h4-6jhm).",
		RelPath: "package-lock.json",
	}
	cases := []struct {
		name       string
		mut        func(*Input)
		reason     string
		source     string
		noReadFile bool
	}{
		{"database not installed", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return []byte(buildLock), nil }
			in.LookupRecord = func(string, string) ([]byte, error) { return nil, ErrDatabaseNotInstalled }
		}, "", SourceDatabaseNotInstalled, false},
		{"record not in database", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return []byte(buildLock), nil }
			in.LookupRecord = func(string, string) ([]byte, error) { return nil, ErrRecordNotFound }
		}, "", SourceNotInLocalDatabase, false},
		{"too large", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return nil, ErrFileTooLarge }
		}, ReasonFileTooLarge, SourceNotInLocalDatabase, false},
		{"outside project", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return nil, ErrOutsideProject }
		}, ReasonOutsideProject, SourceNotInLocalDatabase, false},
		{"unreadable", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return nil, errors.New("gone") }
		}, ReasonUnreadable, SourceNotInLocalDatabase, false},
		{"dotdot never read", func(in *Input) {
			in.RelPath = "../other/package-lock.json"
		}, ReasonOutsideProject, SourceNotInLocalDatabase, true},
		{"absolute never read", func(in *Input) {
			in.RelPath = "C:/x/package-lock.json"
		}, ReasonOutsideProject, SourceNotInLocalDatabase, true},
		{"unsupported never read", func(in *Input) {
			in.RelPath = "deps.lock"
		}, ReasonUnsupportedFormat, SourceNotInLocalDatabase, true},
		{"not in the file", func(in *Input) {
			in.ReadFile = func(string) ([]byte, error) { return []byte(`{"packages":{}}`), nil }
		}, ReasonNotFound, SourceNotInLocalDatabase, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.mut(&in)
			if c.noReadFile {
				in.ReadFile = func(rel string) ([]byte, error) { t.Fatalf("read %q", rel); return nil, nil }
			}
			d, ok := Build(in)
			if !ok {
				t.Fatal("not built")
			}
			if d.Location.Reason != c.reason || d.AdvisorySource != c.source {
				t.Fatalf("reason %q source %q, want %q %q", d.Location.Reason, d.AdvisorySource, c.reason, c.source)
			}
			if d.SuggestedVersion != "" {
				t.Fatalf("suggested a version with no advisory: %q", d.SuggestedVersion)
			}
		})
	}
	// A non-dependency finding is never built (its evidence never read).
	in := base
	in.Category = string(policy.FindingSecret)
	if _, ok := Build(in); ok {
		t.Fatal("built a secret finding")
	}
}
