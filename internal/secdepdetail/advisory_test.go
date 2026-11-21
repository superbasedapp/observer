package secdepdetail

import (
	"reflect"
	"strings"
	"testing"
)

const lodashRecord = `{
  "id": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337", "bad id!"],
  "summary": "Command\u0007 Injection\nin lodash‮",
  "details": "line one\r\nline two\u0000",
  "published": "2021-02-15T11:46:48Z",
  "modified": "2024-01-01T10:00:00.123+02:00",
  "severity": [
    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
    {"type": "CVSS_V3", "score": "not a vector <script>"}
  ],
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "lodash"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
      "versions": ["4.17.19", "4.17.20"]
    },
    {
      "package": {"ecosystem": "npm", "name": "lodash-es"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]
    },
    {
      "package": {"ecosystem": "npm", "name": "lodash"},
      "ranges": [{"type": "GIT", "repo": "https://example.invalid/r", "events": [{"introduced": "abc"}, {"fixed": "def"}]}]
    }
  ],
  "references": [
    {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
    {"type": "WEB", "url": "javascript:alert(1)"},
    {"type": "WEB", "url": "ftp://example.invalid/x"},
    {"type": "package", "url": "http://example.invalid/lodash"}
  ],
  "database_specific": {"cwe_ids": ["CWE-94", "CWE-77", "nope"], "severity": "HIGH", "github_reviewed": true}
}`

// TestParseAdvisory: the record's own fields cleaned and capped, only the
// package's affected entries, only http(s) references.
func TestParseAdvisory(t *testing.T) {
	a, err := ParseAdvisory([]byte(lodashRecord), Package{"npm", "lodash", "4.17.20"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "GHSA-35jh-r3h4-6jhm" || !reflect.DeepEqual(a.Aliases, []string{"CVE-2021-23337"}) {
		t.Fatalf("ids: %+v", a)
	}
	if a.Summary != "Command Injection in lodash" {
		t.Fatalf("summary not cleaned: %q", a.Summary)
	}
	if a.Details != "line one\nline two" || a.DetailsTruncated {
		t.Fatalf("details: %q", a.Details)
	}
	if a.Published != "2021-02-15T11:46:48Z" || a.Modified != "2024-01-01T08:00:00Z" {
		t.Fatalf("times: %q %q", a.Published, a.Modified)
	}
	if !reflect.DeepEqual(a.CWE, []string{"CWE-94", "CWE-77"}) {
		t.Fatalf("cwe: %v", a.CWE)
	}
	if !reflect.DeepEqual(a.CVSS, []string{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}) {
		t.Fatalf("cvss: %v", a.CVSS)
	}
	wantRefs := []Reference{
		{"ADVISORY", "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
		{"PACKAGE", "http://example.invalid/lodash"},
	}
	if !reflect.DeepEqual(a.References, wantRefs) {
		t.Fatalf("refs: %+v", a.References)
	}
	if !a.MatchesPackage || a.ExplicitVersions != 2 || !reflect.DeepEqual(a.Ranges, []Range{{Introduced: "0", Fixed: "4.17.21"}}) {
		t.Fatalf("affected: %+v", a)
	}
}

// TestParseAdvisoryGoSymbolsAndPEP503: Go imports become affected symbols;
// a PyPI name matches across PEP 503 spellings; last_affected closes a
// range.
func TestParseAdvisoryGoSymbolsAndPEP503(t *testing.T) {
	goRec := `{"id":"GO-2022-1059","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"},
	  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.3.8"}]}],
	  "ecosystem_specific":{"imports":[{"path":"golang.org/x/text/language","symbols":["Parse","MatchStrings"]}]}}]}`
	a, err := ParseAdvisory([]byte(goRec), Package{"Go", "golang.org/x/text", "v0.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.AffectedSymbols, []string{"golang.org/x/text/language.Parse", "golang.org/x/text/language.MatchStrings"}) {
		t.Fatalf("symbols: %v", a.AffectedSymbols)
	}
	pyRec := `{"id":"PYSEC-1","affected":[{"package":{"ecosystem":"PyPI","name":"Zope.Interface"},
	  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"last_affected":"2.0"}]}]}]}`
	p, err := ParseAdvisory([]byte(pyRec), Package{"PyPI", "zope-interface", "1.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.MatchesPackage || !reflect.DeepEqual(p.Ranges, []Range{{Introduced: "1.0", LastAffected: "2.0"}}) {
		t.Fatalf("pypi: %+v", p)
	}
}

// TestParseAdvisoryCapsAndRefusals: details over the cap are cut on a rune
// boundary and flagged; a record with no valid id, bad JSON, or over the
// size cap is refused.
func TestParseAdvisoryCapsAndRefusals(t *testing.T) {
	long := strings.Repeat("é", MaxDetailsBytes) // 2 bytes each
	a, err := ParseAdvisory([]byte(`{"id":"GHSA-a","details":"`+long+`"}`), Package{"npm", "x", "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.DetailsTruncated || len(a.Details) > MaxDetailsBytes || !strings.HasSuffix(a.Details, "é") {
		t.Fatalf("details cap: %d %v", len(a.Details), a.DetailsTruncated)
	}
	for name, raw := range map[string]string{
		"no id":    `{"summary":"x"}`,
		"bad id":   `{"id":"../etc"}`,
		"bad json": `{"id":`,
		"too big":  `{"id":"GHSA-a","details":"` + strings.Repeat("a", MaxRecordBytes) + `"}`,
	} {
		if _, err := ParseAdvisory([]byte(raw), Package{"npm", "x", "1"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
