package secdiffobs

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func ids(obs []Observation) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.RuleID)
	}
	return out
}

// TestObserveTable is one case per rule row plus clean shapes.
func TestObserveTable(t *testing.T) {
	cases := []struct {
		name string
		f    FileDiff
		want []string
	}{
		{"S-761 python verify=False", FromEdit("svc/client.py", "", "r = requests.get(u, verify=False)\n"), []string{"S-761"}},
		{"S-761 go InsecureSkipVerify", FromEdit("net/c.go", "", "cfg := &tls.Config{InsecureSkipVerify: true}\n"), []string{"S-761"}},
		{"S-761 node env", FromEdit("start.sh", "", "export NODE_TLS_REJECT_UNAUTHORIZED=0\n"), []string{"S-761"}},
		{"S-761 curl -k", FromEdit("deploy.sh", "", "curl -k https://x\n"), []string{"S-761"}},
		{"verify=True is clean", FromEdit("svc/client.py", "", "requests.get(u, verify=True)\n"), nil},
		{"S-767 pytest skip", FromEdit("tests/test_auth.py", "", "@pytest.mark.skip(reason='flaky')\n"), []string{"S-767"}},
		{"S-767 go t.Skip", FromEdit("pkg/a_test.go", "", "\tt.Skip(\"later\")\n"), []string{"S-767"}},
		{"S-767 jest only", FromEdit("web/a.test.ts", "", "it.only('x', () => {})\n"), []string{"S-767"}},
		{"S-767 deleted test", FileDiff{Path: "pkg/a_test.go", Deleted: true}, []string{"S-767"}},
		{"skip marker outside a test file", FromEdit("pkg/a.go", "", "t.Skip()\n"), nil},
		{"moved skip marker", FromEdit("tests/test_a.py", "@pytest.mark.skip\n", "@pytest.mark.skip\n"), nil},
		{"S-768 assertion removed", FromEdit("pkg/a_test.go", "\tif got != want {\n\t\tt.Fatalf(\"x\")\n\t}\n", "\t_ = got\n"), []string{"S-768"}},
		{"assertion reworded", FromEdit("pkg/a_test.go", "\tt.Fatalf(\"a\")\n", "\tt.Fatalf(\"b\")\n"), nil},
		{"S-769 nosec", FromEdit("pkg/a.go", "", "x := exec.Command(c) // #nosec G204\n"), []string{"S-769"}},
		{"S-769 eslint-disable", FromEdit("web/a.ts", "", "// eslint-disable-next-line\n"), []string{"S-769"}},
		{"S-769 nolint", FromEdit("pkg/a.go", "", "_ = f() //nolint:errcheck\n"), []string{"S-769"}},
		{"S-769 CI always true", FromEdit(".github/workflows/ci.yml", "", "      - run: go test ./... || true\n"), []string{"S-769"}},
		{"|| true outside CI", FromEdit("scripts/x.sh", "", "rm -f x || true\n"), nil},
		{"S-769 coverage lowered", FromEdit("setup.cfg", "fail_under = 90\n", "fail_under = 60\n"), []string{"S-769"}},
		{"coverage raised", FromEdit("setup.cfg", "fail_under = 60\n", "fail_under = 90\n"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ids(Observe([]FileDiff{tc.f})); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseUnifiedDiff(t *testing.T) {
	diff := "diff --git a/pkg/a_test.go b/pkg/a_test.go\n--- a/pkg/a_test.go\n+++ b/pkg/a_test.go\n@@ -10,3 +10,2 @@ func TestX(t *testing.T) {\n \tgot := f()\n-\tif got != 1 {\n-\t\tt.Fatal(\"bad\")\n+\tt.Skip(\"later\")\n" +
		"diff --git a/old_test.go b/old_test.go\n--- a/old_test.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package x\n"
	files := ParseUnifiedDiff([]byte(diff))
	if len(files) != 2 || files[1].Path != "old_test.go" || !files[1].Deleted {
		t.Fatalf("files = %+v", files)
	}
	if files[0].Added[0].N != 11 || files[0].Removed[0].N != 11 {
		t.Fatalf("line numbers = %+v", files[0])
	}
	got := Observe(files)
	want := []Observation{
		{RuleID: "S-767", Path: "old_test.go", Message: ruleMsg["S-767"]},
		{RuleID: "S-767", Path: "pkg/a_test.go", Line: 11, Message: ruleMsg["S-767"]},
		{RuleID: "S-768", Path: "pkg/a_test.go", Line: 12, Message: ruleMsg["S-768"]},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observations = %+v\nwant %+v", got, want)
	}
}

func TestIsTestPath(t *testing.T) {
	cases := map[string]bool{"pkg/a_test.go": true, "tests/x.py": true, "test_a.py": true, "web/a.spec.ts": true, "pkg/a.go": false, "latest/x.go": false}
	for p, want := range cases {
		if IsTestPath(p) != want {
			t.Errorf("IsTestPath(%q) != %v", p, want)
		}
	}
}

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/secdiffobs is pure rules over diff text",
	})
}
