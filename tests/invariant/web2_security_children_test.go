package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// web2_security_children_test.go pins R3-62: the org dashboard's security
// floor form lists the security child components a body may name
// (SECURITY_CHILDREN in web2/src/pages/policyforms/securityScanningModel.ts).
// It had drifted behind the Go vocabulary (securityscanning.Children), so a
// required scan.sarif-import / scan.actionlint / scan.trivy / scan.kics
// survived a publish but could not be seen or edited in the form. Every Go
// child must have a web2 row with the same id and component, and the row's
// "risky" flag must equal StartsProcess || MakesEgress.

// web2SecurityChildRow matches one SECURITY_CHILDREN entry.
var web2SecurityChildRow = regexp.MustCompile(`\{\s*id:\s*"([^"]+)",\s*component:\s*"([^"]+)",\s*label:\s*"[^"]*",\s*risky:\s*(true|false)\s*\}`)

func TestWeb2SecurityChildrenCoverTheGoVocabulary(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "web2")
	path := filepath.Join(repoRoot(t), "web2", "src", "pages", "policyforms", "securityScanningModel.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "export const SECURITY_CHILDREN")
	if start < 0 {
		t.Fatalf("%s no longer declares SECURITY_CHILDREN; update this test", path)
	}
	end := strings.Index(src[start:], "];")
	if end < 0 {
		t.Fatalf("SECURITY_CHILDREN in %s is not a closed array literal", path)
	}
	type row struct {
		component string
		risky     bool
	}
	web := map[string]row{}
	for _, m := range web2SecurityChildRow.FindAllStringSubmatch(src[start:start+end], -1) {
		web[m[1]] = row{component: m[2], risky: m[3] == "true"}
	}
	var missing []string
	for _, c := range securityscanning.Children {
		w, ok := web[c.ID]
		if !ok {
			missing = append(missing, c.ID)
			continue
		}
		if w.component != c.Component {
			t.Errorf("web2 row %q names component %q, want %q", c.ID, w.component, c.Component)
		}
		if want := c.StartsProcess || c.MakesEgress; w.risky != want {
			t.Errorf("web2 row %q risky = %v, want %v (StartsProcess || MakesEgress)", c.ID, w.risky, want)
		}
		delete(web, c.ID)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("web2 SECURITY_CHILDREN lacks the Go children %v: a floor requiring them cannot be seen or edited", missing)
	}
	for id := range web {
		t.Errorf("web2 SECURITY_CHILDREN row %q is not in securityscanning.Children", id)
	}
}
