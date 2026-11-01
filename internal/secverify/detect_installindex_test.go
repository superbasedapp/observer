package secverify

import (
	"context"
	"strings"
	"testing"
)

func fakeIndex(path, added string) ([]DependencyHit, bool) {
	if !isManifestPath(path) {
		return nil, false
	}
	var hits []DependencyHit
	if strings.Contains(added, "evil-pkg") {
		hits = append(hits, DependencyHit{Ecosystem: "npm", Name: "evil-pkg", Verdict: "malicious"})
	}
	if strings.Contains(added, "lodahs") {
		hits = append(hits, DependencyHit{Ecosystem: "npm", Name: "lodahs", Verdict: "near_miss", NearMiss: "lodash"})
	}
	return hits, true
}

func TestDetectInstallIndex(t *testing.T) {
	files := []ChangedFile{
		{Path: "web/package.json", Status: StatusModified, Added: []AddedLine{{N: 7, Text: `    "lodahs": "^1",`}, {N: 8, Text: `    "evil-pkg": "1.0.0",`}}},
		{Path: "main.go", Status: StatusModified, Added: []AddedLine{{N: 1, Text: "evil-pkg"}}},
	}
	res := detectInstallIndex(context.Background(), Input{Files: files, Dependencies: fakeIndex})
	if res.Coverage.Status != CoverageComplete || res.Coverage.Files != 1 || len(res.Findings) != 2 {
		t.Fatalf("result %+v", res)
	}
	var mal, near Finding
	for _, f := range res.Findings {
		if f.RuleID == "install/malicious" {
			mal = f
		} else {
			near = f
		}
	}
	if mal.DefaultAction != ActionDeny || mal.Line != 8 || near.DefaultAction != ActionFlag || near.Line != 7 || !strings.Contains(near.Message, "near lodash") {
		t.Errorf("findings %+v %+v", mal, near)
	}

	none := detectInstallIndex(context.Background(), Input{Files: files})
	if none.Coverage.Status != CoveragePartial || len(none.Findings) != 0 {
		t.Errorf("a changed manifest without an index must be partial: %+v", none.Coverage)
	}
	noManifest := detectInstallIndex(context.Background(), Input{Files: files[1:]})
	if noManifest.Coverage.Status != CoverageComplete {
		t.Errorf("no manifest changed: %+v", noManifest.Coverage)
	}
}

// TestInstallIndexRequiredWithoutIndexIsUnknown: a policy that requires the
// detector gets unknown, never pass, when no index was supplied.
func TestInstallIndexRequiredWithoutIndexIsUnknown(t *testing.T) {
	p := DefaultPolicy()
	p.Require = append(p.Require, "install_index")
	ns := []byte("M\x00package.json\x00")
	patch := []byte("diff --git a/package.json b/package.json\n--- a/package.json\n+++ b/package.json\n@@ -1,0 +2,1 @@\n+    \"evil-pkg\": \"1.0.0\",\n")
	rep := Verify(context.Background(), Request{Policy: p, NameStatus: ns, Patch: patch}, nil)
	if rep.Verdict != VerdictUnknown {
		t.Errorf("verdict %s (%s)", rep.Verdict, rep.Reason)
	}
	rep = Verify(context.Background(), Request{Policy: p, NameStatus: ns, Patch: patch, Dependencies: fakeIndex}, nil)
	if rep.Verdict != VerdictFail {
		t.Errorf("with an index: verdict %s (%s)", rep.Verdict, rep.Reason)
	}
}
