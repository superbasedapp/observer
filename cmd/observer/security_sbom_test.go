//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secinventory"
	"github.com/marmutapp/superbased-observer/internal/seclicense"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const testLock = `{"name":"app","lockfileVersion":3,"packages":{
 "":{"name":"app","version":"1.0.0"},
 "node_modules/left-pad":{"version":"1.3.0","license":"WTFPL"},
 "node_modules/agpl-thing":{"version":"2.0.0","license":"AGPL-3.0"}
}}`

// TestProjectSBOMAndLicences (security coverage gaps plan items 2 and 4):
// a stored inventory renders as CycloneDX with the licences the project's
// lockfile declares; a licence policy records flag-only findings that stay
// out of the commit gate, and a later complete read closes what it no
// longer sees.
func TestProjectSBOMAndLicences(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(testLock), 0o600); err != nil {
		t.Fatal(err)
	}
	secDir := t.TempDir()
	hash := secposture.ProjectRootHash(root)
	now := time.Now().UTC()
	snap := inventorySnapshot(depscan.OSVID, []depscan.Package{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "agpl-thing", Version: "2.0.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "workspace-member", Version: "0.0.1", Path: "package-lock.json", Local: true},
	}, now)
	if _, err := secinventory.Replace(secDir, hash, snap, now); err != nil {
		t.Fatal(err)
	}
	stored, ok := secinventory.Load(secDir, hash)
	if !ok || len(stored.Packages) != 2 {
		t.Fatalf("snapshot %+v %v: the local package must be left out", stored, ok)
	}
	doc, err := renderProjectSBOM(root, stored, projectLicenceMap(root, stored))
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Purl     string            `json:"purl"`
			Licenses []json.RawMessage `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || len(bom.Components) != 2 {
		t.Fatalf("bom %s: %v", doc, err)
	}
	if !strings.Contains(string(doc), "pkg:npm/left-pad@1.3.0") || !strings.Contains(string(doc), "AGPL-3.0-only") || strings.Contains(string(doc), root) {
		t.Fatalf("bom content %s", doc)
	}

	st, _ := openTestStore(t)
	p := seclicense.Policy{Deny: []string{string(seclicense.ClassOf("AGPL-3.0-only"))}}
	if _, err := recordProjectLicences(ctx, st, root, p, walkProjectLicences(ctx, root), now); err != nil {
		t.Fatal(err)
	}
	open := func() []secfinding.Finding {
		got, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := open()
	if len(got) != 1 || got[0].Category != policy.FindingLicense || got[0].Rule.ID != seclicense.RuleDenied ||
		got[0].Severity != policy.FindingSeverityMedium || got[0].Baseline != policy.FindingBaselineUnknown || got[0].Location.RelPath != "package-lock.json" {
		t.Fatalf("licence findings %+v", got)
	}
	sev := []secfinding.Severity{policy.FindingSeverityInfo, policy.FindingSeverityLow, policy.FindingSeverityMedium, policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	if keys, err := st.SecBlockingKeys(ctx, store.SecBlockingQuery{ProjectRootHash: hash, Severities: sev, IncludeUntrusted: true}, 10); err != nil || len(keys) != 0 {
		t.Fatalf("a licence finding is in the commit gate's blocking set: %v %v", keys, err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(strings.Replace(testLock, `"AGPL-3.0"`, `"MIT"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recordProjectLicences(ctx, st, root, p, walkProjectLicences(ctx, root), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := open(); len(got) != 0 {
		t.Fatalf("the relicensed dependency's finding stayed open: %+v", got)
	}
}
