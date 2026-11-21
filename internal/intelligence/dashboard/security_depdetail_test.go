//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const depTestLock = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": { "next": "14.1.0" }
    },
    "node_modules/next": {
      "version": "14.1.0",
      "dependencies": { "lodash": "^4.17.20" }
    },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}
`

const depTestRecord = `{
  "id": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337"],
  "summary": "Command Injection in lodash",
  "details": "lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
  "published": "2021-05-06T16:05:51Z",
  "modified": "2023-11-08T03:59:30Z",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "npm", "name": "lodash"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
  }],
  "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
  "database_specific": {"cwe_ids": ["CWE-77", "CWE-94"]}
}`

// installTestOSV writes a one-record npm export and its epoch under the
// config path's security directory, the store the drawer reads.
func installTestOSV(t *testing.T, s *Server) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.toml")
	s.opts.ConfigPath = cfg
	dir := filepath.Join(secposture.LayoutFor(cfg).Dir, "osv")
	zdir := filepath.Join(dir, "osv-scalibr", "npm")
	if err := os.MkdirAll(zdir, 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("GHSA-35jh-r3h4-6jhm.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(depTestRecord)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(zdir, "all.zip"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	epochs := `[{"ecosystem":"npm","last_modified":"Mon, 02 Nov 2026 00:00:00 GMT","crc32c":"AAAAAA==","size":1,"fetched_at":"2026-11-02T00:00:00Z","checked_at":"2026-11-02T00:00:00Z"}]`
	if err := os.WriteFile(filepath.Join(dir, "epochs.json"), []byte(epochs), 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedDepFinding(t *testing.T, st *store.Store, rootHash, rel, evidence string) string {
	t.Helper()
	id, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: "dep-" + evidence, Rule: secfinding.Rule{ID: "CVE-2021-23337", Pack: "osv"},
		Category: policy.FindingVulnerableDependency, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
		Baseline: policy.FindingBaselineNew, Project: secfinding.Project{RootHash: rootHash},
		Location: secfinding.Location{RelPath: rel}, EvidenceRedacted: evidence,
		Message: "Known vulnerability in a npm dependency (CVE-2021-23337, GHSA-35jh-r3h4-6jhm).",
		FixHint: "Upgrade the dependency to a version the advisory lists as fixed, then regenerate the lockfile.",
		Status:  policy.FindingStatusOpen,
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func getFindingDetail(t *testing.T, s *Server, id string) (securityFindingDetail, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/security/findings/{id}", s.handleSecurityFinding)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/security/findings/"+id, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", w.Code, w.Body)
	}
	var d securityFindingDetail
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	return d, raw
}

// TestSecurityFindingDependencyDetail: a dependency finding's drawer names
// the package, its lockfile lines (with the relationship the lockfile
// states), the local advisory and the suggested upgrade, and its fix hint
// says which version to move to.
func TestSecurityFindingDependencyDetail(t *testing.T) {
	s, root := newTestServer(t)
	installTestOSV(t, s)
	if err := os.MkdirAll(filepath.Join(root, "web"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "web", "package-lock.json"), []byte(depTestLock), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.New(s.db())
	id := seedDepFinding(t, st, secposture.ProjectRootHash(root), "web/package-lock.json", "npm lodash@4.17.20")

	d, raw := getFindingDetail(t, s, id)
	if d.Finding.Package != "lodash@4.17.20" || d.Finding.Ecosystem != "npm" {
		t.Fatalf("finding package: %+v", d.Finding)
	}
	dep := d.Dependency
	if dep == nil {
		t.Fatalf("no dependency block: %s", raw)
	}
	if dep.Ecosystem != "npm" || dep.Name != "lodash" || dep.Version != "4.17.20" {
		t.Fatalf("package: %+v", dep)
	}
	if dep.Relationship != "transitive" || dep.Scope != "runtime" || len(dep.IntroducedBy) != 1 || dep.IntroducedBy[0] != "next@14.1.0" {
		t.Fatalf("relationship: %+v", dep)
	}
	loc := dep.Location
	if !loc.Found || loc.Reason != "" || loc.RelPath != "web/package-lock.json" || loc.StartLine != 12 || loc.EndLine != 15 {
		t.Fatalf("location: %+v", loc)
	}
	if len(loc.Context) == 0 || !loc.Context[3].Match || loc.Context[3].Line != 12 || loc.Context[0].Match {
		t.Fatalf("context: %+v", loc.Context)
	}
	if dep.AdvisorySource != "local_database" || len(dep.Advisories) != 1 {
		t.Fatalf("advisories: %+v", dep)
	}
	a := dep.Advisories[0]
	if a.ID != "GHSA-35jh-r3h4-6jhm" || a.Summary != "Command Injection in lodash" || len(a.CWE) != 2 || len(a.CVSS) != 1 ||
		len(a.References) != 1 || len(a.Ranges) != 1 || a.Ranges[0].Fixed != "4.17.21" || a.Published != "2021-05-06T16:05:51Z" {
		t.Fatalf("advisory: %+v", a)
	}
	if dep.SuggestedVersion != "4.17.21" || len(dep.FixedVersions) != 1 {
		t.Fatalf("fix: %+v", dep)
	}
	if d.FixHint != "Upgrade lodash from 4.17.20 to 4.17.21 or later, then regenerate the lockfile." {
		t.Fatalf("fix hint: %q", d.FixHint)
	}
	// The contract: location.found always present; empty fields omitted.
	depRaw := raw["dependency"].(map[string]any)
	locRaw := depRaw["location"].(map[string]any)
	if _, ok := locRaw["found"]; !ok {
		t.Fatal("location.found omitted")
	}
	if _, ok := locRaw["reason"]; ok {
		t.Fatal("an empty reason is serialised")
	}
	for _, k := range []string{"ecosystem", "name", "version", "relationship", "scope", "introduced_by", "fixed_versions", "suggested_version", "advisory_source", "advisories"} {
		if _, ok := depRaw[k]; !ok {
			t.Errorf("dependency.%s missing", k)
		}
	}
	// The advisory prose is in this response only: never in the finding row.
	got, err := st.ListSecFindings(context.Background(), store.SecFindingFilter{ID: id})
	if err != nil || len(got) != 1 || strings.Contains(got[0].Message, "Command Injection") || strings.Contains(got[0].FixHint, "4.17.21") {
		t.Fatalf("the finding row changed: %+v %v", got, err)
	}
}

// TestSecurityFindingDependencyHonestAbsences: a lockfile gone from disk,
// a record the local database does not hold, and no database at all each
// say so, and no upgrade is suggested.
func TestSecurityFindingDependencyHonestAbsences(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	// No OSV store installed under this config path.
	s.opts.ConfigPath = filepath.Join(t.TempDir(), "config.toml")
	id := seedDepFinding(t, st, hash, "package-lock.json", "npm lodash@4.17.20")
	d, _ := getFindingDetail(t, s, id)
	if d.Dependency == nil || d.Dependency.AdvisorySource != "database_not_installed" || d.Dependency.Location.Reason != "unreadable" ||
		d.Dependency.SuggestedVersion != "" || !strings.HasPrefix(d.FixHint, "Upgrade the dependency to a version") {
		t.Fatalf("no database: %+v hint %q", d.Dependency, d.FixHint)
	}
	installTestOSV(t, s)
	other := seedDepFinding(t, st, hash, "deps/unknown.lock", "npm left-pad@1.0.0")
	if err := os.MkdirAll(filepath.Join(root, "deps"), 0o700); err != nil {
		t.Fatal(err)
	}
	d, _ = getFindingDetail(t, s, other)
	// The finding's ids are the lodash advisory's, which the database does
	// hold, but not for left-pad: the record is shown, no fix is invented.
	if d.Dependency == nil || d.Dependency.Location.Reason != "unsupported_format" || d.Dependency.SuggestedVersion != "" {
		t.Fatalf("unsupported: %+v", d.Dependency)
	}
}

// TestSecurityFindingsListSecretHasNoPackage: a dependency row carries its
// package; a secret row carries no package and no evidence on the list or
// on the drawer.
func TestSecurityFindingsListSecretHasNoPackage(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	const secretEvidence = "EXAMPLE-REDACTED-EVIDENCE-0000"
	secretID, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: "sec", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityCritical, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: hash}, Location: secfinding.Location{RelPath: "a.go", StartLine: 3},
		EvidenceRedacted: "npm " + secretEvidence + "@1", Status: policy.FindingStatusOpen,
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	depID := seedDepFinding(t, st, hash, "package-lock.json", "npm @scope/pkg@1.2.3")

	w := httptest.NewRecorder()
	s.handleSecurityFindings(w, httptest.NewRequest(http.MethodGet, "/api/security/findings?project="+hash, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), secretEvidence) {
		t.Fatal("a secret's evidence reached the list")
	}
	var page securityFindingsPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	byID := map[string]securityFindingJS{}
	for _, f := range page.Findings {
		byID[f.ID] = f
	}
	if f := byID[secretID]; f.Package != "" || f.Ecosystem != "" {
		t.Fatalf("secret row carries a package: %+v", f)
	}
	if f := byID[depID]; f.Package != "@scope/pkg@1.2.3" || f.Ecosystem != "npm" {
		t.Fatalf("dependency row: %+v", f)
	}
	d, raw := getFindingDetail(t, s, secretID)
	if d.Dependency != nil || d.Finding.Package != "" {
		t.Fatalf("secret drawer: %+v", d)
	}
	if b, _ := json.Marshal(raw); strings.Contains(string(b), secretEvidence) {
		t.Fatal("a secret's evidence reached the drawer")
	}
}

// TestReadProjectFile: the lockfile read stays under the project root.
func TestReadProjectFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.lock"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.lock")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readProjectFile(root, "a.lock", 32); err != nil || string(b) != "0123456789" {
		t.Fatalf("read: %q %v", b, err)
	}
	if _, err := readProjectFile(root, "a.lock", 5); !errors.Is(err, secdepdetail.ErrFileTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	for _, rel := range []string{"../x.lock", "sub/../../x.lock", outside, "/etc/passwd", ""} {
		if _, err := readProjectFile(root, rel, 32); !errors.Is(err, secdepdetail.ErrOutsideProject) {
			t.Errorf("%q: %v", rel, err)
		}
	}
	if _, err := readProjectFile(root, "missing.lock", 32); err == nil || errors.Is(err, secdepdetail.ErrOutsideProject) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.lock")); err != nil {
		t.Logf("symlink not available here (%v); escape case skipped", err)
		return
	}
	if _, err := readProjectFile(root, "link.lock", 32); !errors.Is(err, secdepdetail.ErrOutsideProject) {
		t.Fatalf("symlink escape: %v", err)
	}
}
