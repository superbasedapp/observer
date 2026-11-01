//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const securityTestConfirm = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func securityPost(h http.HandlerFunc, path, body string, confirm bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if confirm {
		r.Header.Set(remoteConfirmHeader, securityTestConfirm)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: securityTestConfirm})
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestSecurityExceptionRoutes: the page's grant, list and revoke, the
// confirm token on every write, the closed pickers, and a refusal for a
// free-text reason.
func TestSecurityExceptionRoutes(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.New(s.db())
	id, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
		LocalKey: "k1", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(root)}, Location: secfinding.Location{RelPath: "a.go", StartLine: 1},
		Status: policy.FindingStatusOpen,
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant := `{"finding_id":"` + id + `","reason":"test_fixture","expiry":"until_change"}`
	if w := securityPost(s.handleSecurityExceptions, "/api/security/exceptions", grant, false); w.Code != http.StatusForbidden {
		t.Fatalf("grant without the confirm token: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityExceptions, "/api/security/exceptions", `{"finding_id":"`+id+`","reason":"trust me","expiry":"7d"}`, true); w.Code != http.StatusConflict {
		t.Fatalf("free-text reason: %d %s", w.Code, w.Body)
	}
	w := securityPost(s.handleSecurityExceptions, "/api/security/exceptions", grant, true)
	if w.Code != http.StatusOK {
		t.Fatalf("grant: %d %s", w.Code, w.Body)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusSuppressed {
		t.Fatalf("finding after grant: %s", f.Status)
	}
	rr := httptest.NewRecorder()
	s.handleSecurityExceptions(rr, httptest.NewRequest(http.MethodGet, "/api/security/exceptions", nil))
	var list struct {
		Exceptions []securityExceptionJS `json:"exceptions"`
		Reasons    []securityPickerJS    `json:"reasons"`
		Expiries   []securityPickerJS    `json:"expiries"`
		Token      string                `json:"confirm_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Exceptions) != 1 || list.Exceptions[0].GrantedBy != "dashboard" || len(list.Reasons) != 3 || len(list.Expiries) != 4 || list.Token == "" {
		t.Fatalf("list: %+v", list)
	}
	if strings.Contains(rr.Body.String(), "file_hash") || strings.Contains(rr.Body.String(), "local_key") {
		t.Fatalf("list carries the fingerprint or the key: %s", rr.Body)
	}
	revoke := `{"id":` + jsonInt(list.Exceptions[0].ID) + `}`
	if w := securityPost(s.handleSecurityExceptionRevoke, "/api/security/exceptions/revoke", revoke, true); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityExceptionRevoke, "/api/security/exceptions/revoke", revoke, true); w.Code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d", w.Code)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen {
		t.Fatalf("finding after revoke: %s", f.Status)
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestSecurityBaselineRoute: a project is named by its hash; an unknown
// one is a 404, a directory git cannot read gives an empty picker with a
// reason, and an approval takes only a full commit id from the picker.
func TestSecurityBaselineRoute(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	get := func(project string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityBaseline(w, httptest.NewRequest(http.MethodGet, "/api/security/baseline?project="+project, nil))
		return w
	}
	if w := get("nope"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", w.Code)
	}
	w := get(hash)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "proposal_error") || strings.Contains(w.Body.String(), root) {
		t.Fatalf("baseline view: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityBaseline, "/api/security/baseline", `{"project":"`+hash+`","action":"approve","commit":"HEAD"}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("approve a ref, not a commit id: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityBaseline, "/api/security/baseline", `{"project":"`+hash+`","action":"reset"}`, false); w.Code != http.StatusForbidden {
		t.Fatalf("reset without the confirm token: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityBaseline, "/api/security/baseline", `{"project":"`+hash+`","action":"reset"}`, true); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
}

// TestSecurityEditorRoute: the extension's feed lists a project's open
// findings by relative path, for the workspace folder's git root, and
// refuses a relative directory.
func TestSecurityEditorRoute(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := store.New(s.db())
	if _, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
		LocalKey: "k1", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(root)}, Location: secfinding.Location{RelPath: "sub/a.go", StartLine: 4},
		Message: "S-721: a secret", Status: policy.FindingStatusOpen, EvidenceRedacted: "[aws_secret_access_key]",
	}), time.Now()); err != nil {
		t.Fatal(err)
	}
	get := func(dir string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityEditor(w, httptest.NewRequest(http.MethodGet, "/api/security/editor?root="+dir, nil))
		return w
	}
	if w := get("relative"); w.Code != http.StatusBadRequest {
		t.Fatalf("relative: %d", w.Code)
	}
	w := get(filepath.Join(root, "sub"))
	var resp struct {
		Findings []securityEditorFindingJS `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s %v", w.Code, w.Body, err)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].RelPath != "sub/a.go" || resp.Findings[0].StartLine != 4 {
		t.Fatalf("findings %+v", resp.Findings)
	}
	if strings.Contains(w.Body.String(), "aws_secret_access_key") {
		t.Fatalf("the feed carries evidence: %s", w.Body)
	}
}

// TestSecurityGithooksRoute: the state of a repository's hooks, an install
// refused while the component is not active (fails closed with no
// component service), and an uninstall that always works.
func TestSecurityGithooksRoute(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s, root := newTestServer(t)
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	hash := secposture.ProjectRootHash(root)
	w := httptest.NewRecorder()
	s.handleSecurityGithooks(w, httptest.NewRequest(http.MethodGet, "/api/security/githooks?project="+hash, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"active":false`) || !strings.Contains(w.Body.String(), `"pre-commit"`) {
		t.Fatalf("state: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityGithooks, "/api/security/githooks", `{"project":"`+hash+`","action":"install"}`, true); w.Code != http.StatusConflict {
		t.Fatalf("install while inactive: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(root, ".git", "hooks", "pre-commit")); err == nil {
		t.Fatal("a hook was written while the component is inactive")
	}
	if w := securityPost(s.handleSecurityGithooks, "/api/security/githooks", `{"project":"`+hash+`","action":"uninstall"}`, true); w.Code != http.StatusOK {
		t.Fatalf("uninstall: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityGithooks, "/api/security/githooks", `{"project":"`+hash+`","action":"uninstall"}`, false); w.Code != http.StatusForbidden {
		t.Fatalf("uninstall without the confirm token: %d", w.Code)
	}
}
