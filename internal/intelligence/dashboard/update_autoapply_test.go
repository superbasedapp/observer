package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// B-S7 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the
// "Update automatically" switch writes [update].auto_apply through the save
// pipeline: a dry run first, the confirm token on the real save, null back
// to the managed-fleet default, every other line of config.toml kept.

const updateAutoApplyCorpus = `# my node
[update]
enabled = true
channel = "stable"
`

func getUpdateAutoApply(t *testing.T, s *Server) (updateAutoApplyView, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/update/auto-apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/update/auto-apply: %d %s", rr.Code, rr.Body.String())
	}
	var v updateAutoApplyView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	return v, cookie
}

func putUpdateAutoApply(t *testing.T, s *Server, query, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, cookie := getUpdateAutoApply(t, s)
	req := httptest.NewRequest(http.MethodPut, "/api/update/auto-apply"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, v.ConfirmToken)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func loadAutoApply(t *testing.T, path string) *bool {
	t.Helper()
	cfg, err := loadConfigForDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Update.AutoApply
}

func TestUpdateAutoApply_UnsetReadsNull(t *testing.T) {
	s, _ := newSecretTestServer(t, updateAutoApplyCorpus)
	v, cookie := getUpdateAutoApply(t, s)
	if v.AutoApply != nil {
		t.Fatalf("unset key reads %v, want null", *v.AutoApply)
	}
	if v.ConfirmToken == "" || cookie == nil || v.ConfigEtag == "" {
		t.Fatalf("GET must mint a confirm token and report the etag: %+v", v)
	}
}

func TestUpdateAutoApply_DryRunWritesNothing(t *testing.T) {
	s, path := newSecretTestServer(t, updateAutoApplyCorpus)
	before, _ := os.ReadFile(path)
	rr := putUpdateAutoApply(t, s, "?dry_run=1", `{"auto_apply":true}`, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["dry_run"] != true || resp["needs_confirm"] != true || !strings.Contains(resp["diff"].(string), "auto_apply = true") {
		t.Fatalf("dry run answer: %v", resp)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("a dry run wrote config.toml")
	}
}

func TestUpdateAutoApply_SaveNeedsTheConfirmToken(t *testing.T) {
	s, path := newSecretTestServer(t, updateAutoApplyCorpus)
	if rr := putUpdateAutoApply(t, s, "", `{"auto_apply":true}`, false); rr.Code == http.StatusOK {
		t.Fatalf("a save without the confirm token was accepted: %s", rr.Body.String())
	}
	if got := loadAutoApply(t, path); got != nil {
		t.Fatalf("refused save wrote auto_apply=%v", *got)
	}
}

func TestUpdateAutoApply_OnOffAndBackToDefault(t *testing.T) {
	s, path := newSecretTestServer(t, updateAutoApplyCorpus)
	cases := []struct {
		body string
		want *bool
	}{
		{`{"auto_apply":true}`, autoApplyPtr(true)},
		{`{"auto_apply":false}`, autoApplyPtr(false)},
		{`{"auto_apply":null}`, nil},
	}
	for _, c := range cases {
		rr := putUpdateAutoApply(t, s, "", c.body, true)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.body, rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["restart_required"] != true {
			t.Fatalf("%s: [update] binds at start, want restart_required: %v", c.body, resp)
		}
		got := loadAutoApply(t, path)
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Fatalf("%s: auto_apply = %v, want %v", c.body, got, c.want)
		}
		b, _ := os.ReadFile(path)
		if !strings.Contains(string(b), `channel = "stable"`) || !strings.Contains(string(b), "enabled = true") {
			t.Fatalf("%s: the save lost another [update] key:\n%s", c.body, b)
		}
	}
}

func TestUpdateAutoApply_RefusesOtherFields(t *testing.T) {
	s, path := newSecretTestServer(t, updateAutoApplyCorpus)
	for _, body := range []string{`{}`, `{"auto_apply":true,"enabled":false}`, `{"auto_apply":"yes"}`} {
		if rr := putUpdateAutoApply(t, s, "", body, true); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s, want 400", body, rr.Code, rr.Body.String())
		}
	}
	if got := loadAutoApply(t, path); got != nil {
		t.Fatalf("a refused body wrote auto_apply=%v", *got)
	}
}

// autoApplyPtr is a *bool for a case table.
func autoApplyPtr(v bool) *bool { return &v }
