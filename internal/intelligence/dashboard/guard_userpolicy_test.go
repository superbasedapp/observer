package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAPIGuardSummaryReportsInvalidUserPolicy pins the T-323 banner
// payload: a user guard-policy.toml that does not load surfaces on
// /api/guard/summary with its path, line and error; a valid (or absent)
// file carries no user_policy key at all.
func TestAPIGuardSummaryReportsInvalidUserPolicy(t *testing.T) {
	t.Parallel()
	s, policyPath, _ := newGuardPolicyServer(t)

	get := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/summary", nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return m
	}

	// Absent file: no banner.
	if _, ok := get()["user_policy"]; ok {
		t.Fatal("absent policy file reported user_policy")
	}

	// Malformed: banner with path, line and the parse error.
	if err := os.WriteFile(policyPath, []byte("# mine\n[[override]]\nrule = R-153\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, ok := get()["user_policy"].(map[string]any)
	if !ok {
		t.Fatal("malformed policy file not reported on /api/guard/summary")
	}
	// The banner names the path as configured, and newGuardPolicyServer
	// writes it in slash form; compare cleaned, since C:/x and C:\x are the
	// same file on Windows.
	gotPath, _ := up["path"].(string)
	if filepath.Clean(gotPath) != filepath.Clean(policyPath) || up["line"] != float64(3) || !strings.Contains(up["error"].(string), "parse") {
		t.Errorf("user_policy = %v, want path %q, line 3, a parse error", up, policyPath)
	}

	// Fixed: the banner clears on the next read.
	if err := os.WriteFile(policyPath, []byte("[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := get()["user_policy"]; ok {
		t.Error("valid policy file still reported user_policy")
	}
}

// TestAPIGuardPolicyRefusesEngineInvalidSave pins the editor's sanity
// check for the OTHER way a file fails to load: it parses, but an
// override names a rule that does not exist, so the engine refuses it
// and the guard would drop the whole file. The save is refused 422 and
// nothing reaches disk.
func TestAPIGuardPolicyRefusesEngineInvalidSave(t *testing.T) {
	t.Parallel()
	s, policyPath, _ := newGuardPolicyServer(t)
	rec := doGuardPolicy(t, s, "PUT", "/api/guard/policy", policyBody("[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n"))
	if rec.Code != 422 {
		t.Fatalf("PUT status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "R-999") {
		t.Errorf("422 body does not name the bad rule: %s", rec.Body.String())
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Errorf("refused save reached disk (stat err %v)", err)
	}
}
