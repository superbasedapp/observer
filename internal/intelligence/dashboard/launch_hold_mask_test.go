package dashboard

import (
	"strings"
	"testing"
)

// TestHeldDetailsMaskSecretMembers pins lane cli-2 fixes-3, audit L3 on
// the dashboard card: a secret-looking member is shown masked and flagged,
// a certain secret inside any value or list item is masked, and every
// member is still on the card.
func TestHeldDetailsMaskSecretMembers(t *testing.T) {
	row, _ := launchRouteFor("/api/arena/runs")
	ghp := "ghp_" + strings.Repeat("B", 36)
	body := `{"prompt":"use ` + ghp + `","api_key":"abc123","Client_Secret":"s3cr3t","candidates":[{"tool":"codex","token":"` + ghp + `"}],"project_root":"/w"}`
	ds := heldDetails(row, "/api/arena/runs", []byte(body))
	byLabel := map[string]string{}
	warn := map[string]bool{}
	for _, d := range ds {
		byLabel[d.Label], warn[d.Label] = d.Value, d.Warn
		for _, secret := range []string{ghp, "abc123", "s3cr3t"} {
			if strings.Contains(d.Value, secret) {
				t.Errorf("%s shows a secret: %q", d.Label, d.Value)
			}
		}
	}
	for _, k := range []string{"prompt", "api_key", "Client_Secret", "candidates", "project_root"} {
		if _, ok := byLabel[k]; !ok {
			t.Errorf("member %s is not on the card: %+v", k, ds)
		}
	}
	if byLabel["api_key"] != maskedDetail || !warn["api_key"] || byLabel["Client_Secret"] != maskedDetail {
		t.Errorf("secret-looking members = %q / %q", byLabel["api_key"], byLabel["Client_Secret"])
	}
	if !strings.Contains(byLabel["prompt"], "[REDACTED:") || !strings.Contains(byLabel["candidates"], `"tool":"codex"`) {
		t.Errorf("prompt %q, candidates %q", byLabel["prompt"], byLabel["candidates"])
	}
	if byLabel["project_root"] != "/w" {
		t.Errorf("an ordinary member was changed: %q", byLabel["project_root"])
	}
}
