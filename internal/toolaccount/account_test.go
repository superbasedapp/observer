package toolaccount

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestNormalizeIdentityAndRejectInvalid(t *testing.T) {
	base := models.ToolAccountObservation{SessionID: "s", Tool: models.ToolCodex, BindingKind: "turn", BindingID: "turn", Role: "assistant", Email: " First@Example.Invalid ", AccountID: "workspace", Source: "snapshot", Scope: "profile", Stage: "activity"}
	normalized, key, ok := Normalize(base)
	if !ok || normalized.Email != "first@example.invalid" {
		t.Fatalf("normalization %+v %v", normalized, ok)
	}
	other := base
	other.Email = "second@example.invalid"
	other.AccountID = "other-person"
	_, otherKey, _ := Normalize(other)
	if key == otherKey {
		t.Fatal("collapsed two people")
	}
	for _, tc := range []struct {
		name string
		edit func(*models.ToolAccountObservation)
	}{
		{"missing ID", func(o *models.ToolAccountObservation) { o.BindingID = "" }},
		{"invalid role", func(o *models.ToolAccountObservation) { o.Role = "system" }},
		{"invalid stage", func(o *models.ToolAccountObservation) { o.Stage = "billing" }},
		{"control", func(o *models.ToolAccountObservation) { o.Name = "name\ncontrol" }},
		{"large", func(o *models.ToolAccountObservation) { o.Email = strings.Repeat("x", 513) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			if _, _, ok := Normalize(o); ok {
				t.Fatal("accepted invalid identity")
			}
		})
	}
}

func TestIdentityProjectionRejectsCredentials(t *testing.T) {
	for _, data := range []string{`{}`, `invalid`, `{"auth_mode":"apikey","OPENAI_API_KEY":"secret-sentinel"}`, `{"auth_mode":"chatgpt","tokens":{"id_token":"invalid","access_token":"secret-sentinel"}}`} {
		got := CodexIdentity([]byte(data))
		if got.Email != "" || got.AccountID != "" {
			t.Fatalf("invented identity %+v", got)
		}
	}
	o := ClaudeIdentity([]byte(`{"oauthAccount":{"emailAddress":"first@example.invalid","displayName":"First","accountUuid":"person"},"secret":"secret-sentinel"}`))
	wire, _ := json.Marshal(o)
	if o.Email != "first@example.invalid" || strings.Contains(string(wire), "secret-sentinel") {
		t.Fatalf("unsafe projection %s", wire)
	}
}
