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

// TestNormalizeAccountLevel pins the account-level marker: an
// "account"/"account:<detail>" scope must carry an AccountID and no person
// field, and a valid one derives the same key as any AccountID row.
func TestNormalizeAccountLevel(t *testing.T) {
	base := models.ToolAccountObservation{SessionID: "s", Tool: models.ToolAutohand, BindingKind: "message", BindingID: "m", Role: "user", AccountID: "device-acct", Source: "autohand_account_snapshot", Scope: models.ToolAccountScopeAccount + ":device", Stage: "activity"}
	for _, tc := range []struct {
		name string
		edit func(*models.ToolAccountObservation)
		ok   bool
	}{
		{"account with detail", func(*models.ToolAccountObservation) {}, true},
		{"bare account scope", func(o *models.ToolAccountObservation) { o.Scope = models.ToolAccountScopeAccount }, true},
		{"no account id", func(o *models.ToolAccountObservation) { o.AccountID = "" }, false},
		{"names a person by email", func(o *models.ToolAccountObservation) { o.Email = "p@example.invalid" }, false},
		{"names a person by name", func(o *models.ToolAccountObservation) { o.Name = "P" }, false},
		{"accountant scope is not the marker", func(o *models.ToolAccountObservation) { o.Scope = "accountant"; o.Email = "p@example.invalid" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			if _, _, ok := Normalize(o); ok != tc.ok {
				t.Fatalf("Normalize ok=%v, want %v", ok, tc.ok)
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

// TestMergeRules pins the resolution rules one row per case: person and
// account-level evidence are separate dimensions, conflict is judged inside a
// dimension only, and an account-level id is never the person label.
func TestMergeRules(t *testing.T) {
	person := func(key, email string) models.ToolAccountEvidence {
		return models.ToolAccountEvidence{Key: key, Email: email, Source: "snap", Scope: "profile", Stage: "activity"}
	}
	acct := func(key, id, scope string) models.ToolAccountEvidence {
		return models.ToolAccountEvidence{Key: key, AccountID: id, Source: "snap", Scope: scope, Stage: "activity"}
	}
	for _, tc := range []struct {
		name         string
		opt          MergeOptions
		in           []models.ToolAccountEvidence
		wantStatus   string
		wantLabel    string
		wantAccLabel string
	}{
		{"single person", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid")}, "observed", "a@x.invalid", ""},
		{"same person twice", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid"), person("k1", "a@x.invalid")}, "observed", "a@x.invalid", ""},
		{"two people conflict", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid"), person("k2", "b@x.invalid")}, "conflict", ConflictLabel, ""},
		{"person then different person then first again is still a conflict", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid"), person("k2", "b@x.invalid"), person("k1", "a@x.invalid")}, "conflict", ConflictLabel, ""},
		{"account only is qualified, never bare", MergeOptions{}, []models.ToolAccountEvidence{acct("d1", "dev-9", "account:device")}, "observed", "device account dev-9", "device account dev-9"},
		{"bare account scope", MergeOptions{}, []models.ToolAccountEvidence{acct("d1", "acct-9", "account")}, "observed", "account acct-9", "account acct-9"},
		{"org detail", MergeOptions{}, []models.ToolAccountEvidence{acct("o1", "xy12345.eu", "account:org")}, "observed", "org account xy12345.eu", "org account xy12345.eu"},
		{"unknown detail falls back to account", MergeOptions{}, []models.ToolAccountEvidence{acct("o1", "z", "account:whatever")}, "observed", "account z", "account z"},
		{"person then account is no conflict, person stays the label", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid"), acct("d1", "dev-9", "account:device")}, "observed", "a@x.invalid", "device account dev-9"},
		{"account then person is no conflict, person is the label", MergeOptions{}, []models.ToolAccountEvidence{acct("d1", "dev-9", "account:device"), person("k1", "a@x.invalid")}, "observed", "a@x.invalid", "device account dev-9"},
		{"two accounts conflict inside the account dimension", MergeOptions{}, []models.ToolAccountEvidence{acct("d1", "dev-9", "account:device"), acct("d2", "dev-8", "account:device")}, "conflict", ConflictLabel, ConflictLabel},
		{"person conflict does not blank a single account", MergeOptions{}, []models.ToolAccountEvidence{person("k1", "a@x.invalid"), person("k2", "b@x.invalid"), acct("d1", "dev-9", "account:device")}, "conflict", ConflictLabel, "device account dev-9"},
		{"same account under two scope details is one account", MergeOptions{}, []models.ToolAccountEvidence{acct("d1", "dev-9", "account:device"), acct("d1", "dev-9", "account")}, "observed", "device account dev-9", "device account dev-9"},
		{"person name beats account id", MergeOptions{}, []models.ToolAccountEvidence{{Key: "k1", Name: "Ann", AccountID: "sub-1", Source: "s", Scope: "profile", Stage: "activity"}}, "observed", "Ann", ""},
		{"no identity, no fallback", MergeOptions{}, []models.ToolAccountEvidence{{Key: "abcdef0123456789", Source: "s", Scope: "profile", Stage: "activity"}}, "observed", "", ""},
		{"org key fallback, person", MergeOptions{KeyFallback: true}, []models.ToolAccountEvidence{{Key: "abcdef0123456789", Source: "s", Scope: "profile", Stage: "activity"}}, "observed", "account abcdef01", ""},
		{"org key fallback, account-level", MergeOptions{KeyFallback: true}, []models.ToolAccountEvidence{{Key: "abcdef0123456789", Source: "s", Scope: "account:device", Stage: "activity"}}, "observed", "device account abcdef01", "device account abcdef01"},
		{"org key fallback, two different keys across dimensions", MergeOptions{KeyFallback: true}, []models.ToolAccountEvidence{{Key: "aaaaaaaa11", Source: "s", Scope: "profile", Stage: "activity"}, {Key: "bbbbbbbb22", Source: "s", Scope: "account", Stage: "activity"}}, "observed", "account aaaaaaaa", "account bbbbbbbb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a models.MessageAccount
			for _, e := range tc.in {
				a = MergeWith(a, e, tc.opt)
			}
			if a.Status != tc.wantStatus || a.Label != tc.wantLabel || a.AccountLabel != tc.wantAccLabel {
				t.Fatalf("got status=%q label=%q account_label=%q; want %q %q %q", a.Status, a.Label, a.AccountLabel, tc.wantStatus, tc.wantLabel, tc.wantAccLabel)
			}
			if len(a.Evidence) != len(tc.in) {
				t.Fatalf("evidence kept %d of %d", len(a.Evidence), len(tc.in))
			}
		})
	}
}

// TestMergeDefaultsToNodeBehaviour keeps the exported Merge equal to
// MergeWith with zero options.
func TestMergeDefaultsToNodeBehaviour(t *testing.T) {
	e := models.ToolAccountEvidence{Key: "abcdef0123456789", Source: "s", Scope: "profile", Stage: "activity"}
	if got := Merge(models.MessageAccount{}, e); got.Label != "" || got.Status != "observed" {
		t.Fatalf("node Merge must not use the key fallback: %+v", got)
	}
}

func TestScopeNoun(t *testing.T) {
	for scope, want := range map[string]string{
		"profile": "", "accountant": "", "account": "account", "account:device": "device account",
		"account:install": "device account", "account:org": "org account", "account:tenant": "org account", "account:host": "org account", "account:zzz": "account",
	} {
		if got := models.ToolAccountScopeNoun(scope); got != want {
			t.Errorf("ToolAccountScopeNoun(%q)=%q want %q", scope, got, want)
		}
	}
}
