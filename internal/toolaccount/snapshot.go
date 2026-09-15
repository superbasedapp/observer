package toolaccount

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// CodexIdentity projects only identity claims from a local file-backed ChatGPT
// login. JWT claims are unverified local metadata, never authentication proof.
// API-key, malformed and ephemeral modes return no identity.
func CodexIdentity(body []byte) models.ToolAccountObservation {
	var p struct {
		Mode   string `json:"auth_mode"`
		APIKey string `json:"OPENAI_API_KEY"`
		Tokens struct {
			IDToken string `json:"id_token"`
		} `json:"tokens"`
	}
	if json.Unmarshal(body, &p) != nil || p.Mode != "chatgpt" || p.APIKey != "" {
		return models.ToolAccountObservation{}
	}
	parts := strings.Split(p.Tokens.IDToken, ".")
	if len(parts) != 3 {
		return models.ToolAccountObservation{}
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return models.ToolAccountObservation{}
	}
	var identity struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Subject string `json:"sub"`
	}
	if json.Unmarshal(claims, &identity) != nil {
		return models.ToolAccountObservation{}
	}
	// tokens.account_id identifies a ChatGPT workspace and can be shared by
	// different people. The ID-token subject identifies the login principal.
	return models.ToolAccountObservation{Email: identity.Email, Name: identity.Name, AccountID: identity.Subject, Source: "codex_local_login_snapshot"}
}

// ClaudeIdentity projects only oauthAccount identity metadata, ignoring all
// credentials/settings in the same file. It is a cached login, not proof that a
// particular provider request used OAuth rather than an API key.
func ClaudeIdentity(body []byte) models.ToolAccountObservation {
	var p struct {
		Account struct {
			Email string `json:"emailAddress"`
			Name  string `json:"displayName"`
			ID    string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	if json.Unmarshal(body, &p) != nil {
		return models.ToolAccountObservation{}
	}
	return models.ToolAccountObservation{Email: p.Account.Email, Name: p.Account.Name, AccountID: p.Account.ID, Source: "claude_local_login_snapshot"}
}
