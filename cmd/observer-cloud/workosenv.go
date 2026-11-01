package main

import (
	"fmt"
	"strings"
)

// WorkOS server-side settings (12-factor, env). Each secret has a plain form
// and a _FILE form that names a mounted file holding the value (a compose
// secret), so a deployment never has to put the value in the container's
// environment, where `docker inspect` would list it.
const (
	envWorkOSClientID          = "WORKOS_CLIENT_ID"
	envWorkOSAPIKey            = "WORKOS_API_KEY"             //nolint:gosec // env var NAME, not a credential
	envWorkOSAPIKeyFile        = "WORKOS_API_KEY_FILE"        //nolint:gosec // env var NAME, not a credential
	envWorkOSWebhookSecret     = "WORKOS_WEBHOOK_SECRET"      //nolint:gosec // env var NAME, not a credential
	envWorkOSWebhookSecretFile = "WORKOS_WEBHOOK_SECRET_FILE" //nolint:gosec // env var NAME, not a credential
	envPortalWorkOS            = "SBCI_PORTAL_WORKOS"
)

// workOSSettings is the resolved WorkOS configuration the serve process wires.
// The two secrets are never logged.
type workOSSettings struct {
	ClientID      string
	APIKey        string
	WebhookSecret string
}

// readExclusiveSecret resolves one secret from either name (the value itself)
// or fileName (the path of a file holding it), never both. Unlike
// readSecretEnv, which lets the plain form win silently, setting both is a
// startup error: the two forms disagreeing is a deployment mistake to fix,
// not a precedence rule to guess at. A named file that cannot be read, or
// that holds only whitespace, is an error too, so a missing secret mount
// fails closed at startup instead of degrading to "unset". Neither value is
// ever included in an error.
func readExclusiveSecret(getenv func(string) string, readFile func(string) ([]byte, error), name, fileName string) (string, error) {
	plain := strings.TrimSpace(getenv(name))
	path := strings.TrimSpace(getenv(fileName))
	switch {
	case plain != "" && path != "":
		return "", fmt.Errorf("set %s or %s, not both", name, fileName)
	case path == "":
		return plain, nil
	}
	b, err := readFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fileName, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s names %q, which is empty", fileName, path)
	}
	return v, nil
}

// workOSSettingsFromEnv resolves the WorkOS client id and both secrets.
func workOSSettingsFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (workOSSettings, error) {
	apiKey, err := readExclusiveSecret(getenv, readFile, envWorkOSAPIKey, envWorkOSAPIKeyFile)
	if err != nil {
		return workOSSettings{}, err
	}
	webhook, err := readExclusiveSecret(getenv, readFile, envWorkOSWebhookSecret, envWorkOSWebhookSecretFile)
	if err != nil {
		return workOSSettings{}, err
	}
	return workOSSettings{
		ClientID:      strings.TrimSpace(getenv(envWorkOSClientID)),
		APIKey:        apiKey,
		WebhookSecret: webhook,
	}, nil
}

// portalWorkOSRequested reports whether SBCI_PORTAL_WORKOS asks for the
// portal's WorkOS browser sign-in leg ("1" or "true").
func portalWorkOSRequested(getenv func(string) string) bool {
	switch strings.TrimSpace(getenv(envPortalWorkOS)) {
	case "1", "true":
		return true
	}
	return false
}

// requireWorkOSComplete refuses to start when the browser sign-in leg is
// requested but the client id or the API key is missing. Before this check
// the routes quietly answered 501 for every visitor; on a deployment that
// meant to open sign-up that is an outage nobody sees until a user reports
// it, so an incomplete request is now a startup error. The webhook secret
// stays optional here (its route fails closed on its own and the serve
// command warns), because sign-in works without it.
func requireWorkOSComplete(requested bool, s workOSSettings) error {
	if !requested {
		return nil
	}
	var missing []string
	if s.ClientID == "" {
		missing = append(missing, envWorkOSClientID)
	}
	if s.APIKey == "" {
		missing = append(missing, envWorkOSAPIKey+" (or "+envWorkOSAPIKeyFile+")")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s=1 needs %s", envPortalWorkOS, strings.Join(missing, " and "))
	}
	return nil
}
