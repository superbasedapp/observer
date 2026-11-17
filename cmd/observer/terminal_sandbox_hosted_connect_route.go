//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// terminal_sandbox_hosted_connect_route.go is the dashboard's key entry for
// a hosted sandbox provider (sandbox installation lifecycle plan ruling R5,
// the standing CLI-in-dashboard rule): POST
// /api/terminal/sandbox/hosted/connect {provider, key} or {provider,
// fields} stores the typed key in the OS keychain through the SAME function
// `observer sandbox hosted connect` uses (hostedConnectCredential, bound to
// the configured region's endpoint and, for a pinned one, its server key).
// The route is Local, needs the confirm token, and the key is never logged,
// never echoed and never written anywhere but the keystore. It is also the
// Hosted sandboxes panel's Connect form (dashboard CLI parity item B-G2,
// which sends the fields shape); the disconnect and the field check live in
// terminal_sandbox_hosted_connect_routes.go. The answer names the provider
// and the endpoint the credential is bound to, never a value.

// hostedConnectMaxBody caps the request body.
const hostedConnectMaxBody = 16 << 10

// hostedConnectBody is the request body. Key is the provider's one API
// key; Fields names each credential field for a provider that needs more
// than one (keyed by the provider's credential names).
type hostedConnectBody struct {
	Provider string            `json:"provider"`
	Key      string            `json:"key,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// errHostedConnectFields refuses a body that names no usable key.
var errHostedConnectFields = errors.New("a key is required")

// hostedConnectStore stores a credential for provider, bound to the
// configured region's endpoint: the dashboard route's and the setup step's
// one path onto the keystore (the CLI verb runs the same
// hostedConnectCredential with the same endpoint resolution). A fields entry
// under "" is the key of a provider whose credential is one field.
func hostedConnectStore(ctx context.Context, cfgPath, provider string, fields map[string]string) error {
	_, err := hostedConnectStoreEndpoint(ctx, cfgPath, provider, fields)
	return err
}

// hostedConnectStoreEndpoint is hostedConnectStore that also answers the
// endpoint the credential is bound to (the Connect form shows it). The
// named fields pass hostedConnectFields (dashboard CLI parity item B-G2):
// every credential name present, no other name, no value over the bound or
// holding a control character. Every refusal names a field, never a value.
func hostedConnectStoreEndpoint(ctx context.Context, cfgPath, provider string, fields map[string]string) (string, error) {
	v, err := hostedStoredVendorArg(strings.TrimSpace(provider))
	if err != nil {
		return "", err
	}
	if !hostedActive(ctx, cfgPath) {
		return "", errHostedNotActive()
	}
	named := map[string]string{}
	for k, val := range fields {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if k == "" {
			if len(v.EnvCredential) != 1 {
				return "", fmt.Errorf("%s needs %s; enter each in Terminals > Settings > Hosted sandboxes", v.Name, strings.Join(v.EnvCredential, " and "))
			}
			k = v.EnvCredential[0]
		}
		named[k] = val
	}
	if len(named) == 0 {
		return "", errHostedConnectFields
	}
	checked, err := hostedConnectFields(v, named)
	if err != nil {
		return "", err
	}
	cfg, err := hostedCLIConfig(ctx, cfgPath)
	if err != nil {
		return "", err
	}
	pc := hostedVendorConfig(cfg.Hosted, v.ID)
	_, endpoint, ok := hostedResolve(v, pc)
	if !ok {
		return "", errors.New("the credential cannot be bound: " + hostedResolveRefusal(v, pc))
	}
	obs, err := hostedObserverDir()
	if err != nil {
		return "", err
	}
	if err := hostedConnectCredential(obs, v, checked, endpoint, pc.EndpointSPKISHA256); err != nil {
		return "", err
	}
	return endpoint, nil
}

// hostedConnectRoute is the route row hostedDashboardRoutes lists.
func hostedConnectRoute(configPath string, gate func(http.HandlerFunc) http.HandlerFunc) dashapi.ExtraRoute {
	return dashapi.ExtraRoute{
		Pattern:    "POST /api/terminal/sandbox/hosted/connect",
		Capability: dashapi.CapabilityLocal,
		Handler:    gate(hostedConnectHandler(configPath)),
	}
}

// hostedConnectHandler serves POST /api/terminal/sandbox/hosted/connect.
func hostedConnectHandler(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hostedConfirmed(w, r) {
			return
		}
		var body hostedConnectBody
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, hostedConnectMaxBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			// The decoder's message can quote the body; never echo it.
			hostedConnectError(w, http.StatusBadRequest, "the request body is not a provider and a key")
			return
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			hostedConnectError(w, http.StatusBadRequest, "the request body holds more than one object")
			return
		}
		fields := map[string]string{}
		for k, v := range body.Fields {
			fields[k] = v
		}
		if body.Key != "" {
			fields[""] = body.Key
		}
		endpoint, err := hostedConnectStoreEndpoint(r.Context(), configPath, body.Provider, fields)
		if err != nil {
			// Every error above is built from names, never from the key.
			hostedConnectError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"provider": strings.TrimSpace(body.Provider), "connected": true, "endpoint": endpoint})
	}
}

// hostedConnectError writes a JSON refusal.
func hostedConnectError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": "hosted_connect_refused"})
}
