//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_connect_routes.go is the dashboard form of
// `observer sandbox hosted connect <provider>` and `disconnect <provider>`
// (dashboard CLI parity plan item B-G2): the Hosted sandboxes panel's
// "Connect" credential form. Both routes are Local, answer 404 while no
// hosted driver is active (the panel's gate) and need the confirm token.
// The connect route itself is the one the sandbox installation lifecycle
// plan's ruling R5 built (hostedConnectRoute,
// terminal_sandbox_hosted_connect_route.go); it checks the typed fields with
// hostedConnectFields below and stores the credential exactly as the CLI
// does (hostedConnectCredential): in the OS keychain, bound to the
// configured region's endpoint and, for a pinned endpoint, its server key.
// No value is ever logged, returned or put in an error: a refusal names the
// field, never what was typed. Guard rule R-165 denies an agent's connect
// (internal/policy/rules_selfapproval.go), so only the person connects a
// credential; a disconnect only takes access away.

// hostedConnectMaxValue bounds one credential field.
const hostedConnectMaxValue = 4096

// hostedConnectFields checks a connect request's fields against the
// vendor's credential names: every name present and non-empty, no other
// name, no value over the bound or holding a control character. The
// returned errors name a field only.
func hostedConnectFields(v sandboxremote.Vendor, in map[string]string) (map[string]string, error) {
	want := map[string]bool{}
	for _, n := range v.EnvCredential {
		want[n] = true
	}
	var unknown []string
	for n := range in {
		if !want[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("%s takes only %s; not %s", v.Name, strings.Join(v.EnvCredential, ", "), strings.Join(unknown, ", "))
	}
	out := make(map[string]string, len(v.EnvCredential))
	for _, n := range v.EnvCredential {
		val := strings.TrimSpace(in[n])
		switch {
		case val == "":
			return nil, fmt.Errorf("%s is required", n)
		case len(val) > hostedConnectMaxValue || strings.ContainsFunc(val, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return nil, fmt.Errorf("%s is not a credential value (too long, or it holds a line break or a control character)", n)
		}
		out[n] = val
	}
	return out, nil
}

// hostedDisconnectHandler serves POST
// /api/terminal/sandbox/hosted/disconnect: {"provider": id}.
func hostedDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if !hostedConfirmed(w, r) {
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "a JSON body is required", http.StatusBadRequest)
		return
	}
	v, err := hostedStoredVendorArg(strings.TrimSpace(body.Provider))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	obs, err := hostedObserverDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := hostedDisconnectCredential(obs, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
