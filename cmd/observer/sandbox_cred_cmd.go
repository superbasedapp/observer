//go:build !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// sandbox_cred_cmd.go is `observer sandbox credentials add|list|remove` and
// the dashboard's Local routes for the same (lane GATES-SBX, G24). A key is
// read from the terminal without echo (or from stdin), stored in the OS
// keychain under sbo-sandbox-cred-v1, and never printed, logged or
// returned: list and the GET route say only which providers have a key.
// Guard rule R-165 refuses an agent's `credentials add` and the POST route
// (internal/policy/rules_selfapproval.go), so only the person adds a key.

// credProviderView is one provider on the CLI and the panel.
type credProviderView struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Host     string `json:"host"`
	KeyEnv   string `json:"key_env"`
	Stored   bool   `json:"stored"`
}

func credViews(observerDir string) ([]credProviderView, string) {
	ks := credKeysFn(observerDir)
	var out []credProviderView
	for _, p := range sandboxcred.Providers() {
		v, err := ks.Get(sandboxcred.KeyName(p.ID))
		out = append(out, credProviderView{Provider: p.ID, Label: p.KeyLabel, Host: p.Host, KeyEnv: p.KeyEnv, Stored: err == nil && v != ""})
	}
	return out, ks.Backend()
}

// errCredInactive is the verbs' refusal while the component
// is off.
var errCredInactive = errors.New("credential injection is off on this node; select " + credentialsComponent + " in Settings > Components")

// credAdd validates and stores a key.
func credAdd(observerDir, provider, key string) error {
	p, ok := sandboxcred.ProviderFor(provider)
	if !ok {
		return fmt.Errorf("unknown provider %q (one of: %s)", provider, credProviderList())
	}
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 4096 || strings.ContainsAny(key, "\r\n\x00 ") || sandboxcred.IsSentinel(key) {
		return errors.New("that is not a key (empty, too long, a sentinel, or it holds a space or a line break)")
	}
	if err := credKeysFn(observerDir).Set(sandboxcred.KeyName(p.ID), key); err != nil {
		return err
	}
	return credMarkProvider(observerDir, p.ID, true)
}

// credRemove deletes a provider's key.
func credRemove(observerDir, provider string) error {
	p, ok := sandboxcred.ProviderFor(provider)
	if !ok {
		return fmt.Errorf("unknown provider %q", provider)
	}
	if err := credKeysFn(observerDir).Delete(sandboxcred.KeyName(p.ID)); err != nil && !errors.Is(err, keystore.ErrNotFound) {
		return err
	}
	return credMarkProvider(observerDir, p.ID, false)
}

func credProviderList() string {
	var ids []string
	for _, p := range sandboxcred.Providers() {
		ids = append(ids, p.ID)
	}
	return strings.Join(ids, ", ")
}

// credReadKey reads a key from in: without echo when it is a terminal.
var credReadKey = func(in io.Reader, out io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor number
		fmt.Fprint(out, "Paste the key (not shown): ")
		b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // G115: a descriptor number
		fmt.Fprintln(out)
		return string(b), err
	}
	line, err := bufio.NewReader(io.LimitReader(in, 8192)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}

func newSandboxCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Your own provider keys for credential injection into sandboxed runs (beta)",
		Long: "Keys added here stay on this machine (the OS keychain). A hosted sandboxed run with key custody home_relay " +
			"gets only a sentinel in its key variable; Observer's proxy adds your key on the way to the provider's model host.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "add <provider>",
		Short: "Store your key for a provider (read without echo, never printed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !credActive(cmd.Context()) {
				return errCredInactive
			}
			key, err := credReadKey(cmd.InOrStdin(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := credAdd(credObserverDir(), args[0], key); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored your %s key for injection.\n", args[0])
			return nil
		},
	}, &cobra.Command{
		Use:   "list",
		Short: "Show which providers have a key (never the key)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !credActive(cmd.Context()) {
				return errCredInactive
			}
			views, backend := credViews(credObserverDir())
			for _, v := range views {
				state := "no key"
				if v.Stored {
					state = "key stored"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-11s %-10s %s (box variable %s)\n", v.Provider, state, v.Host, v.KeyEnv)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "store: %s\n", backend)
			return nil
		},
	}, &cobra.Command{
		Use:   "remove <provider>",
		Short: "Delete your key for a provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !credActive(cmd.Context()) {
				return errCredInactive
			}
			if err := credRemove(credObserverDir(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed the %s key.\n", args[0])
			return nil
		},
	})
	return cmd
}

// credDashboardRoutes are the Credentials panel's routes: Local, 404 while
// the component is off, every write behind the confirm token. R-165 covers
// the path prefix (internal/policy).
func credDashboardRoutes(string) []dashapi.ExtraRoute {
	gate := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !credActive(r.Context()) {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}
	write := func(do func(ctx context.Context, provider, key string) error) http.HandlerFunc {
		return gate(func(w http.ResponseWriter, r *http.Request) {
			if !hostedConfirmed(w, r) {
				return
			}
			var body struct {
				Provider string `json:"provider"`
				Key      string `json:"key"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
				http.Error(w, "a JSON body is required", http.StatusBadRequest)
				return
			}
			if err := do(r.Context(), strings.TrimSpace(body.Provider), body.Key); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	return []dashapi.ExtraRoute{
		{Pattern: "GET /api/terminal/sandbox/credentials", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			tok := hostedConfirmToken(w, r)
			views, backend := credViews(credObserverDir())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": views, "store": backend, "confirm_token": tok, "local_runs": "not injected in this release"})
		})},
		{Pattern: "POST /api/terminal/sandbox/credentials", Capability: dashapi.CapabilityLocal, Handler: write(func(_ context.Context, provider, key string) error {
			return credAdd(credObserverDir(), provider, key)
		})},
		{Pattern: "POST /api/terminal/sandbox/credentials/remove", Capability: dashapi.CapabilityLocal, Handler: write(func(_ context.Context, provider, _ string) error {
			return credRemove(credObserverDir(), provider)
		})},
	}
}
