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
	// A terminal paste's wrappers go first (D9: bracketed-paste markers, a
	// CR or LF, a byte-order mark), then the one broken rule is named,
	// never the key.
	key = sandboxcred.CleanPastedKey(key)
	if problem := sandboxcred.KeyProblem(key); problem != "" {
		return errors.New("that is not a usable key: " + problem + "; nothing was stored")
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

// credPasteTries is how many times the terminal read asks again when a
// read brings nothing (D9: through wsl.exe from Windows PowerShell an Enter
// could arrive before the paste did).
const credPasteTries = 3

// credReadKey reads a key from in: without echo when it is a terminal.
var credReadKey = func(in io.Reader, out io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor number
		return credReadPasted(out, func() ([]byte, error) {
			return term.ReadPassword(int(f.Fd())) //nolint:gosec // G115: a descriptor number
		})
	}
	line, err := bufio.NewReader(io.LimitReader(in, 8192)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}

// credReadPasted prompts and reads one pasted key without echo, asking
// again (up to credPasteTries) while a read brings nothing once the paste's
// wrappers are removed.
func credReadPasted(out io.Writer, read func() ([]byte, error)) (string, error) {
	prompt := "Paste the key (not shown): "
	var last string
	for i := 0; i < credPasteTries; i++ {
		fmt.Fprint(out, prompt)
		b, err := read()
		fmt.Fprintln(out)
		if err != nil {
			return "", err
		}
		last = string(b)
		if sandboxcred.CleanPastedKey(last) != "" {
			return last, nil
		}
		prompt = "Nothing was read (the paste may not have arrived yet). Paste the key again (not shown): "
	}
	return last, nil
}

// credStoreLine is the list's plain line about where keys are kept: on a
// machine with no OS keychain (WSL, a headless Linux) the file store, said
// as such.
func credStoreLine(backend, diagnostic string) string {
	switch backend {
	case "keychain":
		return "store: the OS keychain"
	case "file":
		line := "store: owner-only files on this machine (no OS keychain was found here, so the keys are not encrypted by the OS)"
		if diagnostic != "" {
			line += "\n  " + diagnostic
		}
		return line
	}
	if diagnostic != "" {
		return "store: " + backend + " (" + diagnostic + ")"
	}
	return "store: " + backend
}

func newSandboxCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Your own provider keys for credential injection into sandboxed runs (beta)",
		Long: "Keys added here stay on this machine (the OS keychain). A hosted sandboxed run with key custody home_relay " +
			"gets only a sentinel in its key variable (one per provider its tool can use whose key is stored here); Observer's proxy adds your key only on the way to that provider's own model host. " +
			"Under key custody in_box_api_key a hosted run whose daemon environment lacks a provider's API key variable gets the key stored here instead, in the box; the consent screen and the New Terminal dialog name it before the upload.",
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
			fmt.Fprintln(cmd.OutOrStdout(), credStoreLine(backend, credKeysFn(credObserverDir()).SecurityDiagnostic()))
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
			// The probe answers from the stored key list (decision SBXD-1:
			// the dialog's paste field re-reads it), so its cache goes.
			applySandboxConfigLive()
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
