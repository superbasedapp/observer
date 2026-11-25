//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// --- login -----------------------------------------------------------------

func newCloudLoginCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		devToken   string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to superbased in your browser.",
		Long: "Signs in to superbased in your browser and keeps a sign-in for this machine.\n" +
			"`observer connect` does this and also connects the machine in one step.\n" +
			"For local testing, pass --dev-token (in memory only, never stored).",
		// Getting started v2: hidden from help (`observer connect` is the
		// front door); it keeps working, and the dashboard still runs it.
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			// Dev path: exchange a supplied WorkOS access token via the stub broker.
			if strings.TrimSpace(devToken) != "" {
				resolved := resolveCloudBaseURL(baseURL, cfg)
				if err := requireCloudBaseURL(resolved); err != nil {
					return err
				}
				gw, err := openCloudGateway(cfg, resolved, devToken, nil, nil)
				if err != nil {
					return err
				}
				// BOOTSTRAP lane: the device exchange IS the sign-in action, so it
				// carries no consent grant (R2 disposition F10).
				if err := gw.BootstrapExchange(cmd.Context()); err != nil {
					return fmt.Errorf("exchange: %w", err)
				}
				fmt.Fprintln(w, "Signed in - device-bound API token stored. (dev token was not persisted)")
				// The token may belong to a different account than the one the
				// stored cursor was minted under (T-962).
				cloudResetResultCursor(cmd.Context(), w, configPath, resolved, false)
				return nil
			}
			// Production: WorkOS PKCE loopback sign-in.
			clientID := resolveWorkOSClientID(cfg)
			if clientID == "" {
				fmt.Fprintf(w, "%s\n", cloudWorkOSClientIDMissingHint)
				return nil
			}
			if err := runWorkOSLogin(cmd.Context(), w, cfg, baseURL, clientID); err != nil {
				return err
			}
			cloudResetResultCursor(cmd.Context(), w, configPath, resolveCloudBaseURL(baseURL, cfg), false)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	cmd.Flags().StringVar(&devToken, "dev-token", "", "Dev access token for local testing (never stored)")
	return cmd
}

// cloudWorkOSClientIDEnv names the WorkOS client id used for the node PKCE flow.
// It is PUBLIC (safe on the node); the WorkOS API key is server-side only and is
// never read here.
const cloudWorkOSClientIDEnv = "WORKOS_CLIENT_ID"

// cloudWorkOSClientIDMissingHint is the ONE user-facing line for "no client id
// is configured" — printed by `observer cloud login` and surfaced verbatim by
// the dashboard's Cloud account card, so both name the same two knobs.
const cloudWorkOSClientIDMissingHint = "Set [cloud].workos_client_id in config.toml or the " + cloudWorkOSClientIDEnv +
	" environment variable to sign in with WorkOS (or pass --dev-token to `observer cloud login` for local testing)."

// resolveWorkOSClientID applies the env > [cloud].workos_client_id precedence
// (the same ladder as the base URL, minus a flag: there is no --client-id).
// "" means unconfigured. Both `observer cloud login` and the gateway's refresh
// broker resolve through here, so a config-file id and an env id behave
// identically everywhere — including inside the subprocess the dashboard's
// Sign-in button spawns, which inherits the daemon's environment and reads the
// same config file.
func resolveWorkOSClientID(cfg config.Config) string {
	if v := strings.TrimSpace(os.Getenv(cloudWorkOSClientIDEnv)); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.Cloud.WorkOSClientID)
}

// runWorkOSLogin runs the WorkOS AuthKit PKCE loopback sign-in: it starts a
// 127.0.0.1 callback listener, opens the browser to the AuthKit authorize URL,
// receives the authorization code, exchanges it (with the code verifier, NO
// client secret) for tokens — persisting the refresh token — and then exchanges
// a fresh WorkOS access token for the device-bound SuperBased API token.
func runWorkOSLogin(ctx context.Context, w io.Writer, cfg config.Config, baseURL, clientID string) error {
	// The whole flow is BOOTSTRAP-lane egress: the OAuth leg plus the device
	// exchange, both authorized by the user having typed `observer cloud login`.
	// It is composed through the gateway so cmd/observer holds no direct handle
	// on the network lane or the credential store.
	resolved := resolveCloudBaseURL(baseURL, cfg)
	// Fail before the browser opens rather than after: a sign-in that cannot
	// reach an endpoint would otherwise persist WorkOS refresh material and then
	// stop, leaving the user signed in to nothing.
	if err := requireCloudBaseURL(resolved); err != nil {
		return err
	}
	gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
	if err != nil {
		return err
	}
	pkce, err := gw.GeneratePKCE()
	if err != nil {
		return err
	}
	state, err := gw.RandomState()
	if err != nil {
		return err
	}

	// Loopback callback on a FIXED port. WorkOS matches redirect URIs exactly,
	// including the port, so a dynamic port would never match the registered
	// URI — the operator registers http://127.0.0.1:<port>/callback in the
	// WorkOS dashboard and we must listen on that exact port. Override the
	// default with SBO_CLOUD_LOGIN_PORT, else [cloud].login_port in config.toml
	// (register the matching URI too). Bind 127.0.0.1 explicitly (not
	// "localhost") so the browser's redirect and our listener agree even when
	// localhost resolves to IPv6.
	loginPort := "9797"
	if p := strings.TrimSpace(os.Getenv(cloudLoginPortEnv)); p != "" {
		loginPort = p
	} else if cfg.Cloud.LoginPort != 0 {
		loginPort = strconv.Itoa(cfg.Cloud.LoginPort)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", loginPort))
	if err != nil {
		return fmt.Errorf("start loopback listener on 127.0.0.1:%s (port busy? set %s or [cloud].login_port, and register the matching WorkOS redirect URI): %w", loginPort, cloudLoginPortEnv, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authURL, err := gw.AuthorizeURL(clientID, redirectURI, pkce.Challenge, state)
	if err != nil {
		_ = ln.Close()
		return err
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			writeCloudLoginPage(rw, cloudLoginPageStateMismatch)
			errCh <- fmt.Errorf("state mismatch (possible CSRF) - sign-in aborted")
			return
		}
		if e := q.Get("error"); e != "" {
			writeCloudLoginPage(rw, cloudLoginPageAuthError)
			errCh <- fmt.Errorf("authorization error: %s (%s)", e, q.Get("error_description"))
			return
		}
		code := q.Get("code")
		if code == "" {
			writeCloudLoginPage(rw, cloudLoginPageNoCode)
			errCh <- fmt.Errorf("callback carried no authorization code")
			return
		}
		writeCloudLoginPage(rw, cloudLoginPageSuccess)
		codeCh <- code
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintln(w, "Opening your browser to sign in with WorkOS...")
	fmt.Fprintf(w, "If it does not open, visit this URL:\n\n  %s\n\n", authURL)
	openBrowser(authURL) // best-effort + silent; the URL above is the manual fallback

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("sign-in timed out after 5 minutes")
	}

	if err := gw.BootstrapExchangeWorkOSCode(ctx, clientID, code, pkce.Verifier); err != nil {
		return err
	}

	// Exchange a fresh WorkOS access token (via the persisted refresh) for the
	// device-bound SuperBased API token. The gateway resolved the production
	// WorkOS broker at Open time from WORKOS_CLIENT_ID, which is the same id the
	// authorize URL above was built with.
	if err := gw.BootstrapExchange(ctx); err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	fmt.Fprintln(w, "Signed in - device-bound API token stored.")
	return nil
}
