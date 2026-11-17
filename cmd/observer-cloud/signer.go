package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

// newSignerCmd is the signer process family (managed-SaaS M6.2; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3):
// `observer-cloud signer oidc ...` and, since M6.3, `signer document ...`
// (signer_document.go). Each signer runs as its own systemd unit and Linux
// user, so neither the web process (`serve`) nor the worker holds a private
// key.
//
// The OIDC signer's verbs:
//
//	serve       hold the RSA key(s) and sign id_tokens over a unix socket for
//	            the one allowed peer uid (SO_PEERCRED; Linux only)
//	keygen      write a new RSA-3072 key file (0600, never overwriting) and
//	            print its kid
//	public-key  print a key file's kid and public JWK
//	promote     staged -> active: publish a kid now, first use at not_before
//	            (default now + 24h; operator, sbci_app)
//	retire      active -> retiring (stop signing, stay published), or with
//	            --final retiring/staged -> retired (stop publishing)
//
// Environment (flags win):
//
//	SBCI_OIDC_ISSUER             the issuer identifier (the portal origin +
//	                             /oauth2); the signer signs for it alone
//	SBCI_OIDC_SIGNER_SOCKET      the unix socket path
//	                             (default /run/observer-cloud-oidc/signer.sock)
//	SBCI_OIDC_SIGNER_ALLOW_UID   the uid of the serve user
//	SBCI_OIDC_SIGNER_KEY         key file path(s), comma-separated; default
//	                             $CREDENTIALS_DIRECTORY/oidc-signing-key (a
//	                             systemd LoadCredentialEncrypted= credential)
func newSignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signer",
		Short: "run a key-holding signer process (oidc, document)",
	}
	oidc := &cobra.Command{
		Use:   "oidc",
		Short: "the platform OIDC issuer's id_token signer",
	}
	oidc.AddCommand(newSignerOIDCServeCmd(), newSignerOIDCKeygenCmd(), newSignerOIDCPublicKeyCmd(),
		newSignerOIDCPromoteCmd(), newSignerOIDCRetireCmd())
	cmd.AddCommand(oidc, newSignerDocumentCmd())
	return cmd
}

// defaultOIDCSignerSocket is where the signer listens by default (a systemd
// RuntimeDirectory=observer-cloud-oidc owned by the signer user, group the
// serve user).
const defaultOIDCSignerSocket = "/run/observer-cloud-oidc/signer.sock"

// oidcSignerConfig is the resolved configuration of `signer oidc serve`.
type oidcSignerConfig struct {
	issuer   string
	socket   string
	allowUID int
	keyPaths []string
}

// resolveOIDCSignerConfig merges flags over the environment and validates.
func resolveOIDCSignerConfig(issuer, socket, allowUID string, keys []string, getenv func(string) string) (oidcSignerConfig, error) {
	pick := func(flag, env string) string {
		if strings.TrimSpace(flag) != "" {
			return strings.TrimSpace(flag)
		}
		return strings.TrimSpace(getenv(env))
	}
	c := oidcSignerConfig{issuer: pick(issuer, "SBCI_OIDC_ISSUER"), socket: pick(socket, "SBCI_OIDC_SIGNER_SOCKET")}
	if c.socket == "" {
		c.socket = defaultOIDCSignerSocket
	}
	if _, err := oidcissuer.ValidateIssuerURL(c.issuer); err != nil {
		return c, fmt.Errorf("signer oidc: --issuer / SBCI_OIDC_ISSUER: %w", err)
	}
	uidText := pick(allowUID, "SBCI_OIDC_SIGNER_ALLOW_UID")
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid < 0 {
		return c, fmt.Errorf("signer oidc: --allow-uid / SBCI_OIDC_SIGNER_ALLOW_UID must be the serve user's numeric uid, got %q", uidText)
	}
	if uid == 0 {
		return c, errors.New("signer oidc: refusing to sign for uid 0; run serve as its own user")
	}
	c.allowUID = uid
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			c.keyPaths = append(c.keyPaths, k)
		}
	}
	if len(c.keyPaths) == 0 {
		for _, k := range strings.Split(getenv("SBCI_OIDC_SIGNER_KEY"), ",") {
			if k = strings.TrimSpace(k); k != "" {
				c.keyPaths = append(c.keyPaths, k)
			}
		}
	}
	if len(c.keyPaths) == 0 {
		if p := signerd.CredentialKeyPath(getenv("CREDENTIALS_DIRECTORY"), signerd.CredentialKeyName); p != "" {
			c.keyPaths = []string{p}
		}
	}
	if len(c.keyPaths) == 0 {
		return c, errors.New("signer oidc: no key: pass --key, set SBCI_OIDC_SIGNER_KEY, or load the systemd credential oidc-signing-key")
	}
	return c, nil
}

// loadOIDCSigner loads the keys and builds the in-process signer the socket
// serves.
func loadOIDCSigner(c oidcSignerConfig, now func() time.Time) (*oidcissuer.LocalSigner, error) {
	keys := make([]*rsa.PrivateKey, 0, len(c.keyPaths))
	for _, p := range c.keyPaths {
		k, err := signerd.LoadPrivateKey(p)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return oidcissuer.NewLocalSigner(c.issuer, keys, now)
}

func newSignerOIDCServeCmd() *cobra.Command {
	var issuer, socket, allowUID string
	var keys []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "sign id_tokens over a unix socket for the serve user (Linux only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := resolveOIDCSignerConfig(issuer, socket, allowUID, keys, os.Getenv)
			if err != nil {
				return err
			}
			signer, err := loadOIDCSigner(cfg, time.Now)
			if err != nil {
				return err
			}
			ln, err := signerd.ListenUnix(cfg.socket)
			if err != nil {
				return fmt.Errorf("signer oidc: %w", err)
			}
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			pubs, _ := signer.PublicKeys(cmd.Context())
			for _, p := range pubs {
				log.Info("signer oidc: holding key", "kid", p.KID)
			}
			log.Info("signer oidc: serving", "socket", cfg.socket, "issuer", cfg.issuer, "allow_uid", cfg.allowUID)
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			srv := &signerd.Server{Signer: signer, AllowUID: cfg.allowUID, Logger: log}
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "", "the issuer identifier this signer signs for (env SBCI_OIDC_ISSUER)")
	cmd.Flags().StringVar(&socket, "socket", "", "unix socket path (env SBCI_OIDC_SIGNER_SOCKET; default "+defaultOIDCSignerSocket+")")
	cmd.Flags().StringVar(&allowUID, "allow-uid", "", "the serve user's uid, the only peer served (env SBCI_OIDC_SIGNER_ALLOW_UID)")
	cmd.Flags().StringSliceVar(&keys, "key", nil, "RSA key file (repeatable; env SBCI_OIDC_SIGNER_KEY; default the systemd credential oidc-signing-key)")
	return cmd
}

func newSignerOIDCKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "write a new RSA-3072 signing key (0600) and print its kid",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(out) == "" {
				return errors.New("signer oidc keygen: --out is required")
			}
			jwk, err := signerd.GenerateKeyFile(out)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "kid %s\nwrote %s (0600). Seal it as the systemd credential %q on the VM and keep the offline copy; then start the signer, and promote the kid once serve has staged it.\n",
				jwk.Kid, out, signerd.CredentialKeyName)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "path of the new key file (must not exist)")
	return cmd
}

func newSignerOIDCPublicKeyCmd() *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "public-key",
		Short: "print a key file's kid and public JWK",
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := signerd.LoadPrivateKey(key)
			if err != nil {
				return err
			}
			return writeJWK(cmd.OutOrStdout(), oidcissuer.PublicJWK(&k.PublicKey))
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "the key file")
	return cmd
}

func writeJWK(w io.Writer, jwk oidcissuer.JWK) error {
	b, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

func newSignerOIDCPromoteCmd() *cobra.Command {
	var kid, notBefore string
	var lead time.Duration
	cmd := &cobra.Command{
		Use:   "promote",
		Short: "publish a staged kid now; it signs from --not-before (default now + 24h)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now().UTC()
			nb := now.Add(lead)
			if strings.TrimSpace(notBefore) != "" {
				t, err := time.Parse(time.RFC3339, notBefore)
				if err != nil {
					return fmt.Errorf("signer oidc promote: --not-before: %w", err)
				}
				nb = t
			}
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			if err := s.SetOIDCSigningKeyStatus(ctx, kid, oidcissuer.KeyActive, nb, now, lead); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "kid %s is active: published now, signs from %s\n", kid, nb.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&kid, "kid", "", "the staged kid to promote")
	cmd.Flags().StringVar(&notBefore, "not-before", "", "RFC 3339 time of first use (at least --lead from now)")
	cmd.Flags().DurationVar(&lead, "lead", oidcissuer.PublicationLead, "minimum publication lead before first use")
	return cmd
}

func newSignerOIDCRetireCmd() *cobra.Command {
	var kid string
	var final bool
	cmd := &cobra.Command{
		Use:   "retire",
		Short: "stop signing with a kid (it stays published); --final stops publishing it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			to := oidcissuer.KeyRetiring
			if final {
				to = oidcissuer.KeyRetired
			}
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			if err := s.SetOIDCSigningKeyStatus(ctx, kid, to, time.Time{}, time.Now().UTC(), 0); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "kid %s is %s\n", kid, to)
			return nil
		},
	}
	cmd.Flags().StringVar(&kid, "kid", "", "the kid")
	cmd.Flags().BoolVar(&final, "final", false, "retire for good: drop it from the JWKS (wait past the longest token life plus the tenants' one-hour JWKS cache)")
	return cmd
}
