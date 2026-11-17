package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// The document signer (managed-SaaS M6.3; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3, 4.5):
// `observer-cloud signer document ...`, its own systemd unit and Linux user on
// the worker VM. It signs entitlements documents, the availability envelope
// and host-API request envelopes for the worker over a unix socket, and keeps
// a durable record of the last version it signed per (kind, scope).
//
// Verbs:
//
//	serve       hold the Ed25519 keys and sign for the one allowed peer uid
//	            (SO_PEERCRED; Linux only). --init-state creates the version
//	            record on first start; afterwards a missing record refuses to
//	            start, so a lost record is noticed rather than reset
//	keygen      write a new Ed25519 key file (0600, never overwriting) and print
//	            its key id
//	public-key  print a key file's key id and base64 public key
//	raise-floor after a database restore behind the version record, raise
//	            the database's per-stream version floor to a copy of the
//	            record (dry run by default; W16-D6; signer_document_floor.go)
//
// Environment (flags win):
//
//	SBCI_DOC_SIGNER_SOCKET            the unix socket path
//	                                  (default /run/observer-cloud-docsigner/signer.sock)
//	SBCI_DOC_SIGNER_ALLOW_UID         the worker user's uid
//	SBCI_DOC_SIGNER_STATE             the version record
//	                                  (default /var/lib/observer-cloud-docsigner/versions.json)
//	SBCI_DOC_SIGNER_ENTITLEMENTS_KEY  key file path(s), comma-separated, the
//	SBCI_DOC_SIGNER_AVAILABILITY_KEY  first signs and later ones are published
//	SBCI_DOC_SIGNER_HOST_API_KEY      only (rollover); default the systemd
//	                                  credentials entitlements-signing-key,
//	                                  availability-signing-key and
//	                                  host-api-signing-key. The host-API key is
//	                                  optional; the other two are required.

// Defaults of the document signer (a systemd RuntimeDirectory= and
// StateDirectory= owned by its user).
const (
	defaultDocSignerSocket = "/run/observer-cloud-docsigner/signer.sock"
	defaultDocSignerState  = "/var/lib/observer-cloud-docsigner/versions.json"
)

// docKeySource is one row of the key table: the purpose, its flag, its env
// var, its systemd credential and whether it is required.
type docKeySource struct {
	purpose    signerd.Purpose
	flag       string
	env        string
	credential string
	required   bool
}

func docKeySources() []docKeySource {
	return []docKeySource{
		{signerd.PurposeEntitlements, "entitlements-key", "SBCI_DOC_SIGNER_ENTITLEMENTS_KEY", signerd.EntitlementsKeyCredential, true},
		{signerd.PurposeAvailability, "availability-key", "SBCI_DOC_SIGNER_AVAILABILITY_KEY", signerd.AvailabilityKeyCredential, true},
		{signerd.PurposeHostAPI, "host-api-key", "SBCI_DOC_SIGNER_HOST_API_KEY", signerd.HostAPIKeyCredential, false},
	}
}

// docSignerConfig is the resolved configuration of `signer document serve`.
type docSignerConfig struct {
	socket   string
	state    string
	allowUID int
	keyPaths map[signerd.Purpose][]string
}

// splitPaths trims and drops empty entries.
func splitPaths(in []string) []string {
	var out []string
	for _, p := range in {
		for _, q := range strings.Split(p, ",") {
			if q = strings.TrimSpace(q); q != "" {
				out = append(out, q)
			}
		}
	}
	return out
}

// resolveDocSignerConfig merges flags over the environment and validates.
func resolveDocSignerConfig(socket, state, allowUID string, keyFlags map[signerd.Purpose][]string, getenv func(string) string) (docSignerConfig, error) {
	pick := func(flag, env, def string) string {
		if v := strings.TrimSpace(flag); v != "" {
			return v
		}
		if v := strings.TrimSpace(getenv(env)); v != "" {
			return v
		}
		return def
	}
	c := docSignerConfig{
		socket:   pick(socket, "SBCI_DOC_SIGNER_SOCKET", defaultDocSignerSocket),
		state:    pick(state, "SBCI_DOC_SIGNER_STATE", defaultDocSignerState),
		keyPaths: map[signerd.Purpose][]string{},
	}
	uidText := pick(allowUID, "SBCI_DOC_SIGNER_ALLOW_UID", "")
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid < 0 {
		return c, fmt.Errorf("signer document: --allow-uid / SBCI_DOC_SIGNER_ALLOW_UID must be the worker user's numeric uid, got %q", uidText)
	}
	if uid == 0 {
		return c, errors.New("signer document: refusing to sign for uid 0; run the worker as its own user")
	}
	c.allowUID = uid
	for _, src := range docKeySources() {
		paths := splitPaths(keyFlags[src.purpose])
		if len(paths) == 0 {
			paths = splitPaths([]string{getenv(src.env)})
		}
		if len(paths) == 0 {
			if p := signerd.CredentialKeyPath(getenv("CREDENTIALS_DIRECTORY"), src.credential); p != "" {
				if _, statErr := os.Stat(p); statErr == nil || src.required {
					paths = []string{p}
				}
			}
		}
		if len(paths) == 0 && src.required {
			return c, fmt.Errorf("signer document: no %s key: pass --%s, set %s, or load the systemd credential %s", src.purpose, src.flag, src.env, src.credential)
		}
		c.keyPaths[src.purpose] = paths
	}
	return c, nil
}

// loadDocumentKeys loads every configured key file.
func loadDocumentKeys(c docSignerConfig) (signerd.DocumentKeys, error) {
	load := func(paths []string) ([]ed25519.PrivateKey, error) {
		out := make([]ed25519.PrivateKey, 0, len(paths))
		for _, p := range paths {
			k, err := signerd.LoadEd25519Key(p)
			if err != nil {
				return nil, err
			}
			out = append(out, k)
		}
		return out, nil
	}
	var keys signerd.DocumentKeys
	var err error
	if keys.Entitlements, err = load(c.keyPaths[signerd.PurposeEntitlements]); err != nil {
		return keys, err
	}
	if keys.Availability, err = load(c.keyPaths[signerd.PurposeAvailability]); err != nil {
		return keys, err
	}
	keys.HostAPI, err = load(c.keyPaths[signerd.PurposeHostAPI])
	return keys, err
}

func newSignerDocumentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "document",
		Short: "the control plane's document signer (entitlements, availability, host-API requests)",
	}
	cmd.AddCommand(newSignerDocumentServeCmd(), newSignerDocumentKeygenCmd(), newSignerDocumentPublicKeyCmd(), newSignerDocumentRaiseFloorCmd())
	return cmd
}

func newSignerDocumentServeCmd() *cobra.Command {
	var socket, state, allowUID string
	var initState bool
	keyFlags := map[signerd.Purpose]*[]string{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "sign documents over a unix socket for the worker user (Linux only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := map[signerd.Purpose][]string{}
			for p, v := range keyFlags {
				flags[p] = *v
			}
			cfg, err := resolveDocSignerConfig(socket, state, allowUID, flags, os.Getenv)
			if err != nil {
				return err
			}
			keys, err := loadDocumentKeys(cfg)
			if err != nil {
				return fmt.Errorf("signer document: %w", err)
			}
			if initState {
				if err := signerd.CreateVersionFile(cfg.state); err != nil {
					return fmt.Errorf("signer document: --init-state: %w", err)
				}
			}
			versions, err := signerd.OpenFileVersions(cfg.state)
			if err != nil {
				return fmt.Errorf("signer document: %w", err)
			}
			signer, err := signerd.NewDocumentSigner(keys, versions, time.Now)
			if err != nil {
				return fmt.Errorf("signer document: %w", err)
			}
			ln, err := signerd.ListenUnix(cfg.socket)
			if err != nil {
				return fmt.Errorf("signer document: %w", err)
			}
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			for _, k := range signer.PublicKeys() {
				log.Info("signer document: holding key", "purpose", k.Purpose, "key_id", k.KeyID, "signing", k.Signing)
			}
			log.Info("signer document: serving", "socket", cfg.socket, "state", cfg.state, "allow_uid", cfg.allowUID)
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			srv := &signerd.DocumentServer{Signer: signer, AllowUID: cfg.allowUID, Logger: log}
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "unix socket path (env SBCI_DOC_SIGNER_SOCKET; default "+defaultDocSignerSocket+")")
	cmd.Flags().StringVar(&state, "state", "", "the version record (env SBCI_DOC_SIGNER_STATE; default "+defaultDocSignerState+")")
	cmd.Flags().StringVar(&allowUID, "allow-uid", "", "the worker user's uid, the only peer served (env SBCI_DOC_SIGNER_ALLOW_UID)")
	cmd.Flags().BoolVar(&initState, "init-state", false, "create an empty version record first (first start only; refuses to overwrite)")
	for _, src := range docKeySources() {
		v := new([]string)
		keyFlags[src.purpose] = v
		cmd.Flags().StringSliceVar(v, src.flag, nil, fmt.Sprintf("%s key file (repeatable; first signs; env %s; default the systemd credential %s)", src.purpose, src.env, src.credential))
	}
	return cmd
}

func newSignerDocumentKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "write a new Ed25519 document key (0600) and print its key id",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(out) == "" {
				return errors.New("signer document keygen: --out is required")
			}
			id, err := signerd.GenerateEd25519KeyFile(out)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key_id %s\nwrote %s (0600). Seal it as the purpose's systemd credential on the worker VM, keep the offline copy, and pin the key id on the hosts before it signs.\n", id, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "path of the new key file (must not exist)")
	return cmd
}

func newSignerDocumentPublicKeyCmd() *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "public-key",
		Short: "print a key file's key id and base64 public key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := signerd.LoadEd25519Key(key)
			if err != nil {
				return err
			}
			pub, _ := k.Public().(ed25519.PublicKey)
			fmt.Fprintf(cmd.OutOrStdout(), "key_id %s\npublic %s\n", platformcontract.DocumentKeyID(pub), base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "the key file")
	return cmd
}
