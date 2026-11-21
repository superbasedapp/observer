package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// This file wires the platform OIDC issuer (managed-SaaS M6.2) into `serve`.
// The issuer is OFF unless SBCI_OIDC_ISSUER is set; unset, serve mounts no
// /oauth2 route and starts no extra loop, exactly as before M6.2.
//
// Environment (serve):
//
//	SBCI_OIDC_ISSUER         the switch. Must equal the portal origin
//	                         (SBCI_PORTAL_BASE_URL, else
//	                         SBCI_EXTERNAL_BASE_URL) plus /oauth2, the same
//	                         value the signer unit signs for; anything else
//	                         refuses to start (the api would otherwise leave the
//	                         routes off, or the signer would refuse every token)
//	SBCI_OIDC_SIGNER_SOCKET  the signer's unix socket (default
//	                         /run/observer-cloud-oidc/signer.sock)
//	SBCI_OIDC_VM_ID          the name this VM's signer key is registered under
//	                         (oidc_signing_keys.vm_id; default the hostname)
//	SBCI_OIDC_SUPPORT_AUTHORIZE_URL
//	                         the staff console's support authorize endpoint
//	                         (the staff origin plus /staff/oauth2/authorize;
//	                         M7a.2). Set, the token endpoint also redeems
//	                         support codes into tokens carrying support: true
//	                         (store.OIDCStore's support seam), and discovery
//	                         advertises the endpoint as
//	                         sb_support_authorization_endpoint, which is what
//	                         lets a tenant's platform rail start a support
//	                         sign-in. Unset: no support code is ever redeemed
//	                         and discovery is unchanged. Requires
//	                         SBCI_OIDC_ISSUER.

// oidcMaintenanceInterval is how often serve sweeps spent and expired codes
// and, until it has succeeded once, retries registering the signer's keys.
const oidcMaintenanceInterval = time.Minute

// maxVMIDLen mirrors the CHECK on oidc_signing_keys.vm_id (migration 0051).
const maxVMIDLen = 100

// oidcServeConfig is serve's side of the issuer configuration.
type oidcServeConfig struct {
	issuer string
	socket string
	vmID   string
	// supportAuthorizeURL turns the support path on (M7a.2); "" is off.
	supportAuthorizeURL string
}

// envOIDCSupportAuthorizeURL is the support path's switch.
const envOIDCSupportAuthorizeURL = "SBCI_OIDC_SUPPORT_AUTHORIZE_URL"

// resolveOIDCServeConfig reads the issuer configuration. enabled is false
// (and the configuration empty) when SBCI_OIDC_ISSUER is unset.
func resolveOIDCServeConfig(getenv func(string) string, hostname func() (string, error), portalBase string) (cfg oidcServeConfig, enabled bool, err error) {
	issuer := strings.TrimSpace(getenv("SBCI_OIDC_ISSUER"))
	support := strings.TrimSpace(getenv(envOIDCSupportAuthorizeURL))
	if issuer == "" {
		if support != "" {
			return oidcServeConfig{}, false, fmt.Errorf("observer-cloud: %s is set but SBCI_OIDC_ISSUER is not; the support path is part of the platform issuer", envOIDCSupportAuthorizeURL)
		}
		return oidcServeConfig{}, false, nil
	}
	want := strings.TrimRight(portalBase, "/") + oidcissuer.IssuerPath
	if issuer != want {
		return oidcServeConfig{}, false, fmt.Errorf("observer-cloud: SBCI_OIDC_ISSUER %q must be the portal origin plus %s (%q): the tenants pin it and discovery is served there", issuer, oidcissuer.IssuerPath, want)
	}
	if _, err := oidcissuer.ValidateIssuerURL(issuer); err != nil {
		return oidcServeConfig{}, false, fmt.Errorf("observer-cloud: SBCI_OIDC_ISSUER: %w", err)
	}
	cfg = oidcServeConfig{issuer: issuer, socket: strings.TrimSpace(getenv("SBCI_OIDC_SIGNER_SOCKET")), supportAuthorizeURL: support}
	if cfg.socket == "" {
		cfg.socket = defaultOIDCSignerSocket
	}
	cfg.vmID = strings.TrimSpace(getenv("SBCI_OIDC_VM_ID"))
	if cfg.vmID == "" {
		h, herr := hostname()
		if herr != nil {
			return oidcServeConfig{}, false, fmt.Errorf("observer-cloud: SBCI_OIDC_VM_ID is unset and the hostname is unreadable: %w", herr)
		}
		cfg.vmID = strings.TrimSpace(h)
	}
	if err := validateVMID(cfg.vmID); err != nil {
		return oidcServeConfig{}, false, err
	}
	return cfg, true, nil
}

// validateVMID refuses a VM id the oidc_signing_keys CHECK would refuse, or
// one with control characters (it lands in logs and an operator listing).
func validateVMID(id string) error {
	if id == "" || len(id) > maxVMIDLen {
		return fmt.Errorf("observer-cloud: SBCI_OIDC_VM_ID must be 1 to %d characters, got %d", maxVMIDLen, len(id))
	}
	for _, r := range id {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("observer-cloud: SBCI_OIDC_VM_ID must not contain spaces or control characters")
		}
	}
	return nil
}

// newServeOIDCIssuer builds the issuer over a store and a signer. It does no
// I/O (oidcissuer.New validates only, the support authorize URL included).
// The support seam sup is wired only when cfg turns the support path on.
func newServeOIDCIssuer(cfg oidcServeConfig, st oidcissuer.Store, sup oidcissuer.SupportTokenStore, sg oidcissuer.Signer) (*oidcissuer.Issuer, error) {
	ic := oidcissuer.Config{Issuer: cfg.issuer, Store: st, Signer: sg}
	if cfg.supportAuthorizeURL != "" {
		if sup == nil {
			return nil, errors.New("observer-cloud: OIDC issuer: the support path is on but no support store is wired")
		}
		ic.Support, ic.SupportAuthorizeURL = sup, cfg.supportAuthorizeURL
	}
	iss, err := oidcissuer.New(ic)
	if err != nil {
		return nil, fmt.Errorf("observer-cloud: OIDC issuer: %w", err)
	}
	return iss, nil
}

// wireOIDCIssuer returns the issuer serve passes to api.Options.OIDCIssuer,
// or nil when the issuer is not configured. When it is, it also starts the
// issuer's maintenance loop: the signer's keys are registered as staged at
// start (oidcissuer.Issuer.RegisterSignerKeys; promotion stays an operator
// act), and expired codes are swept every minute.
//
// A signer that is down at start does NOT stop serve: the failure is logged,
// the token endpoint answers 503 (never an unsigned token) until the signer
// is back, and registration is retried every minute until it succeeds once.
// Discovery and the JWKS read only the database, so they keep working.
func wireOIDCIssuer(ctx context.Context, log *slog.Logger, s *store.Store, portalBase string) (*oidcissuer.Issuer, error) {
	cfg, enabled, err := resolveOIDCServeConfig(os.Getenv, os.Hostname, portalBase)
	if err != nil || !enabled {
		return nil, err
	}
	iss, err := newServeOIDCIssuer(cfg, s.OIDC(), s.OIDC(), signerd.NewUnixClient(cfg.socket))
	if err != nil {
		return nil, err
	}
	log.Info("observer-cloud: platform OIDC issuer ON", "issuer", cfg.issuer, "signer_socket", cfg.socket, "vm_id", cfg.vmID)
	if cfg.supportAuthorizeURL != "" {
		log.Info("observer-cloud: platform OIDC support path ON (support: true tokens)", "support_authorize_url", cfg.supportAuthorizeURL)
	}
	register := func(ctx context.Context) error {
		keys, err := iss.RegisterSignerKeys(ctx, cfg.vmID)
		for _, k := range keys {
			log.Info("observer-cloud: OIDC signer key registered (staged until an operator promotes it)", "kid", k.KID, "vm_id", cfg.vmID)
		}
		return err
	}
	go func() {
		t := time.NewTicker(oidcMaintenanceInterval)
		defer t.Stop()
		runOIDCMaintenance(ctx, log, register, s.SweepOIDCCodes, t.C, time.Now)
	}()
	return iss, nil
}

// chooseServeIntegrations resolves serve's provider family and credential
// (chooseFamilyCredentials) and wires the OIDC issuer (wireOIDCIssuer) in one
// call, so newServeCmd gains no branch for the issuer.
func chooseServeIntegrations(ctx context.Context, log *slog.Logger, s *store.Store, portalBase string) (inference.Family, jobs.CredentialSource, *oidcissuer.Issuer, error) {
	family, credentials, err := chooseFamilyCredentials(log)
	if err != nil {
		return family, nil, nil, err
	}
	iss, err := wireOIDCIssuer(ctx, log, s, portalBase)
	if err != nil {
		return family, nil, nil, err
	}
	return family, credentials, iss, nil
}

// runOIDCMaintenance registers the signer's keys once now and then, on every
// tick, retries the registration until it has succeeded once and sweeps
// expired codes. It returns when ctx is done.
func runOIDCMaintenance(ctx context.Context, log *slog.Logger, register func(context.Context) error,
	sweep func(context.Context, time.Time) (int64, error), tick <-chan time.Time, now func() time.Time,
) {
	registered := false
	tryRegister := func() {
		if err := register(ctx); err != nil {
			log.Warn("observer-cloud: OIDC signer key registration failed; the token endpoint answers 503 while the signer is unreachable, retrying every minute", "err", err)
			return
		}
		registered = true
	}
	tryRegister()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if !registered {
				tryRegister()
			}
			if n, err := sweep(ctx, now()); err != nil {
				log.Warn("observer-cloud: OIDC code sweep failed", "err", err)
			} else if n > 0 {
				log.Debug("observer-cloud: swept expired OIDC codes", "deleted", n)
			}
		}
	}
}
