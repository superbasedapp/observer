package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// oidcclient.go is `observer-cloud oidc register-client` (managed-SaaS plan
// 07 wave 16 lane control-plane; lead decision W16-D7; docs/security.md
// CPSIGN-13): the operator backfill of the platform OIDC client for an org
// that has none: one provisioned before the provisioning hook registered it
// (store.RegisterProvisionedOIDCClientTx, wave 15), or on a cloud whose
// SBCI_TENANT_DOMAIN was unset at the time. Without a client its owner
// cannot sign in on the org's tenant host.
//
//	observer-cloud oidc register-client --org <uuid> [--apply]
//	observer-cloud oidc register-client --all-missing [--apply]
//
// Dry run by default; --apply writes, through the same idempotent ensure the
// provisioning hook runs, so a registered client is never rewritten. Every
// org kind is registered (L-123: the sign-in client exists for every org
// kind). An org that is not provisioning or active, or has no slug, is
// refused. The client is public (PKCE, no secret), so the verb prints its id
// and redirect URI and nothing else. It runs with the admin DSN
// (SBCI_PG_DSN): the org registry is read through the worker role and the
// clients through the operator role, over the one login.

// oidcBackfillStatuses are the org states a client is registered in: an org
// being created or in service (W16-D7). A suspended org keeps whatever
// client it has; one on its way out gets none.
var oidcBackfillStatuses = []pc.TenantState{pc.StateProvisioning, pc.StateActive}

// clientAction is what register-client does (or would do) for one org.
type clientAction string

// Client actions.
const (
	clientRegister   clientAction = "register"
	clientRegistered clientAction = "registered"
	clientConflict   clientAction = "conflict"
	clientIneligible clientAction = "ineligible"
	clientNoSlug     clientAction = "no_slug"
)

// clientFacts is one org read once, before the rules are walked.
type clientFacts struct {
	org      store.OIDCBackfillOrg
	existing *store.OIDCClientState
	want     oidcissuer.Client
	wantErr  error
}

// clientRules decide one org, walked top-down, first match wins; one test
// case per row (oidcclient_test.go).
var clientRules = []struct {
	action clientAction
	match  func(f clientFacts) bool
}{
	{clientIneligible, func(f clientFacts) bool {
		return !slices.Contains(oidcBackfillStatuses, pc.TenantState(f.org.Status))
	}},
	{clientNoSlug, func(f clientFacts) bool { return strings.TrimSpace(f.org.Slug) == "" || f.wantErr != nil }},
	{clientRegistered, func(f clientFacts) bool { return f.existing != nil && sameClient(*f.existing, f.want) }},
	{clientConflict, func(f clientFacts) bool { return f.existing != nil }},
	{clientRegister, func(clientFacts) bool { return true }},
}

// sameClient reports whether a registered client is exactly want, enabled.
func sameClient(c store.OIDCClientState, want oidcissuer.Client) bool {
	return !c.Disabled && c.ClientID == want.ClientID && c.OrgID == want.OrgID &&
		slices.Equal(c.RedirectURIs, want.RedirectURIs)
}

// decideClient walks clientRules.
func decideClient(f clientFacts) clientAction {
	for _, r := range clientRules {
		if r.match(f) {
			return r.action
		}
	}
	return clientRegister // unreachable: the last row matches everything
}

// oidcOrgReader reads the org registry (a worker-role store).
type oidcOrgReader interface {
	OrgsForOIDCBackfill(ctx context.Context, orgID string) ([]store.OIDCBackfillOrg, error)
}

// oidcClientStore reads and ensures clients (an operator-role store).
type oidcClientStore interface {
	OIDCClientsByOrg(ctx context.Context) (map[string]store.OIDCClientState, error)
	EnsureOIDCClient(ctx context.Context, c oidcissuer.Client) error
}

// registerClientRequest is one register-client invocation.
type registerClientRequest struct {
	OrgID        string
	AllMissing   bool
	TenantDomain string
	Apply        bool
}

// runRegisterClient decides every selected org and, with Apply, registers
// the missing clients. With --org a refusal is an error; with --all-missing
// orgs outside the eligible states are counted as skipped, and a conflict is
// reported and fails the run after every org was handled.
func runRegisterClient(ctx context.Context, out io.Writer, orgs oidcOrgReader, clients oidcClientStore, req registerClientRequest) error {
	orgID := strings.TrimSpace(req.OrgID)
	switch {
	case orgID == "" && !req.AllMissing:
		return errors.New("--org <uuid> or --all-missing is required")
	case orgID != "" && req.AllMissing:
		return errors.New("--org and --all-missing exclude each other")
	}
	domain := strings.TrimSpace(req.TenantDomain)
	if domain == "" {
		return errors.New("--tenant-domain (or SBCI_TENANT_DOMAIN) is required: a client's redirect is https://<slug>.<tenant domain>/auth/oidc/callback")
	}
	if _, err := oidcissuer.TenantRedirectURI("probe", domain); err != nil {
		return fmt.Errorf("the tenant domain %q is unusable: %w", domain, err)
	}
	list, err := orgs.OrgsForOIDCBackfill(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no org %s", orgID)
	}
	if err != nil {
		return fmt.Errorf("read the orgs: %w", err)
	}
	registered, err := clients.OIDCClientsByOrg(ctx)
	if err != nil {
		return fmt.Errorf("read the clients: %w", err)
	}
	mode := "dry run"
	if req.Apply {
		mode = "applied"
	}
	fmt.Fprintf(out, "observer-cloud: oidc register-client, %s, tenant domain %s\n", mode, domain)
	var missing, done, skipped, already int
	var problems []error
	for _, o := range list {
		f := clientFacts{org: o}
		if c, ok := registered[o.OrgID]; ok {
			f.existing = &c
		}
		f.want, f.wantErr = oidcissuer.ClientForOrg(o.OrgID, o.Slug, domain)
		switch a := decideClient(f); a {
		case clientIneligible:
			skipped++
			if orgID != "" {
				return fmt.Errorf("org %s is %s: a client is registered only for a provisioning or active org", o.OrgID, o.Status)
			}
		case clientNoSlug:
			if f.wantErr != nil {
				problems = append(problems, fmt.Errorf("org %s has no usable slug (%q): %w", o.OrgID, o.Slug, f.wantErr))
			} else {
				problems = append(problems, fmt.Errorf("org %s has no slug", o.OrgID))
			}
			fmt.Fprintf(out, "  %s (%s, %s): refused: no usable slug\n", o.OrgID, o.Kind, o.Status)
		case clientRegistered:
			already++
			if orgID != "" {
				fmt.Fprintf(out, "  %s (%s, %s): already registered: client %s, redirect %s\n",
					o.OrgID, o.Kind, o.Status, f.want.ClientID, f.want.RedirectURIs[0])
			}
		case clientConflict:
			problems = append(problems, fmt.Errorf("org %s: %w", o.OrgID, store.ErrOIDCClientConflict))
			fmt.Fprintf(out, "  %s (%s, %s): refused: client %s is registered with redirect %v (disabled %v), want %s\n",
				o.OrgID, o.Kind, o.Status, f.existing.ClientID, f.existing.RedirectURIs, f.existing.Disabled, f.want.RedirectURIs[0])
		case clientRegister:
			missing++
			if !req.Apply {
				fmt.Fprintf(out, "  %s (%s, %s): would register client %s, redirect %s\n",
					o.OrgID, o.Kind, o.Status, f.want.ClientID, f.want.RedirectURIs[0])
				continue
			}
			if err := clients.EnsureOIDCClient(ctx, f.want); err != nil {
				problems = append(problems, fmt.Errorf("org %s: %w", o.OrgID, err))
				fmt.Fprintf(out, "  %s (%s, %s): failed: %v\n", o.OrgID, o.Kind, o.Status, err)
				continue
			}
			done++
			fmt.Fprintf(out, "  %s (%s, %s): registered client %s, redirect %s\n",
				o.OrgID, o.Kind, o.Status, f.want.ClientID, f.want.RedirectURIs[0])
		}
	}
	switch {
	case missing == 0:
		fmt.Fprintf(out, "observer-cloud: nothing missing (%d registered, %d skipped as not provisioning or active)\n", already, skipped)
	case req.Apply:
		fmt.Fprintf(out, "observer-cloud: %d of %d missing clients registered (%d already registered, %d skipped)\n", done, missing, already, skipped)
	default:
		fmt.Fprintf(out, "observer-cloud: %d missing; run again with --apply to register them (%d already registered, %d skipped)\n", missing, already, skipped)
	}
	if len(problems) > 0 {
		return fmt.Errorf("observer-cloud oidc register-client: %w", errors.Join(problems...))
	}
	return nil
}

// newOIDCCmd is `observer-cloud oidc` and its register-client verb.
func newOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "operator verbs of the platform OIDC issuer's clients",
	}
	var req registerClientRequest
	register := &cobra.Command{
		Use:   "register-client",
		Short: "register the platform OIDC client of an org that has none (dry run by default)",
		Long: "Register the platform OIDC client (id org:<uuid>, public, PKCE, one exact\n" +
			"redirect https://<slug>.<tenant domain>/auth/oidc/callback) for an org\n" +
			"provisioned without one (lead decision W16-D7; CPSIGN-13).\n\n" +
			"--org registers one org; --all-missing every provisioning or active org that\n" +
			"has none. Dry run by default; --apply writes. A registered client is never\n" +
			"rewritten: one registered differently is reported and fails the run. There\n" +
			"is no client secret to print. Runs with the admin DSN (SBCI_PG_DSN).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			app, worker, closeFn, err := openOrgGrantStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()
			if req.TenantDomain == "" {
				req.TenantDomain = os.Getenv("SBCI_TENANT_DOMAIN")
			}
			return runRegisterClient(ctx, cmd.OutOrStdout(), worker, app, req)
		},
	}
	register.Flags().StringVar(&req.OrgID, "org", "", "org UUID")
	register.Flags().BoolVar(&req.AllMissing, "all-missing", false, "every provisioning or active org with no client")
	register.Flags().StringVar(&req.TenantDomain, "tenant-domain", "", "the tenant parent domain (default $SBCI_TENANT_DOMAIN)")
	register.Flags().BoolVar(&req.Apply, "apply", false, "register (default: dry run)")
	cmd.AddCommand(register)
	return cmd
}
