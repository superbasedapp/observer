package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/prove"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Prove-lane environment. Every one of these is DISTINCT from the production
// worker's variables by design.
//
// The credential separation is the point (remediation plan §3 W3a, review
// finding 4). This file reads the prove-lane key variable of the selected
// provider family (envProveAPIKey for anthropic, envProveFoundryAPIKey for
// foundry) and hands it to prove.Run as an explicit parameter. It never reads
// the production worker's own key variables and never calls the worker's
// credential chooser, so a proving run cannot borrow, and cannot weaken, the
// worker's credential-ABSENCE boundary. A source scan in prove_test.go pins
// that property.
const (
	// envProveAPIKey is the prove-lane credential for the DEFAULT provider
	// family (anthropic). Unset ⇒ the subcommand refuses to run.
	envProveAPIKey = "SBCI_PROVE_ANTHROPIC_API_KEY" //nolint:gosec // env var NAME, not a credential
	// envProveFoundryAPIKey is the prove-lane credential when
	// SBCI_INFERENCE_PROVIDER=foundry.
	envProveFoundryAPIKey = "SBCI_PROVE_FOUNDRY_API_KEY" //nolint:gosec // env var NAME, not a credential
	// envProveRoute selects the (non-production) route/deployment to prove
	// against.
	envProveRoute = "SBCI_PROVE_ROUTE"
	// envProveARMToken / envProveARMBaseURL / envProveARMAPIVersion are the
	// prove-lane ARM reader token source for the ContentLogging attestation
	// (foundry family only). Each falls back to its SBCI_ARM_* production
	// counterpart: an ARM READER token is not a provider credential, so sharing
	// it does not touch the absence boundary.
	envProveARMToken      = "SBCI_PROVE_ARM_TOKEN" //nolint:gosec // env var NAME, not a credential
	envProveARMBaseURL    = "SBCI_PROVE_ARM_BASE_URL"
	envProveARMAPIVersion = "SBCI_PROVE_ARM_API_VERSION"
)

// proveKeyEnvs maps each provider family to ITS prove-lane key variable.
var proveKeyEnvs = map[inference.Family]string{
	inference.FamilyAnthropic: envProveAPIKey,
	inference.FamilyFoundry:   envProveFoundryAPIKey,
}

// newProveCmd is the operator-only, fixture-only inference proving lane
// (remediation plan §3 W3a / divergence E3, FA3). Like grant-plan it is a
// one-shot CLI verb run against the admin DSN, and deliberately NOT an HTTP
// route: no request from any client can select this lane, and no account flag
// enables it. Ordinary account admission REMAINS credential-absent.
//
// It runs the compiled-in synthetic fixture catalog through the SAME pipeline
// stages the worker runs: route resolve, provider-posture attestation, dialect
// check, the provider call, and normalize/scrub/ground, and exits non-zero if
// any step fails. It writes no job, no reservation, and no tenant row; its only
// write is one content-free system-scoped audit event.
func newProveCmd() *cobra.Command {
	var (
		routeFlag string
		listOnly  bool
		fixture   string
		timeout   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "prove",
		Short: "run the compiled-in synthetic fixtures through the real provider pipeline (operator-only)",
		Long: "Run the operator-only, fixture-only provider proving lane.\n\n" +
			"The fixtures are compiled into this binary and are never accepted from any\n" +
			"client. The lane uses its OWN credential (" + envProveAPIKey + " for anthropic,\n" +
			envProveFoundryAPIKey + " for foundry) and never reads the production worker's\n" +
			"own key variables, so the worker's credential-absence boundary is untouched.\n" +
			"No job, reservation, or tenant row is written.\n\n" +
			"The selected route must be classified NON-PRODUCTION: the lane refuses any\n" +
			"route whose route_registry.environment is not 'nonproduction', and the\n" +
			"production worker refuses every route where it is.\n\n" +
			"Environment:\n" +
			fmt.Sprintf("  %-34s anthropic (default) or foundry\n", envInferenceProvider) +
			fmt.Sprintf("  %-34s prove-lane Anthropic key (anthropic)\n", envProveAPIKey) +
			fmt.Sprintf("  %-34s prove-lane Foundry key (foundry)\n", envProveFoundryAPIKey) +
			fmt.Sprintf("  %-34s route id to prove against (or --route)\n", envProveRoute) +
			fmt.Sprintf("  %-34s disclosed attestation (anthropic)\n", "SBCI_PROVIDER_RETENTION_DISCLOSED_*") +
			fmt.Sprintf("  %-34s ARM reader token (foundry; falls back to SBCI_ARM_TOKEN)\n", envProveARMToken) +
			fmt.Sprintf("  %-34s admin Postgres DSN (REQUIRED)", "SBCI_PG_DSN"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			fixtures, err := selectFixtures(fixture)
			if err != nil {
				return err
			}
			if listOnly {
				printCatalog(cmd, fixtures)
				return nil
			}

			family, err := chooseProviderFamily()
			if err != nil {
				return err
			}
			keyEnv, ok := proveKeyEnvs[family]
			if !ok {
				return fmt.Errorf("no prove-lane key variable for provider %q", family)
			}
			apiKey := strings.TrimSpace(os.Getenv(keyEnv))
			if apiKey == "" {
				return fmt.Errorf("%s is unset - the proving lane refuses to run.\n"+
					"Set it to a NON-PRODUCTION %s key provisioned for this lane. It is deliberately a\n"+
					"different variable from the worker's: the lane never reads the worker's key, and running\n"+
					"without one must fail rather than silently fall back", keyEnv, family)
			}
			routeID := strings.TrimSpace(routeFlag)
			if routeID == "" {
				routeID = strings.TrimSpace(os.Getenv(envProveRoute))
			}
			if routeID == "" {
				return fmt.Errorf("no route selected - set %s or pass --route (the lane never guesses a route)", envProveRoute)
			}

			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

			log := slog.Default()
			router, err := chooseInferenceProvider(log, family)
			if err != nil {
				return err
			}

			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			rep, err := prove.Run(ctx, prove.Options{
				// The credential is passed EXPLICITLY, and it is the prove-lane
				// variable's value — never the worker's.
				APIKey:   apiKey,
				RouteID:  routeID,
				Control:  s,
				Attestor: proveAttestor(s, log, family),
				Provider: router,
				Fixtures: fixtures,
				Audit: func(ctx context.Context, eventType, detailJSON string) error {
					// accountID "" ⇒ NULL: a system-scoped row, bound to no tenant.
					return s.RecordAudit(ctx, "", eventType, detailJSON)
				},
			})
			if err != nil {
				return err
			}
			rep.Print(out)
			if !rep.Passed() {
				return fmt.Errorf("proving run FAILED - see the per-step report above")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&routeFlag, "route", "", "route id to prove against (overrides "+envProveRoute+")")
	cmd.Flags().StringVar(&fixture, "fixture", "", "run only this fixture from the compiled-in catalog (default: all)")
	cmd.Flags().BoolVar(&listOnly, "list", false, "list the compiled-in fixture catalog and exit (no credential, no DB, no provider call)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "overall deadline for the run (0 = none)")
	return cmd
}

// proveAttestor builds the SAME attestation gate the worker uses for the
// family. A disclosed-only family (anthropic) goes through chooseAttestor (the
// disclosed mode is configuration, not a credential, so sharing it with the
// worker does not touch the absence boundary). The foundry family keeps the ARM
// REST reader with the prove-lane token variables, each falling back to its
// production counterpart. An unbound route or an empty token still fails
// CLOSED, exactly as it does for the worker.
func proveAttestor(s *store.Store, log *slog.Logger, family inference.Family) jobs.ProviderAttestor {
	if family.Attestation() == inference.AttestationDisclosedOnly {
		return chooseAttestor(s, log, family)
	}
	arm := &attest.ARMAttestor{
		Tokens: attest.StaticTokenSource{
			Value: envOr(envProveARMToken, "SBCI_ARM_TOKEN"),
		},
		BaseURL:    envOr(envProveARMBaseURL, "SBCI_ARM_BASE_URL"),
		APIVersion: envOr(envProveARMAPIVersion, "SBCI_ARM_API_VERSION"),
	}
	return jobs.NewAttestationGate(s, arm, 15*time.Minute)
}

// envOr returns the first non-empty trimmed value among the named variables.
func envOr(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// selectFixtures resolves the --fixture selector against the compiled-in
// catalog. An unknown name is an error naming what IS available — the catalog
// is closed, so a typo must never silently run everything.
func selectFixtures(name string) ([]prove.Fixture, error) {
	all := prove.Catalog()
	name = strings.TrimSpace(name)
	if name == "" {
		return all, nil
	}
	f, ok := prove.FixtureByName(name)
	if !ok {
		names := make([]string, 0, len(all))
		for _, c := range all {
			names = append(names, c.Name)
		}
		return nil, fmt.Errorf("unknown fixture %q; the compiled-in catalog is: %s", name, strings.Join(names, ", "))
	}
	return []prove.Fixture{f}, nil
}

func printCatalog(cmd *cobra.Command, fixtures []prove.Fixture) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "observer-cloud prove: compiled-in fixture catalog (%d)\n\n", len(fixtures))
	for _, f := range fixtures {
		b, err := f.UploadBytes()
		size := "unbuildable"
		if err == nil {
			size = fmt.Sprintf("%d bytes", len(b))
		}
		fmt.Fprintf(out, "  %-20s %s\n", f.Name, f.Purpose)
		fmt.Fprintf(out, "  %-20s %s\n\n", "", size)
	}
	fmt.Fprintln(out, "These envelopes are Go literals in the binary. No fixture is ever accepted from a client.")
}
