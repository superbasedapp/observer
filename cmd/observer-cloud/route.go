package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/anthropic"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// defaultAnthropicRouteID is migration 0042's Claude Haiku 5.5 route.
const defaultAnthropicRouteID = "session_enrichment.claude-haiku-5-5.v1"

// newRouteCmd groups the operator route-provisioning verbs. Like grant-plan
// and kill-switch they run once against the admin DSN and exit; no HTTP route
// can reach them.
func newRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "provision inference routes (operator-only)",
	}
	cmd.AddCommand(newRouteBindAnthropicCmd())
	return cmd
}

// anthropicBindPlan is the pure result of planning a bind: what the route row
// will carry afterwards. It is computed before any write so a refusal (wrong
// dialect, unpriced model, bad endpoint) touches nothing.
type anthropicBindPlan struct {
	RouteID       string
	Model         string
	Binding       store.RouteBinding
	InputPerMTok  float64
	OutputPerMTok float64
	PriceVersion  string
}

// planAnthropicBind validates the route + endpoint and resolves the price
// snapshot from the pricing table. It is pure: route snapshot, endpoint,
// account label and a price lookup in, a plan or a refusal out.
func planAnthropicBind(route store.RouteInfo, endpoint, account string, lookup func(model string) (cost.Pricing, bool), priceVersion string) (anthropicBindPlan, error) {
	spec, ok := inference.SpecFor(route.Dialect)
	if !ok || spec.Family != inference.FamilyAnthropic {
		return anthropicBindPlan{}, fmt.Errorf("route %q speaks dialect %q, not an Anthropic dialect - refusing to bind it to the Anthropic API", route.RouteID, route.Dialect)
	}
	model := strings.TrimSpace(route.Deployment)
	if model == "" {
		return anthropicBindPlan{}, fmt.Errorf("route %q has no deployment (model id)", route.RouteID)
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		endpoint = anthropic.DefaultBaseURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return anthropicBindPlan{}, fmt.Errorf("endpoint %q must be an https origin with no path (e.g. %s)", endpoint, anthropic.DefaultBaseURL)
	}
	account = strings.TrimSpace(account)
	if account == "" {
		account = "default"
	}
	p, ok := lookup(model)
	if !ok {
		return anthropicBindPlan{}, fmt.Errorf("the pricing table has no row for %q - refusing to bind a route whose calls could not be priced", model)
	}
	if p.Input <= 0 || p.Output <= 0 {
		return anthropicBindPlan{}, fmt.Errorf("the pricing table quotes %q at input %v / output %v per MTok - refusing a zero or negative price snapshot", model, p.Input, p.Output)
	}
	return anthropicBindPlan{
		RouteID: route.RouteID,
		Model:   model,
		// The binding columns are provider-neutral identity fields (their
		// names are historical): tenant = provider, subscription = the
		// operator's account label, resource = the model resource the
		// disclosed attestation is scoped to, audience = the API origin.
		Binding: store.RouteBinding{
			TenantID:         string(inference.FamilyAnthropic),
			SubscriptionID:   account,
			ARMResourceID:    anthropic.ResourceID(model),
			EndpointAudience: endpoint,
			Endpoint:         endpoint,
			APIVersion:       anthropic.APIVersion,
		},
		InputPerMTok:  p.Input,
		OutputPerMTok: p.Output,
		PriceVersion:  priceVersion,
	}, nil
}

func printAnthropicBindPlan(w io.Writer, p anthropicBindPlan, activate bool) {
	fmt.Fprintf(w, "route:            %s\n", p.RouteID)
	fmt.Fprintf(w, "model:            %s\n", p.Model)
	fmt.Fprintf(w, "endpoint:         %s (anthropic-version %s)\n", p.Binding.Endpoint, p.Binding.APIVersion)
	fmt.Fprintf(w, "resource:         %s\n", p.Binding.ARMResourceID)
	fmt.Fprintf(w, "price snapshot:   input %.4f / output %.4f USD per MTok (%s)\n", p.InputPerMTok, p.OutputPerMTok, p.PriceVersion)
	fmt.Fprintf(w, "activate:         %v\n", activate)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To authorize jobs on this route the api and worker also need, in their env:")
	fmt.Fprintf(w, "  SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE=%s\n", p.Binding.ARMResourceID)
	fmt.Fprintln(w, "  SBCI_PROVIDER_RETENTION_POLICY_VERSION=<the published privacy-policy version>")
	fmt.Fprintln(w, "  SBCI_ANTHROPIC_API_KEY or SBCI_ANTHROPIC_API_KEY_FILE")
}

func newRouteBindAnthropicCmd() *cobra.Command {
	var (
		routeID   string
		endpoint  string
		account   string
		activate  bool
		exclusive bool
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   "bind-anthropic",
		Short: "bind an Anthropic route: endpoint, provider resource identity, price snapshot from the pricing table",
		Long: "Bind an anthropic_messages route (default " + defaultAnthropicRouteID + ") to the Anthropic API.\n\n" +
			"It writes the endpoint + anthropic-version, the provider resource identity the disclosed\n" +
			"attestation is scoped to (anthropic:messages:<model>), and a per-MTok price snapshot copied\n" +
			"from the pricing table this binary carries (internal/intelligence/cost). Each write bumps\n" +
			"the route generation, so any earlier attestation stops matching. It refuses a route that\n" +
			"does not speak an Anthropic dialect and a model the pricing table cannot price.\n\n" +
			"It never reads or writes a credential. --activate also flips route_registry.active;\n" +
			"--exclusive (with --activate) then deactivates every OTHER active route of the same feature\n" +
			"and environment, so this route is the only one live (rows are kept: results reference them).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			route, err := s.RouteByID(ctx, routeID)
			if err != nil {
				return fmt.Errorf("route %q: %w", routeID, err)
			}
			table := cost.NewTable()
			now := time.Now()
			plan, err := planAnthropicBind(route, endpoint, account,
				func(model string) (cost.Pricing, bool) { return table.LookupAt(model, now) },
				pricingTableVersion())
			if err != nil {
				return err
			}
			printAnthropicBindPlan(out, plan, activate)
			if exclusive && !activate {
				return fmt.Errorf("--exclusive needs --activate (it retires the other routes in favour of this one)")
			}
			var retire []string
			if exclusive {
				active, err := s.ActiveRoutes(ctx, route.Feature)
				if err != nil {
					return err
				}
				retire = routesToRetire(route, active)
				for _, id := range retire {
					fmt.Fprintf(out, "retire:           %s\n", id)
				}
			}
			if dryRun {
				fmt.Fprintln(out, "\ndry run: nothing written")
				return nil
			}
			if err := s.SetRouteBinding(ctx, plan.RouteID, plan.Binding); err != nil {
				return fmt.Errorf("bind route: %w", err)
			}
			if err := s.SetRoutePrice(ctx, plan.RouteID, plan.InputPerMTok, plan.OutputPerMTok, plan.PriceVersion); err != nil {
				return fmt.Errorf("stamp price: %w", err)
			}
			if activate {
				if err := s.SetRouteActive(ctx, plan.RouteID, true); err != nil {
					return fmt.Errorf("activate route: %w", err)
				}
			}
			// Retire only after the new route is live, so the feature never has no
			// default in between.
			for _, id := range retire {
				if err := s.SetRouteActive(ctx, id, false); err != nil {
					return fmt.Errorf("retire route %s: %w", id, err)
				}
			}
			// Content-free system audit row: what was bound, never a credential.
			detail := fmt.Sprintf(`{"route_id":%q,"resource":%q,"price_version":%q,"activated":%v,"retired":%d}`,
				plan.RouteID, plan.Binding.ARMResourceID, plan.PriceVersion, activate, len(retire))
			if err := s.RecordAudit(ctx, "", "route_bind_anthropic", detail); err != nil {
				fmt.Fprintf(out, "warning: audit row not written: %v\n", err)
			}
			fmt.Fprintln(out, "\nbound")
			return nil
		},
	}
	cmd.Flags().StringVar(&routeID, "route-id", defaultAnthropicRouteID, "route to bind")
	cmd.Flags().StringVar(&endpoint, "endpoint", anthropic.DefaultBaseURL, "Anthropic API origin (https, no path)")
	cmd.Flags().StringVar(&account, "account", "default", "operator label for the Anthropic account/workspace the key belongs to (recorded on the binding)")
	cmd.Flags().BoolVar(&activate, "activate", false, "also mark the route active")
	cmd.Flags().BoolVar(&exclusive, "exclusive", false, "with --activate: deactivate every other active route of the same feature and environment")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan and write nothing")
	return cmd
}

// routesToRetire is the pure half of --exclusive: every active route of the
// bound route's feature and environment other than the bound route itself.
// Another environment's routes (the non-production proving lane) are never
// touched.
func routesToRetire(bound store.RouteInfo, active []store.RouteInfo) []string {
	var out []string
	for _, r := range active {
		if r.RouteID == bound.RouteID || r.Feature != bound.Feature || r.Environment != bound.Environment {
			continue
		}
		out = append(out, r.RouteID)
	}
	return out
}
