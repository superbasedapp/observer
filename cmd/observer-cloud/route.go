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

// defaultOpenAICompatibleRouteID is migration 0045's gpt-oss-120b route on
// OVH AI Endpoints.
const defaultOpenAICompatibleRouteID = "session_enrichment.gpt-oss-120b.v1"

// ovhAIEndpointsBaseURL is OVH AI Endpoints' OpenAI-compatible base URL (the
// part before /chat/completions).
const ovhAIEndpointsBaseURL = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"

// bindSpec is one provider family's row in the bind table: what a route of
// that family is bound to, and how its endpoint is validated. The commands
// and the planner dispatch on this row, never on the family name.
type bindSpec struct {
	// Family is the provider family whose dialects this row binds.
	Family inference.Family
	// Verb is the subcommand name ("bind-anthropic").
	Verb string
	// Provider is the human name used in messages ("the Anthropic API").
	Provider string
	// DefaultRouteID and DefaultEndpoint are the flag defaults.
	DefaultRouteID  string
	DefaultEndpoint string
	// EndpointAllowsPath reports whether the endpoint may carry a path (an
	// OpenAI-compatible base URL ends in /v1; the Anthropic origin has none).
	EndpointAllowsPath bool
	// APIVersion is recorded on the binding ("" when the dialect has none).
	APIVersion string
	// ResourceID is the provider resource identity the disclosed attestation
	// is scoped to, derived from the model id.
	ResourceID func(model string) string
	// KeyHint names the worker's key variables, printed after a bind.
	KeyHint string
}

// bindSpecs is the bind table, one row per provider family that has an
// operator bind command.
var bindSpecs = []bindSpec{
	{
		Family: inference.FamilyAnthropic, Verb: "bind-anthropic", Provider: "the Anthropic API",
		DefaultRouteID: defaultAnthropicRouteID, DefaultEndpoint: anthropic.DefaultBaseURL,
		APIVersion: anthropic.APIVersion, ResourceID: anthropic.ResourceID,
		KeyHint: envAnthropicAPIKey + " or " + envAnthropicAPIKeyFile,
	},
	{
		Family: inference.FamilyOpenAICompatible, Verb: "bind-openai-compatible", Provider: "an OpenAI-compatible endpoint (OVH AI Endpoints)",
		DefaultRouteID: defaultOpenAICompatibleRouteID, DefaultEndpoint: ovhAIEndpointsBaseURL,
		EndpointAllowsPath: true,
		ResourceID:         func(model string) string { return "openai_compatible:chat:" + strings.TrimSpace(model) },
		KeyHint:            envOpenAICompatibleAPIKey + " or " + envOpenAICompatibleAPIKeyFile,
	},
}

// newRouteCmd groups the operator route-provisioning verbs. Like grant-plan
// and kill-switch they run once against the admin DSN and exit; no HTTP route
// can reach them.
func newRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "provision inference routes (operator-only)",
	}
	for _, spec := range bindSpecs {
		cmd.AddCommand(newRouteBindCmd(spec))
	}
	return cmd
}

// bindPlan is the pure result of planning a bind: what the route row will
// carry afterwards. It is computed before any write so a refusal (wrong
// dialect, unpriced model, bad endpoint) touches nothing.
type bindPlan struct {
	RouteID       string
	Model         string
	Binding       store.RouteBinding
	InputPerMTok  float64
	OutputPerMTok float64
	PriceVersion  string
	KeyHint       string
}

// planAnthropicBind is planBind on the Anthropic row.
func planAnthropicBind(route store.RouteInfo, endpoint, account string, lookup func(model string) (cost.Pricing, bool), priceVersion string) (bindPlan, error) {
	return planBind(bindSpecs[0], route, endpoint, account, lookup, priceVersion)
}

// planBind validates the route + endpoint against the family's row and
// resolves the price snapshot from the pricing table. It is pure: row, route
// snapshot, endpoint, account label and a price lookup in, a plan or a
// refusal out.
func planBind(spec bindSpec, route store.RouteInfo, endpoint, account string, lookup func(model string) (cost.Pricing, bool), priceVersion string) (bindPlan, error) {
	ds, ok := inference.SpecFor(route.Dialect)
	if !ok || ds.Family != spec.Family {
		return bindPlan{}, fmt.Errorf("route %q speaks dialect %q, which is not in the %s family - refusing to bind it to %s", route.RouteID, route.Dialect, spec.Family, spec.Provider)
	}
	model := strings.TrimSpace(route.Deployment)
	if model == "" {
		return bindPlan{}, fmt.Errorf("route %q has no deployment (model id)", route.RouteID)
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		endpoint = spec.DefaultEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (!spec.EndpointAllowsPath && u.Path != "" && u.Path != "/") {
		shape := "an https origin with no path"
		if spec.EndpointAllowsPath {
			shape = "an https base URL with no query"
		}
		return bindPlan{}, fmt.Errorf("endpoint %q must be %s (e.g. %s)", endpoint, shape, spec.DefaultEndpoint)
	}
	account = strings.TrimSpace(account)
	if account == "" {
		account = "default"
	}
	p, ok := lookup(model)
	if !ok {
		return bindPlan{}, fmt.Errorf("the pricing table has no row for %q - refusing to bind a route whose calls could not be priced", model)
	}
	if p.Input <= 0 || p.Output <= 0 {
		return bindPlan{}, fmt.Errorf("the pricing table quotes %q at input %v / output %v per MTok - refusing a zero or negative price snapshot", model, p.Input, p.Output)
	}
	return bindPlan{
		RouteID: route.RouteID,
		Model:   model,
		// The binding columns are provider-neutral identity fields (their
		// names are historical): tenant = provider family, subscription =
		// the operator's account label, resource = the model resource the
		// disclosed attestation is scoped to, audience = the API origin.
		Binding: store.RouteBinding{
			TenantID:         string(spec.Family),
			SubscriptionID:   account,
			ARMResourceID:    spec.ResourceID(model),
			EndpointAudience: endpoint,
			Endpoint:         endpoint,
			APIVersion:       spec.APIVersion,
		},
		InputPerMTok:  p.Input,
		OutputPerMTok: p.Output,
		PriceVersion:  priceVersion,
		KeyHint:       spec.KeyHint,
	}, nil
}

func printBindPlan(w io.Writer, p bindPlan, activate bool) {
	fmt.Fprintf(w, "route:            %s\n", p.RouteID)
	fmt.Fprintf(w, "model:            %s\n", p.Model)
	if p.Binding.APIVersion != "" {
		fmt.Fprintf(w, "endpoint:         %s (api version %s)\n", p.Binding.Endpoint, p.Binding.APIVersion)
	} else {
		fmt.Fprintf(w, "endpoint:         %s\n", p.Binding.Endpoint)
	}
	fmt.Fprintf(w, "resource:         %s\n", p.Binding.ARMResourceID)
	fmt.Fprintf(w, "price snapshot:   input %.4f / output %.4f USD per MTok (%s)\n", p.InputPerMTok, p.OutputPerMTok, p.PriceVersion)
	fmt.Fprintf(w, "activate:         %v\n", activate)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To authorize jobs on this route the api and worker also need, in their env:")
	fmt.Fprintf(w, "  SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE=%s\n", p.Binding.ARMResourceID)
	fmt.Fprintln(w, "  SBCI_PROVIDER_RETENTION_POLICY_VERSION=<the published privacy-policy version>")
	fmt.Fprintf(w, "  %s\n", p.KeyHint)
}

func newRouteBindCmd(spec bindSpec) *cobra.Command {
	var (
		routeID   string
		endpoint  string
		account   string
		activate  bool
		exclusive bool
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   spec.Verb,
		Short: "bind a " + string(spec.Family) + " route: endpoint, provider resource identity, price snapshot from the pricing table",
		Long: "Bind a " + string(spec.Family) + " route (default " + spec.DefaultRouteID + ") to " + spec.Provider + ".\n\n" +
			"It writes the endpoint, the provider resource identity the disclosed attestation is\n" +
			"scoped to, and a per-MTok price snapshot copied from the pricing table this binary\n" +
			"carries (internal/intelligence/cost). Each write bumps the route generation, so any\n" +
			"earlier attestation stops matching. It refuses a route of another family and a model\n" +
			"the pricing table cannot price.\n\n" +
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
			plan, err := planBind(spec, route, endpoint, account,
				func(model string) (cost.Pricing, bool) { return table.LookupAt(model, now) },
				pricingTableVersion())
			if err != nil {
				return err
			}
			printBindPlan(out, plan, activate)
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
			if err := s.RecordAudit(ctx, "", "route_"+strings.ReplaceAll(spec.Verb, "-", "_"), detail); err != nil {
				fmt.Fprintf(out, "warning: audit row not written: %v\n", err)
			}
			fmt.Fprintln(out, "\nbound")
			return nil
		},
	}
	cmd.Flags().StringVar(&routeID, "route-id", spec.DefaultRouteID, "route to bind")
	cmd.Flags().StringVar(&endpoint, "endpoint", spec.DefaultEndpoint, "provider endpoint (https)")
	cmd.Flags().StringVar(&account, "account", "default", "operator label for the provider account the key belongs to (recorded on the binding)")
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
