//go:build linux && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// sandbox_cred_broker.go is the provider_injected custody (sandbox plan v2
// section 7.2, decision 4 of lane GATES-SBX): a hosted vendor's own secret
// broker adds the user's key on egress. internal/sandboxcred holds the
// vendor table with its citations and the refusals; here the facts are read
// and a vendor's broker client, when one is registered, sets the rule up
// before the box is created and deletes it (and checks it is gone) at
// teardown. No vendor broker client is registered in this release: E2B and
// Vercel document one (cited in the table), but their clients live in
// internal/sandboxremote, another lane's package, so the custody stays
// unoffered and every provider_injected launch is refused by name. Linux
// only: the hosted host helper that calls it runs only there (WINFIX4 lint).

// credBroker is one vendor's broker client.
type credBroker interface {
	// Setup creates the rule that adds the provider's key to requests to
	// host and returns its id.
	Setup(ctx context.Context, runID, provider, host string) (string, error)
	// Remove deletes the rule.
	Remove(ctx context.Context, ruleID string) error
	// Exists reports whether the rule is still there.
	Exists(ctx context.Context, ruleID string) (bool, error)
}

// credBrokers are the registered broker clients by vendor id (none in this
// release; a test registers a fake).
var credBrokers = map[string]credBroker{}

// credBrokerOffered is sandboxcred.Offered (a test seam).
var credBrokerOffered = sandboxcred.Offered

// credInjectedFacts reads the provider_injected facts from the config. The
// org facts are read conservatively from the local config alone: an
// enrolled node with [guard.budget].from_org counts as budget-enforced, and
// an enrolled node counts as managed with no org allowance (no org value
// allows the custody yet).
var credInjectedFacts = func(vendor string) sandboxcred.InjectedFacts {
	f := sandboxcred.InjectedFacts{Vendor: vendor, Offered: credBrokerOffered(vendor) && credBrokers[vendor] != nil}
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()}); err == nil {
		enrolled := cfg.OrgClient.Enabled
		f.OrgBudgetsEnforced = enrolled && cfg.Guard.Budget.FromOrg
		f.Managed = enrolled
	}
	f.OrgForbids = sandboxOrgFloors().ForbidProviderInject
	return f
}

// credRules holds the broker rule of each provider_injected run.
var credRules = map[string]string{}

// credSetupProviderInjected applies the refusals, then sets the broker rule
// up.
func credSetupProviderInjected(ctx context.Context, plan hostedPlanFile) error {
	code, why, ok := sandboxcred.InjectedRefusal(credInjectedFacts(plan.Provider))
	if !ok {
		return fmt.Errorf("%s: %s", code, why)
	}
	provider := credToolProvider(plan.Tool)
	p, found := sandboxcred.ProviderFor(provider)
	if !found {
		return fmt.Errorf("%s: the tool's model provider is not one a broker rule serves", sandboxcred.CodeCustodyNotOffered)
	}
	id, err := credBrokers[plan.Provider].Setup(ctx, plan.RunID, p.ID, p.Host)
	if err != nil {
		return fmt.Errorf("set up the %s broker rule: %w", plan.Provider, err)
	}
	credRules[plan.RunID] = id
	return nil
}

// credTeardownProviderInjected deletes the run's broker rule and verifies
// it is gone.
func credTeardownProviderInjected(plan hostedPlanFile) {
	id, ok := credRules[plan.RunID]
	b := credBrokers[plan.Provider]
	if !ok || b == nil {
		return
	}
	delete(credRules, plan.RunID)
	ctx := context.Background()
	err := b.Remove(ctx, id)
	if gone, eerr := b.Exists(ctx, id); err != nil || eerr != nil || gone {
		slog.Default().Warn("terminal_sandbox: the run's broker rule may still exist; delete it in the vendor's console", "run", plan.RunID, "vendor", plan.Provider)
	}
}
