package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/anthropic"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// Provider selection (12-factor, env). Exactly ONE provider family is wired
// per process; every route of another family parks provider_policy_unverified
// at the credential gate (FamilyCredentials holds only the selected family's
// key), and the router refuses its dialect even if one ever got that far.
const (
	// envInferenceProvider selects the provider family: "anthropic" (the
	// default since the 2026-10-20 ruling) or "foundry" (the Azure AI Foundry
	// lane, kept as a second implementation).
	envInferenceProvider = "SBCI_INFERENCE_PROVIDER"
	// envAnthropicAPIKey / envAnthropicAPIKeyFile carry the Anthropic key. The
	// _FILE form reads the key from a mounted file (a docker secret), so the
	// value never has to appear in a process environment listing.
	envAnthropicAPIKey     = "SBCI_ANTHROPIC_API_KEY"      //nolint:gosec // env var NAME, not a credential
	envAnthropicAPIKeyFile = "SBCI_ANTHROPIC_API_KEY_FILE" //nolint:gosec // env var NAME, not a credential
	// envAnthropicEffort is output_config.effort (low | medium | high; default low).
	envAnthropicEffort = "SBCI_ANTHROPIC_EFFORT"
	// envAnthropicPromptCache=0 turns off the system-prompt cache breakpoint.
	envAnthropicPromptCache = "SBCI_ANTHROPIC_PROMPT_CACHE"
	// envFoundryAPIKey is the Foundry key (foundry family only).
	envFoundryAPIKey = "SBCI_FOUNDRY_API_KEY" //nolint:gosec // env var NAME, not a credential
)

// chooseProviderFamily resolves SBCI_INFERENCE_PROVIDER. Unset means
// anthropic; an unknown value is a startup error (never a silent default).
func chooseProviderFamily() (inference.Family, error) {
	raw := strings.TrimSpace(os.Getenv(envInferenceProvider))
	if raw == "" {
		return inference.FamilyAnthropic, nil
	}
	f, ok := inference.ParseFamily(raw)
	if !ok {
		return "", fmt.Errorf("%s=%q is not a known provider (anthropic or foundry)", envInferenceProvider, raw)
	}
	return f, nil
}

// readSecretEnv returns the value of name, or the trimmed content of the file
// named by fileName when name is unset. It never logs either value.
func readSecretEnv(name, fileName string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v, nil
	}
	path := strings.TrimSpace(os.Getenv(fileName))
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-named secret file
	if err != nil {
		return "", fmt.Errorf("%s: %w", fileName, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// familyWiring is how the composition root wires one provider family: where
// its key comes from, and how its client is built. One row per family; the
// rest of the process only ever sees the inference seam.
type familyWiring struct {
	keyEnv     string
	keyFileEnv string // "" when the family has no _FILE form
	newClient  func(log *slog.Logger) (inference.Provider, error)
}

var familyWirings = map[inference.Family]familyWiring{
	inference.FamilyAnthropic: {
		keyEnv: envAnthropicAPIKey, keyFileEnv: envAnthropicAPIKeyFile,
		newClient: newAnthropicClient,
	},
	inference.FamilyFoundry: {
		keyEnv: envFoundryAPIKey,
		newClient: func(log *slog.Logger) (inference.Provider, error) {
			log.Info("observer-cloud: inference provider foundry")
			return &foundry.AzureClient{}, nil
		},
	},
}

func newAnthropicClient(log *slog.Logger) (inference.Provider, error) {
	effort := strings.ToLower(strings.TrimSpace(os.Getenv(envAnthropicEffort)))
	switch effort {
	case "":
		effort = anthropic.DefaultEffort
	case "low", "medium", "high":
	default:
		return nil, fmt.Errorf("%s=%q: want low, medium or high", envAnthropicEffort, effort)
	}
	noCache := strings.TrimSpace(os.Getenv(envAnthropicPromptCache)) == "0"
	log.Info("observer-cloud: inference provider anthropic", "effort", effort, "prompt_cache", !noCache)
	return &anthropic.Client{Effort: effort, DisablePromptCache: noCache}, nil
}

func wiringFor(family inference.Family) (familyWiring, error) {
	w, ok := familyWirings[family]
	if !ok {
		return familyWiring{}, fmt.Errorf("no wiring for provider %q", family)
	}
	return w, nil
}

// chooseCredentials returns the credential source for the selected family.
// An absent key resolves to AbsentCredentials, so every job parks
// provider_policy_unverified with no provider call (the §2.1 boundary: the gate
// is credential absence). A key is only ever handed to routes whose dialect
// belongs to the selected family.
func chooseCredentials(log *slog.Logger, family inference.Family) (jobs.CredentialSource, error) {
	w, err := wiringFor(family)
	if err != nil {
		return nil, err
	}
	key, err := readSecretEnv(w.keyEnv, w.keyFileEnv)
	if err != nil {
		return nil, err
	}
	if key == "" {
		log.Warn("observer-cloud: provider credential ABSENT - jobs park provider_policy_unverified", "provider", string(family), "env", w.keyEnv)
		return jobs.AbsentCredentials{}, nil
	}
	log.Info("observer-cloud: provider credential present", "provider", string(family))
	return jobs.FamilyCredentials{Keys: map[inference.Family]string{family: key}}, nil
}

// chooseInferenceProvider builds the router the executors call: the selected
// family's client, registered for exactly that family's dialects.
func chooseInferenceProvider(log *slog.Logger, family inference.Family) (*inference.Router, error) {
	w, err := wiringFor(family)
	if err != nil {
		return nil, err
	}
	client, err := w.newClient(log)
	if err != nil {
		return nil, err
	}
	m := map[inference.Dialect]inference.Provider{}
	for _, d := range inference.DialectsOf(family) {
		m[d] = client
	}
	return inference.NewRouter(m), nil
}

// chooseAttestor builds the provider-posture attestation gate for the selected
// family. A family whose dialect row is AttestationDisclosedOnly (Anthropic)
// can be authorized ONLY by the disclosed mode: the ARM canary and the
// operator-attested mode assert or read an Azure ContentLogging capability that
// does not exist there, so they are refused, and with no disclosure configured
// every job parks provider_policy_unverified. Nothing Azure-shaped (no IMDS
// token source, no ARM client) is constructed on that path.
//
// For the foundry family, three modes, selected by env, mutually exclusive
// between the two operator-asserted ones:
//
//   - default: the live ARM REST read of the ContentLogging capability
//     (plan §2.2, never `az`; token from attestTokenSourceFromEnv). With an
//     unbound route or an empty token the gate fails closed.
//   - SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE (+ _BY): the operator-attested
//     override (attest.OperatorAttestor).
//   - SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE (+ _POLICY_VERSION, _BY): the
//     disclosed-posture mode (attest.DisclosedAttestor).
//
// Both operator modes set at once is an ambiguous deployment: it is logged at
// startup and every job parks provider_policy_unverified until one is removed.
func chooseAttestor(s *store.Store, log *slog.Logger, family inference.Family) jobs.ProviderAttestor {
	disclosed := strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE"))
	attested := strings.TrimSpace(os.Getenv("SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE"))
	disclosedOnly := family.Attestation() == inference.AttestationDisclosedOnly
	switch {
	case disclosed != "" && attested != "":
		log.Error("observer-cloud: BOTH SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE and SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE are set - conflicting attestation modes; every job parks provider_policy_unverified until one is removed")
		// Returned WITHOUT the caching gate: a healthy record persisted before
		// the conflict was introduced must not authorize jobs for up to the
		// gate's max-age (review finding 2026-09-15).
		return jobs.RefusingAttestor{Reason: "conflicting attestation modes configured (fail closed)"}
	case disclosedOnly && attested != "":
		log.Error("observer-cloud: SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE asserts an Azure ContentLogging state that does not exist for the " +
			string(family) + " provider - refused; use the disclosed mode (SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE + _POLICY_VERSION)")
		return jobs.RefusingAttestor{Reason: "operator-attested ContentLogging mode does not apply to provider " + string(family) + " (fail closed)"}
	case disclosed != "":
		d := attest.DisclosedAttestor{
			AttestedResourceID: disclosed,
			PolicyVersion:      strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_POLICY_VERSION")),
			AttestedBy:         strings.TrimSpace(os.Getenv("SBCI_PROVIDER_RETENTION_DISCLOSED_BY")),
		}
		if d.PolicyVersion == "" {
			log.Error("observer-cloud: SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE is set but SBCI_PROVIDER_RETENTION_POLICY_VERSION is empty - the disclosed mode fails closed until a policy version is named")
		} else {
			log.Info("observer-cloud: attestation mode "+attest.ModeProviderRetentionDisclosed+" (provider-side retention NOT verified; disclosed under privacy policy v"+d.PolicyVersion+")",
				"provider", string(family), "resource", disclosed)
		}
		return jobs.NewAttestationGate(s, d, 15*time.Minute)
	case disclosedOnly:
		log.Error("observer-cloud: provider " + string(family) + " can only be authorized by the disclosed attestation mode and none is configured - every job parks provider_policy_unverified (set SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE + SBCI_PROVIDER_RETENTION_POLICY_VERSION)")
		return jobs.RefusingAttestor{Reason: "provider " + string(family) + " requires the " + attest.ModeProviderRetentionDisclosed + " attestation mode, which is not configured (fail closed)"}
	case attested != "":
		op := attest.OperatorAttestor{
			AttestedResourceID: attested,
			AttestedBy:         strings.TrimSpace(os.Getenv("SBCI_CONTENT_LOGGING_ATTESTED_BY")),
		}
		log.Info("observer-cloud: attestation mode operator-attested (asserts ContentLogging=false for the named resource)")
		return jobs.NewAttestationGate(s, op, 15*time.Minute)
	}
	arm := &attest.ARMAttestor{
		Tokens:     attestTokenSourceFromEnv(),
		BaseURL:    strings.TrimSpace(os.Getenv("SBCI_ARM_BASE_URL")),
		APIVersion: strings.TrimSpace(os.Getenv("SBCI_ARM_API_VERSION")),
	}
	return jobs.NewAttestationGate(s, arm, 15*time.Minute)
}

// tablePricer prices a call from the shared pricing table
// (internal/intelligence/cost: the baked seed plus the embedded Tokenomics
// pricing snapshot) at the instant the call completed. It honours the table's
// cache-read / cache-write rates and its long-context tier. The returned
// version names the table it priced under, and is what the result's provenance
// records as price_version.
func tablePricer() jobs.Pricer {
	table := cost.NewTable()
	version := pricingTableVersion()
	return func(route store.RouteInfo, res inference.Response, at time.Time) (float64, string, bool) {
		p, ok := table.LookupAt(route.Deployment, at)
		if !ok {
			return 0, "", false
		}
		usd := cost.Compute(p, cost.TokenBundle{
			Input:         res.Usage.Input,
			Output:        res.Usage.Output,
			CacheRead:     res.Usage.CacheRead,
			CacheCreation: res.Usage.CacheWrite,
		})
		return usd, version, true
	}
}

// pricingTableVersion labels the pricing table this binary carries.
func pricingTableVersion() string {
	meta := cost.PricingSnapshot()
	if meta.Present && meta.Err == nil {
		return fmt.Sprintf("pricing-table:feed-v%d", meta.FeedVersion)
	}
	return "pricing-table:seed"
}

// chooseFamilyCredentials resolves the provider family and its credential
// source together (the serve path needs both before it can build admission).
func chooseFamilyCredentials(log *slog.Logger) (inference.Family, jobs.CredentialSource, error) {
	family, err := chooseProviderFamily()
	if err != nil {
		return "", nil, err
	}
	creds, err := chooseCredentials(log, family)
	if err != nil {
		return "", nil, err
	}
	return family, creds, nil
}
