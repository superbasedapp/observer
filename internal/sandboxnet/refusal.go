package sandboxnet

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// refusal.go is the egress refusal audit model (OpenShell build plan 05,
// section 3.1, the frozen N1 contract): the closed Rule vocabulary a
// refusal is recorded under, the mapping table from the gateway's own rule
// constants onto it, and the structured 403 body the gateway answers a
// refused request with. It is pure: the gateway reports a Refusal through
// Gateway.Report, and the host helper and the daemon carry it on.
//
// The gateway's rule constants (policy.go, hosts.go, provider.go,
// tlsname.go, gateway.go) stay the operator-visible names of the 403
// message and the run log; RefusalRule is the coarser, closed name a
// stored refusal, the read route and the dashboard dispatch on.

// RefusalRule is the closed vocabulary of a recorded refusal. Values are
// spelled with hyphens, like the gateway's own rule names.
type RefusalRule string

// The closed RefusalRule vocabulary. The first six are the plan's names;
// the last three cover gateway decisions none of the six describe (lane N1
// decision, recorded in its report).
const (
	// RefusalAllowListMiss: the run's host allow-list does not list the
	// target (or the target name cannot be compared with the list).
	RefusalAllowListMiss RefusalRule = "allow-list-miss"
	// RefusalPrivateRange: the target is in a private, shared-address,
	// unique-local or site-local range the operator has not allow-listed.
	RefusalPrivateRange RefusalRule = "private-range"
	// RefusalProviderHost: the target is a model provider's host or
	// address while the run's provider-host block is on.
	RefusalProviderHost RefusalRule = "provider-host"
	// RefusalHostLocal: the target is one of the host's own addresses (or
	// the host's addresses could not be listed, so it cannot be told apart).
	RefusalHostLocal RefusalRule = "host-local"
	// RefusalTierNone: the run's tier has no network at all. The gateway
	// never runs at that tier, so no gateway rule maps here; a backend
	// whose own network layer refuses at tier none reports it.
	RefusalTierNone RefusalRule = "tier-none"
	// RefusalSSRFFloor: the target is loopback, link-local, multicast,
	// unspecified or another address no allow-list can lift.
	RefusalSSRFFloor RefusalRule = "ssrf-floor"
	// RefusalLiteralIP: a literal IP target while a host list or the
	// provider-host block is set.
	RefusalLiteralIP RefusalRule = "literal-ip"
	// RefusalPortNotAllowed: a port other than 443 for CONNECT (80 for a
	// plain http request) while a host list is set.
	RefusalPortNotAllowed RefusalRule = "port-not-allowed"
	// RefusalTLSServerName: a tunnel whose TLS ClientHello names no server,
	// or another server than the CONNECT target, while a host list is set.
	RefusalTLSServerName RefusalRule = "tls-server-name"
)

// RefusalRules is the vocabulary in its one fixed order.
var RefusalRules = []RefusalRule{
	RefusalAllowListMiss, RefusalPrivateRange, RefusalProviderHost, RefusalHostLocal,
	RefusalTierNone, RefusalSSRFFloor, RefusalLiteralIP, RefusalPortNotAllowed, RefusalTLSServerName,
}

// Valid reports whether r is in the closed vocabulary.
func (r RefusalRule) Valid() bool {
	for _, v := range RefusalRules {
		if v == r {
			return true
		}
	}
	return false
}

// The config and pin keys a refusal names (Refusal.Key). An org pin that
// narrows the host list uses the same key name as the local setting
// (config governance), so one key covers both.
const (
	KeyEgressAllowHosts = "terminal.sandbox.egress_allow_hosts"
	KeyEgressAllowCIDRs = "terminal.sandbox.egress_allow_cidrs"
	KeyEgress           = "terminal.sandbox.egress"
	KeyProviderDirect   = "terminal.sandbox.provider_direct"
	// KeyInstallHosts is not a config key: it names the host list of the
	// first-start install step's gateway (the tool registry's install
	// hosts for the tool being installed), which no setting changes, so a
	// refusal there is never read as a miss of the owner's host list
	// (tracker F-009, audit finding N1-A11).
	KeyInstallHosts = "sandbox.install_hosts"
)

// Refusal is one refused egress attempt. The gateway fills Host, Port,
// Rule, Key and At; the run's identity (RunID, Backend, Tier) is stamped by
// whoever knows it (the daemon, from the relay channel and the stored run),
// never taken from the box.
type Refusal struct {
	RunID   string
	Backend string
	Tier    string
	Host    string
	Port    int
	Rule    RefusalRule
	Key     string
	At      time.Time
}

// refusalStage is the gateway check that refused: it picks the key of a
// rule more than one check can report (literal-ip).
type refusalStage string

const (
	stageHosts    refusalStage = "hosts"
	stagePort     refusalStage = "port"
	stageProvider refusalStage = "provider"
	stageLocal    refusalStage = "local"
	stagePolicy   refusalStage = "policy"
	stageTunnel   refusalStage = "tunnel"
)

// gatewayRuleRow maps one gateway rule constant onto the closed vocabulary.
type gatewayRuleRow struct {
	gateway string
	rule    RefusalRule
	key     string
}

// gatewayRuleRows is the mapping table: every gateway rule constant has
// exactly one row (TestGatewayRuleTableCoversEveryRule).
var gatewayRuleRows = []gatewayRuleRow{
	// hosts.go: the run's host allow-list.
	{RuleHostNotListed, RefusalAllowListMiss, KeyEgressAllowHosts},
	{RuleHostNameInvalid, RefusalAllowListMiss, KeyEgressAllowHosts},
	// hosts.go and provider.go: a literal IP under a list or the block.
	{RuleLiteralIP, RefusalLiteralIP, KeyEgressAllowHosts},
	// tlsname.go: the listed-run port and server-name checks.
	{RulePortNotAllowed, RefusalPortNotAllowed, KeyEgressAllowHosts},
	{RuleSNIAbsent, RefusalTLSServerName, KeyEgressAllowHosts},
	{RuleSNIMismatch, RefusalTLSServerName, KeyEgressAllowHosts},
	// provider.go: the model-provider host block.
	{RuleModelProviderHost, RefusalProviderHost, KeyProviderDirect},
	{RuleModelProviderAddress, RefusalProviderHost, KeyProviderDirect},
	{RuleProviderAddressesUnknown, RefusalProviderHost, KeyProviderDirect},
	// gateway.go and policy.go: the host's own addresses.
	{ruleLocalAddrsUnavailable, RefusalHostLocal, KeyEgress},
	{RuleHostLocal, RefusalHostLocal, KeyEgress},
	// policy.go: the allow-listable private ranges.
	{RulePrivate, RefusalPrivateRange, KeyEgressAllowCIDRs},
	{RuleSharedAddress, RefusalPrivateRange, KeyEgressAllowCIDRs},
	{RuleUniqueLocal, RefusalPrivateRange, KeyEgressAllowCIDRs},
	{RuleSiteLocal, RefusalPrivateRange, KeyEgressAllowCIDRs},
	// policy.go: the floor no allow-list lifts.
	{RuleNil, RefusalSSRFFloor, KeyEgress},
	{RuleUnspecified, RefusalSSRFFloor, KeyEgress},
	{RuleThisNetwork, RefusalSSRFFloor, KeyEgress},
	{RuleLoopback, RefusalSSRFFloor, KeyEgress},
	{RuleLinkLocalUnicast, RefusalSSRFFloor, KeyEgress},
	{RuleLinkLocalMulticast, RefusalSSRFFloor, KeyEgress},
	{RuleInterfaceLocalMulticast, RefusalSSRFFloor, KeyEgress},
	{RuleMulticast, RefusalSSRFFloor, KeyEgress},
	{RuleLimitedBroadcast, RefusalSSRFFloor, KeyEgress},
	{RuleIPv4Compatible, RefusalSSRFFloor, KeyEgress},
}

// stageKeyRows overrides a row's key when the named check reported the
// rule (literal-ip from the provider block names provider_direct, not the
// host list).
var stageKeyRows = []struct {
	stage   refusalStage
	gateway string
	key     string
}{
	{stageProvider, RuleLiteralIP, KeyProviderDirect},
}

// MapGatewayRule returns the closed rule and the deciding key for a gateway
// rule constant. ok is false for a name the table does not know.
func MapGatewayRule(gateway string) (RefusalRule, string, bool) {
	for _, r := range gatewayRuleRows {
		if r.gateway == gateway {
			return r.rule, r.key, true
		}
	}
	return "", "", false
}

// mapAt is MapGatewayRule with the stage's key override applied. An unknown
// name maps to the SSRF floor under the tier key: a refusal is never
// dropped for want of a row (the coverage test keeps the table complete).
func mapAt(stage refusalStage, gateway string) (RefusalRule, string) {
	rule, key, ok := MapGatewayRule(gateway)
	if !ok {
		rule, key = RefusalSSRFFloor, KeyEgress
	}
	for _, o := range stageKeyRows {
		if o.stage == stage && o.gateway == gateway {
			key = o.key
		}
	}
	return rule, key
}

// refusalNextSteps is what the 403 body tells the user to do, per rule.
var refusalNextSteps = []struct {
	rule RefusalRule
	text string
}{
	{RefusalAllowListMiss, "add the host to " + KeyEgressAllowHosts + " in the owner's config (if an organization pin narrowed the list, ask the organization)"},
	{RefusalPrivateRange, "add the destination's CIDR to " + KeyEgressAllowCIDRs},
	{RefusalProviderHost, "send model API calls through the Observer proxy the tool is configured with"},
	{RefusalHostLocal, "none: the host's own addresses are never reachable from a sandboxed run"},
	{RefusalTierNone, "relaunch with " + KeyEgress + " set to a tier that has a network"},
	{RefusalSSRFFloor, "none: loopback, link-local and similar addresses are never reachable from a sandboxed run"},
	{RefusalLiteralIP, "use the host's name instead of an IP address"},
	{RefusalPortNotAllowed, "use port 443 through CONNECT, or port 80 for a plain http request"},
	{RefusalTLSServerName, "send a TLS ClientHello whose server name is the CONNECT target"},
}

// refusalKeyNextSteps overrides a rule's next_step when the deciding key is
// not the one the rule's own text points at (audit finding FU5-A3): a
// refusal by the first-start install step's host list must not tell the
// user to edit their own host allow-list, which does not change it.
var refusalKeyNextSteps = []struct {
	rule RefusalRule
	key  string
	text string
}{
	{RefusalAllowListMiss, KeyInstallHosts, "none: a first-start tool install reaches only the tool's own install hosts, which no setting changes"},
}

// NextStepFor is the next_step text of rule decided by key: a
// refusalKeyNextSteps row when one names both, else NextStep(rule).
func NextStepFor(rule RefusalRule, key string) string {
	for _, r := range refusalKeyNextSteps {
		if r.rule == rule && r.key == key {
			return r.text
		}
	}
	return NextStep(rule)
}

// NextStep is the next_step text of rule ("" for a name outside the
// vocabulary).
func NextStep(rule RefusalRule) string {
	for _, r := range refusalNextSteps {
		if r.rule == rule {
			return r.text
		}
	}
	return ""
}

// RefusalErrorCode is the 403 body's error field.
const RefusalErrorCode = "egress_refused"

// RefusalBody is the structured 403 the gateway answers a refused request
// with. Message is the sentence the gateway answered in plain text before
// the body was structured, unchanged.
type RefusalBody struct {
	Error    string `json:"error"`
	Rule     string `json:"rule"`
	Key      string `json:"key"`
	Host     string `json:"host"`
	NextStep string `json:"next_step"`
	Message  string `json:"message"`
}

// RefusalJSON renders r's 403 body with message (HTML characters are not
// escaped, so the message reads as it did in plain text). It ends with a
// newline, as http.Error's body did.
func RefusalJSON(r Refusal, message string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(RefusalBody{
		Error:    RefusalErrorCode,
		Rule:     string(r.Rule),
		Key:      r.Key,
		Host:     r.Host,
		NextStep: NextStepFor(r.Rule, r.Key),
		Message:  message,
	})
	return b.Bytes()
}

// WriteRefusal writes r's structured 403 to w.
func WriteRefusal(w http.ResponseWriter, r Refusal, message string) {
	body := RefusalJSON(r, message)
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
}
