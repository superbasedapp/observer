package policy

import (
	"regexp"
	"strings"
)

// settingsApprovalPrefixes are the D19 security-sensitive config key families
// (Plane A W2-8) beyond selfLoweringSections: what is shared, what content is
// captured, where requests and data go, admission and the SDK destination.
// An agent changes them only through MCP set_setting, which files a proposal
// the person approves; `observer config set` and PUT /api/config/keys of one
// of these keys are R-165 self-approvals.
//
// The list mirrors internal/settingsgate's approval families (this package
// stays import-free); settingsgate's TestPolicyCoversEveryApprovalFamily
// fails when the two drift.
var settingsApprovalPrefixes = []string{
	"org_client.share",
	"aggregate_share",
	"observability.store_content",
	"observer.process.network.capture_bodies",
	"observability.egress",
	"observability.judge",
	"observability.admission.judge",
	"observability.eval.judge_base_url",
	// The whole admission block (review finding R-B07): its scope, its
	// prefilter and secret_remote_judge decide what admission checks and
	// where, as much as its mode does. observability.enabled turns the app
	// subsystem, admission included, on or off.
	"observability.admission",
	"observability.enabled",
	"observability.sdk",
	// Review E-24 (ruling D29): judge sampling and model, proxied-turn
	// trace synthesis, alerting on/off and the machine's database path.
	"observability.eval.online_sample_rate",
	"observability.eval.online_scorers",
	"observability.eval.judge_model",
	"observability.proxy_turn_traces",
	"observability.alerts.enabled",
	"observer.db_path",
}

// settingsApprovalConfigKey reports whether key is in a D19 family or is a
// sensitive-tier leaf (sensitiveConfigKeys).
func settingsApprovalConfigKey(key string) bool {
	for _, list := range [][]string{settingsApprovalPrefixes, sensitiveConfigKeys} {
		for _, p := range list {
			if strings.EqualFold(key, p) || hasFoldPrefix(key, p+".") {
				return true
			}
		}
	}
	return false
}

// selfLoweringKeyText is the text fallback of selfLoweringConfigKey for a
// config keys body the JSON matcher cannot see as one: a "key" field whose
// value is a key in any self-lowering section, D19 family or sensitive leaf
// (review finding R-B07: the fallback used to name only the four guard
// sections).
func selfLoweringKeyText() string {
	var alts []string
	for _, list := range [][]string{selfLoweringSections, settingsApprovalPrefixes, sensitiveConfigKeys} {
		for _, p := range list {
			alts = append(alts, regexp.QuoteMeta(p))
		}
	}
	return `(?i)\bkey\\?["']?\s*[:=]\s*\\?["']?\s*(?:` + strings.Join(alts, "|") + `)(?:\.|\\?["'\s,}&]|$)`
}

// SelfLoweringConfigKey reports whether an agent's `observer config set` of
// key is an R-165 self-approval: a guard or security section key, or a D19
// settings family. Exported for the settingsgate drift test.
func SelfLoweringConfigKey(key string) bool { return selfLoweringConfigKey(key) }
