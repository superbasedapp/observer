package cloudagents

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/qoder"
)

// The Qoder Cloud Agents connector (lane CA-V2; grounding
// docs/plans/cloud-agents/grounding/wave-c-vendors-2026-11-01.md section 2).
// A personal access token reads the account's Cloud Agents sessions on the
// managed API (/api/v1/cloud) of the region the user picked when connecting.

// ConnectorQoderCloud is the Qoder Cloud Agents connector id.
const ConnectorQoderCloud = "qoder-cloud"

// SurfaceHostQoderCloud is the surface host of a Qoder Cloud Agents session
// (CA-D15): the session keeps tool "qoder" and is told apart by this fixed
// product token.
const SurfaceHostQoderCloud = "qoder-cloud"

// ParamRegion is the connection parameter naming the API region. Its value
// is one of the row's Regions ids, chosen from a picker, never free text.
const ParamRegion = "region"

// DetailEnvironment reads the environment a session ran in (Qoder: its
// config type decides execution_location through EnvironmentKinds).
const DetailEnvironment DetailKind = "environment"

// UnitQoderCredit is the Cloud Agents credit unit in cloud_usage_ledger
// (CA-D11: native, never converted to USD, never summed with tokens).
const UnitQoderCredit = qoder.UnitCloudCredit

// RevisableQoderCredits is the Revisable key of a Qoder session's cumulative
// credit total. The total grows without the session's updated_at moving
// (sandbox runtime credits accrue while the session sits idle, live check
// 2026-11-02), so a time-keyed record id would freeze the first figure read;
// as a revisable figure each changed total lands as a new revision that
// supersedes the previous one, and the ledger keeps one live row per session.
const RevisableQoderCredits = "qoder_credits_total"

// Region is one API region of a connector: an id the user picks, a label,
// and the exact host every request of an account in that region goes to.
type Region struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Host  string `json:"host"`
}

// qoderRegions is the Qoder region table: the managed API's default host and
// the China region host (the SDK's validate_region pairs: api.qoder.com =
// global, api.qoder.com.cn = cn).
var qoderRegions = []Region{
	{ID: "global", Label: "Global (api.qoder.com)", Host: "api.qoder.com"},
	{ID: "cn", Label: "China (api.qoder.com.cn)", Host: "api.qoder.com.cn"},
}

// regionChoices renders a region table as the picker choices of ParamRegion.
func regionChoices(rs []Region) []ParamChoice {
	out := make([]ParamChoice, 0, len(rs))
	for _, r := range rs {
		out = append(out, ParamChoice{Value: r.ID, Label: r.Label})
	}
	return out
}

func regionHosts(rs []Region) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Host)
	}
	return out
}

// RegionFor returns the region an account's parameters name. A connector
// with no region table has none; a connector with one never falls back: an
// absent or unknown region is refused.
func (c Connector) RegionFor(params map[string]string) (Region, bool) {
	v := strings.TrimSpace(params[ParamRegion])
	for _, r := range c.Regions {
		if r.ID == v {
			return r, true
		}
	}
	return Region{}, false
}

// EnvironmentKinds maps the environment config type the Qoder API reports to
// execution_location (CA-D1). A self-hosted environment runs the agent on
// the customer's own worker through the work-queue protocol; only this row
// stamps customer_worker. A config type no row names stamps nothing (the
// location stays unknown, never guessed).
var EnvironmentKinds = map[string]string{
	"cloud":       models.ExecutionVendorCloud,
	"self_hosted": models.ExecutionCustomerWorker,
}

// qoderCloudRow is the qoder-cloud connector row (appended to Connectors).
var qoderCloudRow = Connector{
	ID: ConnectorQoderCloud, Label: "Qoder Cloud Agents", Provider: "qoder", Issuer: "qoder.com",
	Tool: models.ToolQoder, SurfaceHost: SurfaceHostQoderCloud,
	Kind: SourceAPI, APIHosts: regionHosts(qoderRegions), Regions: qoderRegions, Auth: AuthBearer,
	KeyLabel: "Qoder personal access token (the QODER_ACCESS_TOKEN of the Cloud Agents SDK), created in your Qoder account settings under access tokens",
	Params: []ParamSpec{{
		Name: ParamRegion, Label: "Region",
		Hint:    "global for api.qoder.com, cn for api.qoder.com.cn (the region your Qoder account lives in)",
		Choices: regionChoices(qoderRegions),
	}},
	// GET /sessions orders by creation time and filters only on it, so a
	// pass reads every page up to MaxPages and filters on updated_at
	// locally (NewestFirst and ServerWindow false).
	PageLimit: 100, MaxPages: 10, Paged: true,
	Detail: []DetailKind{DetailEnvironment}, MaxViews: 20,
	History: true, MaxHistory: 10, HistoryPages: 5, HistoryWindow: true,
	Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
	Ceiling: map[Signal]CoverageState{
		SignalIdentity: CoveragePartialHistory, // the token's own sessions; the Session schema names no creator
		SignalActivity: CoveragePartialHistory, // events as metadata, text not stored
		SignalTokens:   CoverageVerified,       // session usage input/output/cache tokens, when the account reports them
		SignalUsage:    CoverageVerified,       // usage.total_credits per session (cumulative, model plus sandbox runtime)
		SignalBilling:  CoverageNotEstablished, // credits are not money (CA-D11)
		SignalControl:  CoverageNotEstablished,
	},
	// Session statuses (qca-sdk sessions.search Literal). idle means the
	// session finished a turn and waits for the next message; the SDK says
	// an idle status does not by itself mean success. rescheduling is the
	// platform moving the session to new compute (still alive). terminated
	// says the session ended but not how, so it maps like Devin's and
	// OpenHands' stopped sessions (cancelled), never succeeded.
	Statuses: map[string]Lifecycle{
		"running": LifecycleRunning, "rescheduling": LifecycleRunning,
		"idle":       LifecycleWaiting,
		"terminated": LifecycleCancelled,
	},
	DocRef: "grounding wave-c-vendors-2026-11-01 section 2 (Qoder), qca-sdk 54e7a314",
}

// qoderTask maps a qoder.cloud_session snapshot, its token row and its credit
// row onto a task (called from mapSnapshot). The session's usage.total_credits
// is the one credit figure landed (CA-D11, CA-D12): one cumulative
// provider-run-total figure per session, revisable so a re-read with a higher
// total supersedes the previous row. The model and sandbox runtime split has
// no ledger column; it stays on the vendor row's flags and the snapshot.
func qoderTask(c Connector, t Task, b map[string]string, usage []vendorapi.UsageRow) Task {
	t.RepoRemote = RemoteFromURL(b["repo_url"])
	t.EnvironmentID = boundField(b["environment_id"])
	if t.EnvironmentID != "" {
		// The location waits for the environment read (DetailEnvironment).
		t.DetailPending = len(c.Detail) > 0
		t.ExecutionPending = true
	}
	for _, u := range usage {
		if u.JoinNamespace == qoder.CloudSessionCreditsNamespace && u.ChargedUnit == qoder.UnitCloudCredit && u.JoinValue == t.ID {
			t.Usage = append(t.Usage, UsageFigure{
				Unit: UnitQoderCredit, Value: float64(u.ChargedMicros) / 1e6, ValueType: models.UsageValueCumulative,
				Source: models.UsageSourceProviderRunTotal, MonetaryStatus: models.UsageMonetaryNone,
				ReportedAt: u.At, Revisable: RevisableQoderCredits,
			})
			continue
		}
		if u.JoinNamespace != qoder.CloudSessionUsageNamespace {
			continue
		}
		// The managed API follows the Anthropic usage convention:
		// input_tokens excludes cache reads and cache creation (Inferred
		// from the SDK's field names; a live-check item).
		t.Tokens = &TokenFigure{
			Kind: TokenFromProviderRunTotal, Model: boundField(u.Model),
			Input: u.InputTokens, Output: u.OutputTokens, CacheRead: u.CacheReadTokens,
			CacheCreation: u.CacheWriteTokens, ReportedAt: u.At,
		}
	}
	return t
}

// applyQoderEnvironment folds an environment read into a task: the config
// type through EnvironmentKinds, else nothing stamped.
func applyQoderEnvironment(t Task, snaps []vendorapi.VendorSnapshot) Task {
	for _, s := range snaps {
		if s.Class != qoder.CloudEnvironmentClass || s.Subject != t.EnvironmentID {
			continue
		}
		t.EnvironmentKind = boundToken(s.Body["config_type"])
		t.ExecutionLocation = EnvironmentKinds[s.Body["config_type"]]
		t.ExecutionPending = false
	}
	return t
}

// qoderActions maps an event action to an activity kind (messages and tool
// calls land; every other event is counted).
var qoderActions = map[string]ActivityKind{
	qoder.ActionUserMessage:  ActivityPrompt,
	qoder.ActionAgentMessage: ActivityResponse,
	qoder.ActionToolCall:     ActivityToolCall,
}

// qoderHistory maps one events page: messages and tool calls as metadata
// activity, and a tool result as the outcome of its call (the same activity
// id, so a result read in a later page or pass patches the call,
// MapOutcomes). Events add no usage figure: their credits repeat the
// session's cumulative total, which the session read lands (qoderTask).
func qoderHistory(vp vendorapi.Page, sessionID string, hp *HistoryPage) {
	seen := func(at time.Time) {
		if at.After(hp.Newest) {
			hp.Newest = at
		}
	}
	calls := map[string]int{}
	for _, a := range vp.Audit {
		seen(a.At)
		if a.AgentSessionID != sessionID {
			continue
		}
		if a.Action == qoder.ActionToolResult {
			ref := a.Detail[qoder.DetailToolUseID]
			if ref == "" {
				continue
			}
			failed := a.Detail[qoder.DetailIsError] == "true"
			if i, ok := calls[ref]; ok {
				hp.Activity[i].OutcomeKnown, hp.Activity[i].Failed, hp.Activity[i].Pending = true, failed, false
				continue
			}
			hp.Activity = append(hp.Activity, Activity{
				ID: "ev:" + ref, At: a.At, Kind: ActivityToolCall, OutcomeKnown: true, Failed: failed,
			})
			continue
		}
		kind, ok := qoderActions[a.Action]
		if !ok {
			continue
		}
		act := Activity{ID: "ev:" + a.EventID, At: a.At, Kind: kind}
		if kind == ActivityToolCall {
			act.Tool, act.Pending = toolToken(a.Target), true
			calls[a.EventID] = len(hp.Activity)
		}
		hp.Activity = append(hp.Activity, act)
	}
}
