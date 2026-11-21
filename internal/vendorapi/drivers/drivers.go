package drivers

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/anthropic"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/aws"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cognition"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cursor"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/factory"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/github"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/google"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/jetbrains"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/kilo"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/microsoft"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/openai"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/opencode"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/openrouter"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/perplexity"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/poolside"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/prime"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/qoder"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/xai"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// table is the driver table, one constructor per surface.
var table = withFamilies(map[vs.SurfaceID]func() vendorapi.Driver{
	github.SurfaceOrgSeats:  github.OrgSeats,
	cursor.SurfaceMembers:   cursor.Members,
	cursor.SurfaceAuditLogs: cursor.AuditLogs,

	// lane ENTAPI-D3 (T-692): the read-only POST surfaces and the Graph
	// reports behind the OAuth client-credentials token step.
	cursor.SurfaceUsageEvents:         cursor.UsageEvents,
	cursor.SurfaceDailyUsage:          cursor.DailyUsage,
	cursor.SurfaceSpend:               cursor.Spend,
	microsoft.SurfaceUsageUserDetail:  microsoft.UsageUserDetail,
	microsoft.SurfaceUserCountSummary: microsoft.UserCountSummary,
	microsoft.SurfaceUserCountTrend:   microsoft.UserCountTrend,

	// lane ENTAPI-L15 (T-618): the first CONTENT surface, fetched only while
	// the connection's vendor content is on with its own consent.
	microsoft.SurfaceInteractions: microsoft.Interactions,

	// lane ENTAPI-D1 (T-609 Anthropic, T-610 OpenAI).
	anthropic.SurfaceUsageMessages:   anthropic.UsageMessages,
	anthropic.SurfaceCostReport:      anthropic.CostReport,
	anthropic.SurfaceClaudeCodeUsage: anthropic.ClaudeCodeUsage,
	anthropic.SurfaceUsers:           anthropic.Users,
	openai.SurfaceUsageCompletions:   openai.UsageCompletions,
	openai.SurfaceCosts:              openai.Costs,
	openai.SurfaceAuditLogs:          openai.AuditLogs,
	openai.SurfaceUsers:              openai.Users,

	// lane ENTAPI-H (T-697): Claude Enterprise per-user cost.
	anthropic.SurfaceUserCost: anthropic.UserCostReport,

	// lane ENTAPI-L16 (T-619): the Phase 8 long tail, Cognition Devin v3
	// and Factory analytics.
	cognition.SurfaceConsumptionDaily: cognition.ConsumptionDaily,
	cognition.SurfaceEnterpriseUsers:  cognition.EnterpriseUsers,
	cognition.SurfaceAuditLogs:        cognition.AuditLogs,
	factory.SurfaceTokens:             factory.Tokens,

	// lane ENTAPI-L16B (T-708): the remaining Devin v3 enterprise reads.
	cognition.SurfaceOrganizations: cognition.Organizations,
	cognition.SurfaceRoles:         cognition.Roles,
	cognition.SurfaceServiceUsers:  cognition.ServiceUsers,
	cognition.SurfaceIdPGroups:     cognition.IdPGroups,
	cognition.SurfaceACULimits:     cognition.ACULimits,
	cognition.SurfaceMetricsActive: cognition.MetricsActive,
	factory.SurfaceUsers:           factory.Users,
	factory.SurfaceOrgUsers:        factory.OrgUsers,
	factory.SurfaceLimitsUsers:     factory.LimitsUsers,
	xai.SurfaceAuditEvents:         xai.AuditEvents,
	xai.SurfaceSpendingLimits:      xai.SpendingLimits,
	qoder.SurfaceMembers:           qoder.Members,
	perplexity.SurfaceMemberUsage:  perplexity.MemberUsage,

	// lane ENTAPI-L16C (T-710): the rest of the Qoder Teams OpenAPI lists and
	// AI code trend, the Factory daily analytics, OpenCode Console budgets and
	// the Charm Hyper balance.
	qoder.SurfaceGroups:          qoder.Groups,
	qoder.SurfaceBillingGroups:   qoder.BillingGroups,
	qoder.SurfaceDailyTrend:      qoder.DailyTrend,
	factory.SurfaceActivity:      factory.Activity,
	factory.SurfaceProductivity:  factory.Productivity,
	factory.SurfaceTools:         factory.Tools,
	opencode.SurfaceBudgets:      opencode.Budgets,
	opencode.SurfaceHyperCredits: opencode.HyperCredits,
	// Lane ENTAPI-L16C (T-710): the first customer_host surface.
	jetbrains.SurfaceUsers: jetbrains.Users,

	// lane ENTAPI-L16C second half (T-710): OpenRouter management reads (the
	// activity lands as unattributed gateway facts), Prime team members and
	// the Kilo tRPC reads.
	openrouter.SurfaceOrgMembers: openrouter.OrgMembers,
	openrouter.SurfaceActivity:   openrouter.Activity,
	openrouter.SurfaceCredits:    openrouter.Credits,
	prime.SurfaceTeamMembers:     prime.TeamMembers,
	kilo.SurfaceTimeseries:       kilo.Timeseries,
	kilo.SurfaceMembers:          kilo.Members,

	// lane ENTAPI-L16D (T-713): the first drivers of the cloud signer tables,
	// CloudTrail Event history for Amazon Q Developer (AWS SigV4) and the
	// Gemini Code Assist audit logs through Cloud Logging (Google service
	// account token).
	aws.SurfaceQDeveloperEvents:   aws.QDeveloperEvents,
	google.SurfaceCodeAssistAudit: google.CodeAssistAudit,

	// lane ENTAPI-L16D (T-713): the remaining long-tail reads.
	perplexity.SurfaceMemberQueryVolume: perplexity.MemberQueryVolume,
	kilo.SurfaceTable:                   kilo.Table,
	prime.SurfaceWallet:                 prime.Wallet,

	// lane ENTAPI-L16E (T-717): customer-hosted drivers on the VCONN-HOST
	// binding, the JetBrains Hub SCIM user list and the LiteLLM gateway's
	// daily activity (unattributed gateway:litellm facts).
	jetbrains.SurfaceHubSCIM: jetbrains.HubSCIM,
	poolside.SurfaceLiteLLM:  poolside.LiteLLM,

	// cloud agents arc, lane CA-C3: the cloud-session lists the org's
	// vendor-connection projection reads (internal/orgserver/cloudproj).
	// The same pure drivers serve the node connector (lane CA-B2).
	cursor.SurfaceCloudAgents:    cursor.CloudAgents,
	cognition.SurfaceOrgSessions: cognition.OrgSessions,

	// cloud agents arc, lane CA-C8: the vendor-stated owners of Cursor cloud
	// agents. The key-info call names a user key's owner (the node
	// connector's connect probe parses it through the same function); the
	// cloud-filtered Admin API usage events name who ran each cloud agent.
	cursor.SurfaceCloudAgentMeta:   cursor.CloudAgentMeta,
	cursor.SurfaceCloudAgentOwners: cursor.CloudAgentOwners,
},
	// The GitHub activity families of lane L8 (T-611): each family is one
	// closed surface table in its package.
	github.MetricsReports(), github.AICreditReports(), github.AuditLogs(),
)

// withFamilies merges driver families into the base table.
func withFamilies(base map[vs.SurfaceID]func() vendorapi.Driver, fams ...map[vs.SurfaceID]func() vendorapi.Driver) map[vs.SurfaceID]func() vendorapi.Driver {
	for _, fam := range fams {
		for id, f := range fam {
			base[id] = f
		}
	}
	return base
}

// Lookup returns the driver of a surface.
func Lookup(id vs.SurfaceID) (vendorapi.Driver, bool) {
	f, ok := table[id]
	if !ok {
		return vendorapi.Driver{}, false
	}
	return f(), true
}

// Surfaces lists the surfaces that have a driver, sorted.
func Surfaces() []vs.SurfaceID {
	out := make([]vs.SurfaceID, 0, len(table))
	for id := range table {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
