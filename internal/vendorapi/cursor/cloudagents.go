package cursor

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Cloud Agents API v1 surfaces (lane CA-A4, cloud agents arc; plan
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, connector cursor-cloud). The API is per user: a user or
// service-account key lists the caller's own agents only, so these drivers
// are consumed by the node connector (lane CA-B2) through the node's own
// egress package. Since lane CA-C3 the agents list also has an org
// driver-table entry: an org connection (typically a team service-account
// key) lands that key's agents and internal/orgserver/cloudproj projects
// each. An agent names no person: since lane CA-C8 the org attributes it from
// the Admin API's cloud usage events (CloudAgentOwners) or a user key's owner
// (CloudAgentMeta), else it stays an org-level row. Runs and usage stay
// node-only (they are per-agent detail calls). Each Build is a GET on
// api.cursor.com; nothing here sends a request.
const (
	SurfaceCloudAgents     vs.SurfaceID = "cursor.cloudagent.agents"
	SurfaceCloudAgentRuns  vs.SurfaceID = "cursor.cloudagent.runs"
	SurfaceCloudAgentUsage vs.SurfaceID = "cursor.cloudagent.usage"

	CloudAgentsContract     = "cursor.cloudagent.agents/v1 cloud-agents-api v1 2026-10-07"
	CloudAgentRunsContract  = "cursor.cloudagent.runs/v1 cloud-agents-api v1 2026-10-07"
	CloudAgentUsageContract = "cursor.cloudagent.usage/v1 cloud-agents-api v1 2026-10-07"

	// CloudAgentClass is the snapshot class of one cloud agent (a durable
	// bc- agent, the session Observer shows); its subject is the agent id.
	CloudAgentClass = "cursor.cloud_agent"
	// CloudAgentRunClass is the snapshot class of one run of an agent; its
	// subject is the run id.
	CloudAgentRunClass = "cursor.cloud_agent_run"
	// CloudAgentUsageClass is the snapshot class of an agent's token totals
	// (Task subagents and side chats included, per the reference); its
	// subject is the agent id.
	CloudAgentUsageClass = "cursor.cloud_agent_usage"
	// CloudAgentRunUsageClass is the snapshot class of one run's token
	// counts; its subject is the run id.
	CloudAgentRunUsageClass = "cursor.cloud_agent_run_usage"

	// ParamAgentID is the connection parameter naming the agent whose runs
	// or usage a request reads.
	ParamAgentID = "agent_id"

	// CloudAgentPageSize is the documented maximum page size of the list
	// routes (default 20, max 100).
	CloudAgentPageSize = 100

	// maxSnapshotText caps a free-text snapshot value (the agent name) below
	// vendorapi.MaxAttrValue.
	maxSnapshotText = 256
)

// The usage counts land as snapshot body keys. A snapshot body key may not
// carry the secret-shaped fragment "token" (vendorapi.secretShaped), so the
// counts are named by direction and the body states its unit.
const (
	usageUnitKey   = "unit"
	usageUnitValue = "tokens"
)

var (
	// agentIDRE bounds a Cursor agent id before it enters a request path.
	// The reference documents bc- ids (bc-<uuid>); the legacy v0 examples
	// used bc_, which is accepted too.
	agentIDRE = regexp.MustCompile(`^bc[-_][A-Za-z0-9_-]{1,200}$`)
	// cloudCursorRE bounds an opaque nextCursor before it is sent back.
	cloudCursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)
	// runIDRE bounds a run id used as a snapshot subject.
	runIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,256}$`)
)

// CloudAgents returns the driver of cursor.cloudagent.agents.
//
// Contract (Cloud Agents API v1, "List Agents", reference source CU01): GET
// /v1/agents with limit (default 20, max 100) and cursor; the response is
// {"items": [{id, name, status, env: {type}, url, createdAt, updatedAt,
// latestRunId}], "nextCursor"} and nextCursor is omitted on the last page.
// The list covers the authenticated user's agents only and takes no time
// filter, so a run re-lists every agent and the consumer keeps its own
// checkpoint on updatedAt. Each agent lands as one snapshot of class
// cursor.cloud_agent keyed by its bc- id (the id Observer keeps as
// sessions.id, CA-D2).
func CloudAgents() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudAgents,
		Build:           buildCloudAgents,
		ParseResponse:   parseCloudAgents,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: CloudAgentsContract,
		Tool:            Tool,
		KnownPaths:      cloudAgentsKnownPaths,
	}
}

// CloudAgentRuns returns the driver of cursor.cloudagent.runs.
//
// Contract (Cloud Agents API v1, "List Runs", CU01): GET
// /v1/agents/{id}/runs with limit and cursor; the response is {"items":
// [{id, agentId, status, createdAt, updatedAt, git: {branches: [{repoUrl,
// branch}]}}]} with nextCursor while more runs exist. A run carries state
// and branch, never a transcript (v1 has no transcript endpoint). Each run
// lands as one snapshot of class cursor.cloud_agent_run keyed by its run id.
// The agent id comes from the agent_id parameter.
func CloudAgentRuns() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudAgentRuns,
		Build:           buildCloudAgentRuns,
		ParseResponse:   parseCloudAgentRuns,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: CloudAgentRunsContract,
		Tool:            Tool,
		KnownPaths:      cloudAgentRunsKnownPaths,
	}
}

// CloudAgentUsage returns the driver of cursor.cloudagent.usage.
//
// Contract (Cloud Agents API v1, "Get Agent Usage", CU01): GET
// /v1/agents/{id}/usage, one document {"totalUsage": {inputTokens,
// outputTokens, cacheWriteTokens, cacheReadTokens, totalTokens}, "runs":
// [{id, usageUuid, usage: {...}}]}. The counts match the tokenUsage object
// of the Admin API usage events, and totalUsage includes Task subagents and
// side chats. The document carries no timestamp, so the counts land as
// snapshots (a per-call usage row needs a time): one cursor.cloud_agent_usage
// snapshot of the agent's totals and one cursor.cloud_agent_run_usage
// snapshot per run, each body stating its unit (tokens). Provider units stay
// native (CA-D11); nothing is priced here.
//
// Live-verified 2026-11-01 (a Cursor Pro account): the document also carries
// "cost": {"rawCostCents", "chargedCents"} on the agent and on each run, in
// US cents with a fractional part (rawCostCents is what the usage would cost
// at list rates, chargedCents what was billed, 0 on a plan's included
// usage). Both are kept as the vendor's decimal text on the snapshot
// ("raw_cost_cents", "charged_cents"); an absent amount stays absent. The
// cost members are not in the corpus ledger (KnownPaths), so the runner's
// shape digest wildcards them until a recorded live fixture adds them.
func CloudAgentUsage() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudAgentUsage,
		Build:           buildCloudAgentUsage,
		ParseResponse:   parseCloudAgentUsage,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage},
		ClosedDTO:       true,
		ContractVersion: CloudAgentUsageContract,
		Tool:            Tool,
		KnownPaths:      cloudAgentUsageKnownPaths,
	}
}

// listQuery adds the page size and a validated cursor.
func listQuery(surface vs.SurfaceID, cursor string) (map[string][]string, error) {
	q := map[string][]string{"limit": {strconv.Itoa(CloudAgentPageSize)}}
	if cursor == "" {
		return q, nil
	}
	if !cloudCursorRE.MatchString(cursor) {
		return nil, fmt.Errorf("%s: cursor is not an opaque nextCursor", surface)
	}
	q["cursor"] = []string{cursor}
	return q, nil
}

// agentPath renders /v1/agents/{id}<suffix> from the agent_id parameter.
func agentPath(surface vs.SurfaceID, p vendorapi.Params, suffix string) (string, error) {
	id := p[ParamAgentID]
	if !agentIDRE.MatchString(id) {
		return "", fmt.Errorf("%s: parameter %s must be a Cursor agent id (bc-...)", surface, ParamAgentID)
	}
	return "/v1/agents/" + url.PathEscape(id) + suffix, nil
}

func buildCloudAgents(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q, err := listQuery(SurfaceCloudAgents, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/agents", Query: q}, nil
}

func buildCloudAgentRuns(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	path, err := agentPath(SurfaceCloudAgentRuns, p, "/runs")
	if err != nil {
		return vendorapi.Request{}, err
	}
	q, err := listQuery(SurfaceCloudAgentRuns, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path, Query: q}, nil
}

func buildCloudAgentUsage(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the usage document has one page", SurfaceCloudAgentUsage)
	}
	path, err := agentPath(SurfaceCloudAgentUsage, p, "/usage")
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path}, nil
}

// cloudList is the v1 list envelope: items (required) and nextCursor
// (omitted on the last page).
type cloudList[T any] struct {
	Items      *[]T    `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

// cloudEnvelope checks one list page's paging contract and returns its next
// cursor ("" on the last page).
func cloudEnvelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *cloudList[T]) (string, error) {
	if r.Status != 200 {
		return "", drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := decode(r.Body, doc); err != nil {
		return "", drift(surface, "body does not decode as the documented list")
	}
	if doc.Items == nil {
		return "", drift(surface, "required field items is missing")
	}
	if doc.NextCursor == nil || *doc.NextCursor == "" {
		return "", nil
	}
	if !cloudCursorRE.MatchString(*doc.NextCursor) {
		return "", drift(surface, "nextCursor is not an opaque cursor")
	}
	if *doc.NextCursor == r.Cursor {
		return "", drift(surface, "nextCursor repeats the cursor the page was asked with")
	}
	return *doc.NextCursor, nil
}

// isoTime reads an ISO 8601 / RFC 3339 timestamp and renders it in UTC
// seconds precision.
func isoTime(s *string) (string, bool) {
	if s == nil || *s == "" {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

// capText cuts free text at a rune boundary within maxSnapshotText bytes.
func capText(s string) string {
	if len(s) <= maxSnapshotText {
		return s
	}
	cut := maxSnapshotText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

type cloudAgent struct {
	ID          *string `json:"id"`
	Name        *string `json:"name"`
	Status      *string `json:"status"`
	URL         *string `json:"url"`
	CreatedAt   *string `json:"createdAt"`
	UpdatedAt   *string `json:"updatedAt"`
	LatestRunID *string `json:"latestRunId"`
	Env         *struct {
		Type *string `json:"type"`
	} `json:"env"`
}

func parseCloudAgents(r vendorapi.Response) (vendorapi.Page, error) {
	var doc cloudList[cloudAgent]
	next, err := cloudEnvelope(SurfaceCloudAgents, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next}
	seen := map[string]bool{}
	for i, a := range *doc.Items {
		id := str(a.ID)
		if !agentIDRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d].id is not a Cursor agent id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d] repeats an agent", i)
		}
		seen[id] = true
		status := str(a.Status)
		if status == "" || len(status) > 64 {
			return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d].status is missing", i)
		}
		created, ok := isoTime(a.CreatedAt)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d].createdAt is not an ISO timestamp", i)
		}
		body := map[string]string{"status": status, "created_at": created}
		if a.UpdatedAt != nil {
			v, ok := isoTime(a.UpdatedAt)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d].updatedAt is not an ISO timestamp", i)
			}
			body["updated_at"] = v
		}
		if v := capText(str(a.Name)); v != "" {
			body["name"] = v
		}
		if v := str(a.URL); v != "" && len(v) <= vendorapi.MaxAttrValue {
			body["url"] = v
		}
		if v := str(a.LatestRunID); v != "" {
			if !runIDRE.MatchString(v) {
				return vendorapi.Page{}, drift(SurfaceCloudAgents, "items[%d].latestRunId is not a run id", i)
			}
			body["latest_run_id"] = v
		}
		if a.Env != nil && str(a.Env.Type) != "" {
			body["env_type"] = capText(str(a.Env.Type))
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: CloudAgentClass, Subject: id, Body: body})
	}
	return page, nil
}

type cloudRun struct {
	ID        *string `json:"id"`
	AgentID   *string `json:"agentId"`
	Status    *string `json:"status"`
	CreatedAt *string `json:"createdAt"`
	UpdatedAt *string `json:"updatedAt"`
	Git       *struct {
		Branches *[]struct {
			RepoURL *string `json:"repoUrl"`
			Branch  *string `json:"branch"`
		} `json:"branches"`
	} `json:"git"`
}

func parseCloudAgentRuns(r vendorapi.Response) (vendorapi.Page, error) {
	var doc cloudList[cloudRun]
	next, err := cloudEnvelope(SurfaceCloudAgentRuns, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	want := r.Params[ParamAgentID]
	page := vendorapi.Page{NextCursor: next}
	seen := map[string]bool{}
	for i, run := range *doc.Items {
		id := str(run.ID)
		if !runIDRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d].id is not a run id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d] repeats a run", i)
		}
		seen[id] = true
		agent := str(run.AgentID)
		if !agentIDRE.MatchString(agent) {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d].agentId is not a Cursor agent id", i)
		}
		if want != "" && agent != want {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d] belongs to another agent than the one asked for", i)
		}
		status := str(run.Status)
		if status == "" || len(status) > 64 {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d].status is missing", i)
		}
		created, ok := isoTime(run.CreatedAt)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d].createdAt is not an ISO timestamp", i)
		}
		body := map[string]string{"agent_id": agent, "status": status, "created_at": created}
		if run.UpdatedAt != nil {
			v, ok := isoTime(run.UpdatedAt)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceCloudAgentRuns, "items[%d].updatedAt is not an ISO timestamp", i)
			}
			body["updated_at"] = v
		}
		if run.Git != nil && run.Git.Branches != nil {
			branches := *run.Git.Branches
			body["branch_count"] = strconv.Itoa(len(branches))
			if len(branches) > 0 {
				if v := str(branches[0].RepoURL); v != "" && len(v) <= vendorapi.MaxAttrValue {
					body["repo_url"] = v
				}
				if v := str(branches[0].Branch); v != "" && len(v) <= vendorapi.MaxAttrValue {
					body["branch"] = v
				}
			}
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: CloudAgentRunClass, Subject: id, Body: body})
	}
	return page, nil
}

// cloudTokens is the v1 token object (the Admin API tokenUsage shape).
type cloudTokens struct {
	InputTokens      *num `json:"inputTokens"`
	OutputTokens     *num `json:"outputTokens"`
	CacheWriteTokens *num `json:"cacheWriteTokens"`
	CacheReadTokens  *num `json:"cacheReadTokens"`
	TotalTokens      *num `json:"totalTokens"`
}

// cloudCost is the usage document's cost object (US cents, fractional).
type cloudCost struct {
	RawCostCents *num `json:"rawCostCents"`
	ChargedCents *num `json:"chargedCents"`
}

type usageDoc struct {
	TotalUsage *cloudTokens `json:"totalUsage"`
	Cost       *cloudCost   `json:"cost"`
	Runs       *[]struct {
		ID        *string      `json:"id"`
		UsageUUID *string      `json:"usageUuid"`
		Usage     *cloudTokens `json:"usage"`
		Cost      *cloudCost   `json:"cost"`
	} `json:"runs"`
}

// maxCents bounds a cost amount (one billion dollars in cents): a larger
// value is drift, not money.
const maxCents = 1e11

// costBody renders a cost object as snapshot body entries holding the
// vendor's decimal text; an absent amount is absent. A negative, non-finite
// or absurd amount refuses the document.
func costBody(c *cloudCost, into map[string]string) bool {
	if c == nil {
		return true
	}
	for _, f := range []struct {
		key string
		n   *num
	}{{"raw_cost_cents", c.RawCostCents}, {"charged_cents", c.ChargedCents}} {
		if f.n == nil {
			continue
		}
		v, err := strconv.ParseFloat(string(*f.n), 64)
		if err != nil || !(v >= 0 && v <= maxCents) {
			return false
		}
		into[f.key] = string(*f.n)
	}
	return true
}

// num is a JSON number kept as its literal text; it refuses a quoted value
// (a number turned string is a type change, plan 12A.5). A JSON null leaves
// a *num nil.
type num string

// UnmarshalJSON accepts a bare JSON number only.
func (n *num) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("cursor: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// tokenBody renders a token object as snapshot body entries; an absent count
// is absent, never zero.
func tokenBody(t *cloudTokens, into map[string]string) bool {
	if t == nil {
		return true
	}
	for _, f := range []struct {
		key string
		n   *num
	}{
		{"input", t.InputTokens},
		{"output", t.OutputTokens},
		{"cache_write", t.CacheWriteTokens},
		{"cache_read", t.CacheReadTokens},
		{"total", t.TotalTokens},
	} {
		if f.n == nil {
			continue
		}
		v, err := strconv.ParseInt(string(*f.n), 10, 64)
		if err != nil || v < 0 {
			return false
		}
		into[f.key] = strconv.FormatInt(v, 10)
	}
	into[usageUnitKey] = usageUnitValue
	return true
}

func parseCloudAgentUsage(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "status %d is not the documented 200", r.Status)
	}
	var doc usageDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "body does not decode as the documented object")
	}
	if doc.Runs == nil || doc.TotalUsage == nil {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "required field runs or totalUsage is missing")
	}
	agent := r.Params[ParamAgentID]
	if !agentIDRE.MatchString(agent) {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "the request's %s parameter is not a Cursor agent id", ParamAgentID)
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Runs)}
	total := map[string]string{"run_count": strconv.Itoa(len(*doc.Runs))}
	if !tokenBody(doc.TotalUsage, total) {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "totalUsage has a count that is not a whole non-negative number")
	}
	if !costBody(doc.Cost, total) {
		return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "cost has an amount that is not a non-negative number")
	}
	page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: CloudAgentUsageClass, Subject: agent, Body: total})
	seen := map[string]bool{}
	for i, run := range *doc.Runs {
		id := str(run.ID)
		if !runIDRE.MatchString(id) || run.Usage == nil {
			return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "runs[%d] misses id or usage", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "runs[%d] repeats a run", i)
		}
		seen[id] = true
		body := map[string]string{"agent_id": agent}
		if v := str(run.UsageUUID); v != "" {
			if !runIDRE.MatchString(v) {
				return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "runs[%d].usageUuid is not an id", i)
			}
			body["usage_uuid"] = v
		}
		if !tokenBody(run.Usage, body) {
			return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "runs[%d].usage has a count that is not a whole non-negative number", i)
		}
		if !costBody(run.Cost, body) {
			return vendorapi.Page{}, drift(SurfaceCloudAgentUsage, "runs[%d].cost has an amount that is not a non-negative number", i)
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: CloudAgentRunUsageClass, Subject: id, Body: body})
	}
	return page, nil
}

// cloudAgentsKnownPaths are the documented response paths (the corpus field
// ledger of "List Agents").
var cloudAgentsKnownPaths = []string{
	"items", "items[]", "items[].createdAt", "items[].env", "items[].env.type", "items[].id", "items[].latestRunId",
	"items[].name", "items[].status", "items[].updatedAt", "items[].url", "nextCursor",
}

// cloudAgentRunsKnownPaths are the documented response paths (the corpus
// field ledger of "List Runs").
var cloudAgentRunsKnownPaths = []string{
	"items", "items[]", "items[].agentId", "items[].createdAt", "items[].git", "items[].git.branches",
	"items[].git.branches[]", "items[].git.branches[].branch", "items[].git.branches[].repoUrl", "items[].id",
	"items[].status", "items[].updatedAt",
}

// cloudAgentUsageKnownPaths are the documented response paths (the corpus
// field ledger of "Get Agent Usage").
var cloudAgentUsageKnownPaths = []string{
	"runs", "runs[]", "runs[].id", "runs[].usage", "runs[].usage.cacheReadTokens", "runs[].usage.cacheWriteTokens",
	"runs[].usage.inputTokens", "runs[].usage.outputTokens", "runs[].usage.totalTokens", "runs[].usageUuid",
	"totalUsage", "totalUsage.cacheReadTokens", "totalUsage.cacheWriteTokens", "totalUsage.inputTokens",
	"totalUsage.outputTokens", "totalUsage.totalTokens",
}
