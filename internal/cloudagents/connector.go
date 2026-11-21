package cloudagents

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// SourceKind says how a connector reaches its vendor.
type SourceKind string

const (
	// SourceCLI runs the user's own vendor CLI with a fixed argv; the CLI's
	// own login is the credential and Observer stores none.
	SourceCLI SourceKind = "cli"
	// SourceAPI calls a vendor HTTPS API on an exact host with a key held in
	// the keychain (lane CA-B2).
	SourceAPI SourceKind = "api"
)

// Connector ids (the cloud_connector_accounts.connector token).
const (
	ConnectorCodexCloud   = "codex-cloud"
	ConnectorCopilotAgent = "copilot-agent"
	// The API connectors (lane CA-B2): an API key held in the keychain.
	ConnectorCursorCloud    = "cursor-cloud"
	ConnectorDevin          = "devin"
	ConnectorOpenHandsCloud = "openhands-cloud"
	// ConnectorWarpCloud is the Warp Agent API connector (lane CA-V1): Warp
	// cloud agent runs, landed under the tool their harness names.
	ConnectorWarpCloud = "warp-cloud"
)

// SurfaceHostCopilotCodingAgent is the surface host of a Copilot coding
// agent session (CA-D15). A fixed product token, never a path or prose.
const SurfaceHostCopilotCodingAgent = "copilot-coding-agent"

// SurfaceHostWarpCloud is the surface host of a Warp cloud agent run
// (CA-D15, lane CA-V1): a Claude Code or Codex harness run keeps tool
// claude-code or codex and is told apart by this fixed product token.
const SurfaceHostWarpCloud = "warp-cloud"

// Op is one operation a connector performs against its vendor.
type Op string

const (
	// OpIdentity reads who the vendor login belongs to (the connect probe).
	OpIdentity Op = "identity"
	// OpList lists recent sessions or tasks (discovery).
	OpList Op = "list"
	// OpView reads one session (per-session refresh).
	OpView Op = "view"
	// OpDetail reads one session's detail (Cursor: its runs or its usage).
	OpDetail Op = "detail"
	// OpHistory reads one page of one session's message or event history.
	OpHistory Op = "history"
	// OpStream reads one run's live event stream (Cursor SSE).
	OpStream Op = "stream"
)

// AuthScheme is how the egress presents an API connector's key.
type AuthScheme string

const (
	// AuthBasicUser sends HTTP Basic with the key as the user name and an
	// empty password (Cursor).
	AuthBasicUser AuthScheme = "basic_user"
	// AuthBearer sends "Authorization: Bearer <key>" (Devin v3, OpenHands
	// Cloud).
	AuthBearer AuthScheme = "bearer"
)

// Accept values an HTTPS request may ask for.
const (
	AcceptJSON        = "application/json"
	AcceptEventStream = "text/event-stream"
)

// Request is one call the egress package performs: for a CLI connector, the
// fixed argv (argv[0] is the bare command name, resolved on PATH by the
// egress package, never a path); for an API connector, an HTTPS GET of URL
// on one of the row's exact hosts, authenticated with Auth. A Request never
// carries the key: the egress adds it from the value the service read from
// the keychain.
type Request struct {
	Connector string
	Op        Op
	Argv      []string
	// URL is the absolute https URL of an API request.
	URL string
	// Auth is the scheme the key is presented with.
	Auth AuthScheme
	// Accept is AcceptJSON or AcceptEventStream.
	Accept string
	// LastEventID resumes an event stream ("" = from the start).
	LastEventID string
	// Absent lists the HTTP statuses that mean "this record does not exist
	// (yet)" for this request (Connector.Absent): the egress answers them
	// with the JSON body null instead of an error.
	Absent []int
}

// ParamSpec is one non-secret connection parameter an API connector needs
// besides its key (Devin: the organization id). The value is validated by
// Pattern and stored as the account id, never as a secret.
type ParamSpec struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Hint  string `json:"hint"`
	// Choices, when set, is the closed list the value is picked from (a
	// picker, never free text); ValidateParams refuses anything else.
	Choices []ParamChoice `json:"choices,omitempty"`
}

// ParamChoice is one value a picker parameter offers.
type ParamChoice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Connector is one row of the connector table.
type Connector struct {
	// ID is the connector token.
	ID string
	// Label is the display name.
	Label string
	// Provider is the vendor token (cloud_connector_accounts.provider).
	Provider string
	// Issuer is the identity namespace the account id is unique within.
	Issuer string
	// Tool is the Observer tool id a pulled session lands under. Where a
	// session ran is execution_location (CA-D1), not a new tool id. A row
	// that declares HarnessTools leaves it empty: the tool follows each
	// session's harness (ForTask).
	Tool string
	// HarnessTools declares that the tool a pulled session lands under
	// follows the vendor's harness, one row per harness (Warp: the run's
	// agent_config.harness.type). A harness with no row, or a row naming
	// tool "", lands no tool rows: no sessions, actions or token_usage row
	// (sessions.tool is required and no tool id is invented for a vendor
	// with no local adapter, operator ruling 2026-11-01); the run's native
	// usage still reaches the ledger. nil means every session lands under
	// Tool.
	HarnessTools map[string]string
	// ToolVocabulary is the tool id whose native tool names the vendor's
	// tool calls carry, when that differs from the tool a session lands
	// under: MapActivity classifies a call through the canonical taxonomy
	// (internal/tooltax) under this id. Cline Cloud lands under tool
	// "cline" (the VS Code product) but its sandbox runs the Cline SDK,
	// whose tool names (run_commands, editor, read_files, ...) are
	// cline-cli's vocabulary, not the VS Code extension's. "" means the
	// landing tool's own vocabulary. A non-empty value must be a tool the
	// taxonomy has rows for (pinned by TestToolVocabularyIsATaxonomyTool).
	ToolVocabulary string
	// SurfaceHost is the sessions.surface_host token a pulled session is
	// stamped with when the vendor product behind the connector differs
	// from the tool id's ordinary product (CA-D15: the Copilot coding
	// agent keeps tool "copilot" and is told apart by host
	// "copilot-coding-agent"). The surface KIND stays unstamped: the list
	// does not say where the human started the task (web, IDE, gh), and
	// an unknown kind is never guessed. "" stamps nothing. Every non-empty
	// value must be in orgpush.go's knownSurfaceHosts (pinned by
	// cloudagentssvc's drift test).
	SurfaceHost string
	// Kind says how the vendor is reached.
	Kind SourceKind
	// Command is the vendor CLI (SourceCLI only).
	Command string
	// APIHosts is the exact HTTPS host table (SourceAPI only); the first
	// entry is the host every request of the row goes to.
	APIHosts []string
	// Regions, when set, is the row's region table (Qoder): the account's
	// region parameter picks the one host its requests go to, and APIHosts
	// lists every region's host for the egress table.
	Regions []Region
	// Auth is how the key is presented (SourceAPI only).
	Auth AuthScheme
	// KeyLabel names the key the user pastes and where the vendor issues it
	// (SourceAPI only).
	KeyLabel string
	// Params are the non-secret connection parameters the row needs.
	Params []ParamSpec
	// NewestFirst declares that the list call returns sessions newest
	// update first, so a pass may stop at the first one older than its
	// window. False means the order is not documented: a pass reads every
	// page up to MaxPages and filters locally.
	NewestFirst bool
	// ServerWindow declares that the list call takes an updated-since
	// filter, so a pass asks the vendor for its window only.
	ServerWindow bool
	// Detail lists the per-session detail calls of the row (Cursor: runs,
	// usage), read for at most MaxViews sessions per pass.
	Detail []DetailKind
	// History declares a per-session message or event history call, read
	// for at most MaxHistory sessions and HistoryPages pages each per pass.
	History      bool
	MaxHistory   int
	HistoryPages int
	// HistoryWindow declares that the history call takes a time window, so
	// a pass resumes from the newest record read minus the overlap
	// (OpenHands, Qoder); otherwise it resumes from a page cursor (Devin).
	HistoryWindow bool
	// Stream declares a per-run live event stream (Cursor SSE), read for at
	// most MaxStreams runs per pass and StreamWindow each.
	Stream       bool
	MaxStreams   int
	StreamWindow time.Duration
	// StreamRetention is how long after a run ends its stream can still be
	// replayed, when the vendor has not said (the last observed retention
	// header wins, StreamRetentionFor). An ended run older than this is
	// recorded as a gap without a request. 0 = unknown: nothing is skipped.
	StreamRetention time.Duration
	// Experimental marks a vendor surface the vendor itself labels
	// experimental or preview; the UI says so.
	Experimental bool
	// PageLimit is the per-call page size the vendor allows.
	PageLimit int
	// MaxPages bounds the pages one discovery pass reads.
	MaxPages int
	// Paged is true when the list call returns a continuation cursor.
	Paged bool
	// Viewable is true when a single session can be re-read by id with the
	// CLI view call (used for open sessions that fell off the list). An API
	// row re-reads sessions through its Detail calls instead.
	Viewable bool
	// MaxViews bounds per-session refreshes (CLI views, API detail reads)
	// per sync.
	MaxViews int
	// Overlap is the discovery overlap window behind the high-water mark.
	Overlap time.Duration
	// Interval is the poll cadence of the daemon loop.
	Interval time.Duration
	// InferRepoFromEnvLabel declares that an environment label shaped like a
	// GitHub "owner/repo" slug MAY name the task's repository (an inference,
	// recorded as such). Since decision CA-D16 the inference is taken only
	// when that remote is already the remote of a project the node knows; a
	// label naming no known project files the task under the connector's
	// placeholder project with the "repository not reported" note, never a
	// new project from a guess. False means a task without a repository
	// field always goes to the placeholder.
	InferRepoFromEnvLabel bool
	// Ceiling is the best coverage each signal can reach on this connector
	// when the account is healthy; discovery follows the account's state.
	Ceiling map[Signal]CoverageState
	// Statuses maps the vendor's status strings to a lifecycle.
	Statuses map[string]Lifecycle
	// StatusDetails refine a status by the vendor's finer status detail,
	// walked top-down (LifecycleOfDetail); a detail no row names leaves the
	// status mapping alone.
	StatusDetails []StatusDetailRule
	// DocRef names the reviewed reference chapter.
	DocRef string
	// MemberUsers, when set, declares that the list returns the sessions of
	// every member of the account's organization or team (Devin: a key
	// scoped to an organization; OpenHands: an organization key; Warp: a
	// Personal key sees its teams' runs, an Agent key the team's), not only
	// the key owner's. Such an account must name its vendor user; only that
	// user's sessions land (OwnershipOf), and with no user named a pass
	// pulls nothing (CLOUDAGENTS-6, owner.go; OpenHands and Warp CA-T8).
	MemberUsers *MemberUsers
	// Absent declares, per operation, the HTTP statuses the vendor answers
	// when a record does not exist (yet), so a missing record is an empty
	// read and never a failed pass (Cline: a session history answers 404
	// until an archive exists). An undeclared status keeps its error class.
	Absent []AbsentStatus
}

// AbsentStatus is one row of a connector's Absent table: operation Op
// answers Status when the record it reads does not exist.
type AbsentStatus struct {
	Op     Op
	Status int
}

// Vocabulary returns the tool id whose native tool names the connector's
// tool calls are classified under: ToolVocabulary when the row declares
// one, else the landing tool.
func (c Connector) Vocabulary() string {
	if c.ToolVocabulary != "" {
		return c.ToolVocabulary
	}
	return c.Tool
}

// AbsentFor returns the statuses op answers for a missing record.
func (c Connector) AbsentFor(op Op) []int {
	var out []int
	for _, a := range c.Absent {
		if a.Op == op {
			out = append(out, a.Status)
		}
	}
	return out
}

// Connectors is the connector table: lane CA-B1's two CLI connectors and
// lane CA-B2's three API connectors (cursor-cloud, devin, openhands-cloud).
var Connectors = []Connector{
	{
		ID: ConnectorCodexCloud, Label: "Codex Cloud", Provider: "openai", Issuer: "chatgpt",
		Tool: models.ToolCodex, Kind: SourceCLI, Command: "codex", Experimental: true,
		PageLimit: 20, MaxPages: 10, Paged: true, Viewable: false, NewestFirst: true,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		InferRepoFromEnvLabel: true,
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoveragePartialHistory, // the CLI login, no user key in the task schema
			SignalActivity: CoverageNotEstablished, // no transcript endpoint
			SignalTokens:   CoverageNotEstablished,
			SignalUsage:    CoverageNotEstablished,
			SignalBilling:  CoverageNotEstablished,
			SignalControl:  CoverageNotEstablished,
		},
		Statuses: map[string]Lifecycle{
			"pending": LifecycleRunning, "running": LifecycleRunning, "in_progress": LifecycleRunning,
			"ready": LifecycleSucceeded, "applied": LifecycleSucceeded, "completed": LifecycleSucceeded,
			"error": LifecycleFailed, "failed": LifecycleFailed,
			"cancelled": LifecycleCancelled, "canceled": LifecycleCancelled,
		},
		DocRef: "reference chapter 03, section 1 (CX01)",
	},
	{
		ID: ConnectorCopilotAgent, Label: "GitHub Copilot cloud agent", Provider: "github", Issuer: "github.com",
		Tool: models.ToolCopilot, SurfaceHost: SurfaceHostCopilotCodingAgent,
		Kind: SourceCLI, Command: "gh", Experimental: true,
		PageLimit: 100, MaxPages: 1, Paged: false, Viewable: true, MaxViews: 20, NewestFirst: true,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoverageVerified,       // the session's user login
			SignalActivity: CoverageNotEstablished, // `view --log` is text, not read in this lane
			SignalTokens:   CoverageNotEstablished,
			SignalUsage:    CoverageNotEstablished, // premium requests are not in the JSON fields
			SignalBilling:  CoverageNotEstablished,
			SignalControl:  CoverageNotEstablished,
		},
		Statuses: map[string]Lifecycle{
			"queued": LifecycleRunning, "in_progress": LifecycleRunning,
			"idle": LifecycleWaiting, "waiting_for_user": LifecycleWaiting,
			"completed": LifecycleSucceeded,
			"failed":    LifecycleFailed, "timed_out": LifecycleFailed,
			"cancelled": LifecycleCancelled,
		},
		DocRef: "reference chapter 04, user level discovery (GH01, GH02)",
	},
	{
		ID: ConnectorCursorCloud, Label: "Cursor Cloud Agents", Provider: "cursor", Issuer: "cursor.com",
		Tool: models.ToolCursor, Kind: SourceAPI, APIHosts: []string{"api.cursor.com"}, Auth: AuthBasicUser,
		KeyLabel:     "Cursor user API key (cursor.com Dashboard > API Keys, User API Keys, Add)",
		Experimental: true, // Cloud Agents API v1 is Public Beta (CU01)
		PageLimit:    100, MaxPages: 10, Paged: true, MaxViews: 5,
		// GET /v1/agents is ordered by updatedAt, newest first (live-verified
		// 2026-11-01 across four agents; NOT ordered by createdAt), and the
		// discovery window is on updatedAt, so a pass may stop at the first
		// agent older than its window.
		NewestFirst: true,
		Detail:      []DetailKind{DetailRuns, DetailUsage},
		Stream:      true, MaxStreams: 3, StreamWindow: 15 * time.Second,
		// Live 2026-11-01: every stream of a run older than a day answered
		// 410 stream_expired with X-Cursor-Stream-Retention-Seconds: 86400.
		StreamRetention: 24 * time.Hour,
		Overlap:         15 * time.Minute, Interval: 15 * time.Minute,
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoverageVerified,       // GET /v1/me: the key's user id
			SignalActivity: CoveragePartialHistory, // run streams: tool calls as metadata, text not stored; expired streams are gaps
			SignalTokens:   CoverageVerified,       // GET /v1/agents/{id}/usage totals
			SignalUsage:    CoverageNotEstablished,
			SignalBilling:  CoverageVerified, // per-run cost.chargedCents (and rawCostCents) of the usage read, live-verified 2026-11-01
			SignalControl:  CoverageNotEstablished,
		},
		// One table for agent and run statuses. Live 2026-11-01: runs report
		// FINISHED (succeeded) and CANCELLED; an agent reports IDLE when no
		// run is in progress. IDLE says nothing about how the agent's work
		// ended, so it is deliberately NOT a row (a row may not map to
		// unknown): it reads as unknown and the lifecycle comes from the
		// latest run (ApplyAPIDetail), pinned by TestCursorStatusVocabulary.
		Statuses: map[string]Lifecycle{
			"creating": LifecycleRunning, "running": LifecycleRunning, "queued": LifecycleRunning,
			"finished": LifecycleSucceeded, "completed": LifecycleSucceeded,
			"error": LifecycleFailed, "failed": LifecycleFailed,
			"cancelled": LifecycleCancelled, "canceled": LifecycleCancelled, "expired": LifecycleCancelled,
			"stopped": LifecycleCancelled,
		},
		DocRef: "reference chapter 02, Cloud Agents API v1 (CU01, CU02)",
	},
	{
		ID: ConnectorDevin, Label: "Devin", Provider: "cognition", Issuer: "devin.ai",
		Tool: models.ToolDevin, Kind: SourceAPI, APIHosts: []string{"api.devin.ai"}, Auth: AuthBearer,
		KeyLabel: "Devin personal access token or service-user key (cog_...), Settings > API keys",
		Params: []ParamSpec{{
			Name: ParamOrgID, Label: "Organization id",
			Hint: "org-<32 hex>, the id in https://api.devin.ai/v3/organizations/org-...; a token reaches every organization you can access, so name one",
		}},
		PageLimit: 200, MaxPages: 10, Paged: true, ServerWindow: true,
		History: true, MaxHistory: 10, HistoryPages: 5,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		// The organization's list holds every member's sessions and Devin
		// names no token owner: the account names the developer's Devin user
		// and only that user's sessions land (operator decision 2026-11-02).
		MemberUsers: &MemberUsers{Label: "Devin user", Pattern: devinUserRE},
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoveragePartialHistory, // the organization; the token owner is not reported
			SignalActivity: CoveragePartialHistory, // messages as metadata, text not stored
			SignalTokens:   CoverageNotEstablished, // Devin reports ACUs, not tokens
			SignalUsage:    CoverageVerified,       // acus_consumed per session
			SignalBilling:  CoveragePartialHistory, // on_demand_usage (USD) on Teams only
			SignalControl:  CoverageNotEstablished,
		},
		Statuses: map[string]Lifecycle{
			"new": LifecycleRunning, "claimed": LifecycleRunning, "running": LifecycleRunning,
			"working": LifecycleRunning, "resuming": LifecycleRunning, "started": LifecycleRunning,
			"blocked": LifecycleWaiting, "suspended": LifecycleWaiting, "sleeping": LifecycleWaiting,
			"waiting_for_user": LifecycleWaiting, "paused": LifecycleWaiting,
			"finished": LifecycleSucceeded, "exit": LifecycleSucceeded, "completed": LifecycleSucceeded,
			"error": LifecycleFailed, "failed": LifecycleFailed,
			"expired": LifecycleCancelled, "terminated": LifecycleCancelled, "cancelled": LifecycleCancelled,
			"stopped": LifecycleCancelled,
		},
		// A session done with its work and awaiting the next instruction
		// reports status "running" with status_detail "waiting_for_user",
		// indefinitely (live-verified 2026-11-01; the app says "Devin is
		// awaiting instructions"): waiting, not running.
		StatusDetails: []StatusDetailRule{
			{Status: "running", Detail: "waiting_for_user", Lifecycle: LifecycleWaiting},
		},
		DocRef: "reference chapter 05, managed API (DV01, DV03, DV06)",
	},
	{
		ID: ConnectorOpenHandsCloud, Label: "OpenHands Cloud", Provider: "openhands", Issuer: "app.all-hands.dev",
		Tool: ToolOpenHands, Kind: SourceAPI, APIHosts: []string{"app.all-hands.dev"}, Auth: AuthBearer,
		KeyLabel:  "OpenHands Cloud API key (Settings > API Keys; not the LLM key)",
		PageLimit: 100, MaxPages: 10, Paged: true, ServerWindow: true,
		History: true, MaxHistory: 10, HistoryPages: 5, HistoryWindow: true,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		// The search lists every conversation the key can see, an
		// organization's too, and OpenHands names no key owner: the account
		// names the developer's OpenHands user and only that user's
		// conversations land (CLOUDAGENTS-6, task CA-T8). The id grammar is
		// conservative until the live check (owner.go).
		MemberUsers: &MemberUsers{Label: "OpenHands user", Pattern: openHandsUserRE},
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoveragePartialHistory, // created_by_user_id per conversation; no key-owner call
			SignalActivity: CoveragePartialHistory, // events as metadata, text not stored
			SignalTokens:   CoverageVerified,       // metrics.accumulated_token_usage
			SignalUsage:    CoverageNotEstablished,
			SignalBilling:  CoverageVerified, // metrics.accumulated_cost (USD, provider reported)
			SignalControl:  CoverageNotEstablished,
		},
		Statuses: map[string]Lifecycle{
			"running": LifecycleRunning, "starting": LifecycleRunning,
			"idle": LifecycleWaiting, "paused": LifecycleWaiting, "waiting_for_confirmation": LifecycleWaiting,
			"finished": LifecycleSucceeded, "completed": LifecycleSucceeded,
			"error": LifecycleFailed, "stuck": LifecycleFailed, "failed": LifecycleFailed,
			"stopped": LifecycleCancelled, "cancelled": LifecycleCancelled,
		},
		DocRef: "reference chapter 08, Cloud V1 API (OH01, OH04, OH08)",
	},
	{
		// Lane CA-V1: the Warp Agent API (grounding wave-c-vendors-2026-11-01
		// section 1). Documented, not live-verified (CA-D17).
		ID: ConnectorWarpCloud, Label: "Warp cloud agents", Provider: "warp", Issuer: "app.warp.dev",
		SurfaceHost: SurfaceHostWarpCloud, Kind: SourceAPI, APIHosts: []string{"app.warp.dev"}, Auth: AuthBearer,
		KeyLabel: "Warp API key (wk-...): in the Warp app, Settings > Platform > API Keys, create a Personal key (or run `oz api-key create`)",
		// The harness decides the tool. Warp's own oz harness has no local
		// adapter, so its runs land no tool rows (only their ledger rows);
		// gemini and pi (in the OpenAPI enum, not in the harness docs) have
		// no row and land the same way.
		HarnessTools: map[string]string{
			"claude": models.ToolClaudeCode,
			"codex":  models.ToolCodex,
			"oz":     "",
		},
		// GET /agent/runs defaults to updated_at descending and takes
		// updated_after (no upper bound), so a pass asks for its window and
		// may stop at the first run older than it.
		PageLimit: 100, MaxPages: 10, Paged: true, ServerWindow: true, NewestFirst: true,
		Detail: []DetailKind{DetailHarnessUsage}, MaxViews: 10,
		// The normalized conversation is one document, read whole.
		History: true, MaxHistory: 10, HistoryPages: 1,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		// A Personal key lists the runs of the user's teams as well as the
		// user's own, an Agent key the whole team's, and Warp names no key
		// owner: the account names the developer's Warp user and only the
		// runs that user created land; a run a service account created is
		// never landed (CLOUDAGENTS-6, task CA-T8; warpCreators).
		MemberUsers: &MemberUsers{Label: "Warp user", Pattern: warpUserRE},
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoveragePartialHistory, // the run's creator uid; no call names the key owner
			SignalActivity: CoveragePartialHistory, // conversation messages and actions as metadata, text not stored
			SignalTokens:   CoveragePartialHistory, // harness counters for Claude Code and Codex runs only
			SignalUsage:    CoverageVerified,       // request_usage credits per run
			SignalBilling:  CoveragePartialHistory, // request_usage USD; older runs fall back to an unmarked estimate
			SignalControl:  CoverageNotEstablished,
		},
		// The OpenAPI RunState enum, lowercased.
		Statuses: map[string]Lifecycle{
			"queued": LifecycleRunning, "pending": LifecycleRunning, "claimed": LifecycleRunning,
			"inprogress": LifecycleRunning,
			"blocked":    LifecycleWaiting,
			"succeeded":  LifecycleSucceeded,
			"failed":     LifecycleFailed, "error": LifecycleFailed,
			"cancelled": LifecycleCancelled,
		},
		DocRef: "grounding wave-c-vendors-2026-11-01 section 1 (Warp Agent API OpenAPI at docs 4aa3f12)",
	},
	// Lane CA-V2: Qoder Cloud Agents (qoder.go).
	qoderCloudRow,
	// Lane CA-V6: Cline Cloud Agents. The session API is undocumented
	// (grounding "Observed in vendor client, undocumented", grounding.go);
	// mapping and status tables in cline.go.
	{
		ID: ConnectorClineCloud, Label: "Cline Cloud Agents", Provider: "cline", Issuer: "cline.bot",
		Tool: models.ToolCline, SurfaceHost: SurfaceHostClineCloud,
		// The cloud sandbox runs the Cline SDK, the same agent core as
		// cline-cli: its tool calls carry cline-cli's tool names (live
		// check 2026-11-02 observed run_commands and editor).
		ToolVocabulary: models.ToolClineCLI,
		Kind:           SourceAPI, APIHosts: []string{"api.cline.bot"}, Auth: AuthBearer,
		KeyLabel:     "Cline API key (create one at app.cline.bot, Account > API Keys)",
		Experimental: true, // Cline Cloud sessions are rolling out (VS Code 4.1.25, 2026-10-16)
		// GET /api/v1/session returns the whole list, unpaged; 1000 or more
		// sessions is read as possibly truncated (a gap), never as complete.
		PageLimit: 1000, MaxPages: 1, Paged: false,
		Detail: []DetailKind{DetailStatus}, MaxViews: 10,
		History: true, MaxHistory: 10, HistoryPages: 1,
		Overlap: 15 * time.Minute, Interval: 15 * time.Minute,
		Ceiling: map[Signal]CoverageState{
			SignalIdentity: CoverageNotEstablished, // no user on the record and no owner call read
			SignalActivity: CoveragePartialHistory, // the archived history: messages and tool calls as metadata, text not stored
			SignalTokens:   CoveragePartialHistory, // message metrics "when available"
			SignalUsage:    CoverageNotEstablished,
			SignalBilling:  CoveragePartialHistory, // message metrics.cost (Cline credits are USD) when reported
			SignalControl:  CoverageNotEstablished,
		},
		Statuses:      clineStatuses,
		StatusDetails: clineStatusDetails,
		// The client reads 404 as session_not_found / no archive and 410 as
		// session_expired (@cline/core 0.2.0 dist/cloud/index.js).
		Absent: []AbsentStatus{
			{OpDetail, 404}, {OpDetail, 410}, {OpHistory, 404}, {OpHistory, 410},
		},
		DocRef: "grounding/wave-c-vendors-2026-11-01.md section 6 (Cline); @cline/core 0.2.0 dist/cloud/api.d.ts (undocumented)",
	},
}

// ForTask returns the connector as it applies to one task: a row that
// declares HarnessTools takes the tool of the task's harness. ok is false
// when the task lands no tool rows (a harness with no tool; for a row with a
// fixed Tool, never).
func ForTask(c Connector, t Task) (Connector, bool) {
	if c.HarnessTools == nil {
		return c, c.Tool != ""
	}
	c.Tool = c.HarnessTools[t.Harness]
	return c, c.Tool != ""
}

// ToolOpenHands is the tool id OpenHands Cloud conversations land under. No
// capture adapter or integration registry row exists for OpenHands yet; the
// connector is its only source (the value equals the A4 driver's Tool).
const ToolOpenHands = "openhands"

// ParamOrgID is the Devin connection parameter naming the organization.
const ParamOrgID = "org_id"

// DetailKind is one per-session detail call.
type DetailKind string

const (
	// DetailRuns lists an agent's runs (Cursor).
	DetailRuns DetailKind = "runs"
	// DetailUsage reads an agent's token totals (Cursor).
	DetailUsage DetailKind = "usage"
	// DetailHarnessUsage reads a run's native harness token counters
	// (Warp, Claude Code and Codex harness runs only).
	DetailHarnessUsage DetailKind = "harness_usage"
)

// detailHarnesses limits a detail call to the harnesses the vendor documents
// it for (Warp: "a Claude Code or Codex run"); a kind with no row applies to
// every task.
var detailHarnesses = map[DetailKind]map[string]bool{
	DetailHarnessUsage: {"claude": true, "codex": true},
}

// DetailApplies reports whether detail call kind applies to task t.
func DetailApplies(kind DetailKind, t Task) bool {
	hs, ok := detailHarnesses[kind]
	return !ok || hs[t.Harness]
}

// NeedsDetail reports whether any of the row's detail calls applies to t.
func NeedsDetail(c Connector, t Task) bool {
	for _, k := range c.Detail {
		if DetailApplies(k, t) {
			return true
		}
	}
	return false
}

// BaseURL is the https origin of an API connector's requests.
func (c Connector) BaseURL() string {
	if c.Kind != SourceAPI || len(c.APIHosts) == 0 {
		return ""
	}
	return "https://" + c.APIHosts[0]
}

// ConnectorByID returns the connector row with id.
func ConnectorByID(id string) (Connector, bool) {
	for _, c := range Connectors {
		if c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}

// CoverageFor returns the coverage of signal s on connector c for an
// account whose discovery state is account. Discovery IS the account state;
// every other signal is capped by the connector's ceiling and drops to the
// account's state when the account cannot collect at all.
func (c Connector) CoverageFor(s Signal, account CoverageState) CoverageState {
	if s == SignalDiscovery {
		return account
	}
	ceil, ok := c.Ceiling[s]
	if !ok {
		ceil = CoverageNotEstablished
	}
	switch account {
	case CoverageDisconnected, CoveragePermissionRequired, CoverageAvailable:
		if ceil != CoverageNotEstablished {
			return account
		}
	}
	return ceil
}

// Lifecycle is the normalized state of a cloud task.
type Lifecycle string

const (
	LifecycleRunning   Lifecycle = "running"
	LifecycleWaiting   Lifecycle = "waiting"
	LifecycleSucceeded Lifecycle = "succeeded"
	LifecycleFailed    Lifecycle = "failed"
	LifecycleCancelled Lifecycle = "cancelled"
	LifecycleUnknown   Lifecycle = "unknown"
)

// Terminal reports whether the task has ended.
func (l Lifecycle) Terminal() bool {
	return l == LifecycleSucceeded || l == LifecycleFailed || l == LifecycleCancelled
}

// LifecycleOf maps a vendor status through the connector's table; an
// unlisted status is "unknown" (never guessed terminal).
func (c Connector) LifecycleOf(status string) Lifecycle {
	if l, ok := c.Statuses[strings.ToLower(strings.TrimSpace(status))]; ok {
		return l
	}
	return LifecycleUnknown
}

// StatusDetailRule is one row of a connector's status-detail refinement:
// a session reporting Status with Detail is in Lifecycle.
type StatusDetailRule struct {
	Status, Detail string
	Lifecycle      Lifecycle
}

// LifecycleOfDetail maps a status refined by its status detail: the first
// StatusDetails row matching both wins, else the status alone decides
// (LifecycleOf), so an unknown detail never changes the mapping.
func (c Connector) LifecycleOfDetail(status, detail string) Lifecycle {
	s, d := strings.ToLower(strings.TrimSpace(status)), strings.ToLower(strings.TrimSpace(detail))
	if d != "" {
		for _, r := range c.StatusDetails {
			if r.Status == s && r.Detail == d {
				return r.Lifecycle
			}
		}
	}
	return c.LifecycleOf(status)
}

// --- argv builders -----------------------------------------------------------

// reCursor bounds a provider pagination cursor before it reaches an argv.
var reCursor = regexp.MustCompile(`^[A-Za-z0-9._~+/=:-]{1,512}$`)

// reSessionID bounds a vendor session id before it reaches an argv.
var reSessionID = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$`)

// ValidCursor reports whether a provider cursor may be passed on an argv.
func ValidCursor(c string) bool { return reCursor.MatchString(c) && !strings.HasPrefix(c, "-") }

// ValidSessionID reports whether a vendor session id may be passed on an
// argv or used as a sessions.id.
func ValidSessionID(id string) bool { return reSessionID.MatchString(id) }

// copilotFields is the --json field list of `gh agent-task list|view`
// (gh 2.89.0 capi.SessionFields).
const copilotFields = "id,name,state,repository,user,createdAt,updatedAt,completedAt,pullRequestNumber,pullRequestUrl,pullRequestState"

// ListRequest builds the discovery call. cursor is "" for the first page.
func (c Connector) ListRequest(cursor string) (Request, error) {
	switch c.ID {
	case ConnectorCodexCloud:
		argv := []string{"codex", "cloud", "list", "--json", "--limit", strconv.Itoa(c.PageLimit)}
		if cursor != "" {
			if !ValidCursor(cursor) {
				return Request{}, errInvalid("bad cursor")
			}
			argv = append(argv, "--cursor", cursor)
		}
		return Request{Connector: c.ID, Op: OpList, Argv: argv}, nil
	case ConnectorCopilotAgent:
		if cursor != "" {
			return Request{}, errInvalid("gh agent-task list has no cursor")
		}
		return Request{Connector: c.ID, Op: OpList, Argv: []string{
			"gh", "agent-task", "list", "--json", copilotFields, "-L", strconv.Itoa(c.PageLimit),
		}}, nil
	}
	return Request{}, errInvalid("connector has no list call")
}

// ViewRequest builds the per-session refresh call.
func (c Connector) ViewRequest(id string) (Request, error) {
	if !c.Viewable {
		return Request{}, errInvalid("connector has no view call")
	}
	if !ValidSessionID(id) {
		return Request{}, errInvalid("bad session id")
	}
	return Request{Connector: c.ID, Op: OpView, Argv: []string{
		"gh", "agent-task", "view", id, "--json", copilotFields,
	}}, nil
}

// IdentityRequest builds the connect probe.
func (c Connector) IdentityRequest() (Request, error) {
	switch c.ID {
	case ConnectorCodexCloud:
		// codex has no identity call that prints only an id; a one-task list
		// proves the login works and reads nothing from ~/.codex.
		return Request{Connector: c.ID, Op: OpIdentity, Argv: []string{"codex", "cloud", "list", "--json", "--limit", "1"}}, nil
	case ConnectorCopilotAgent:
		return Request{Connector: c.ID, Op: OpIdentity, Argv: []string{"gh", "api", "user"}}, nil
	}
	return Request{}, errInvalid("connector has no identity call")
}

// AllArgv returns every argv shape the connector table can produce, with
// placeholder ids, for the process-declaration test and security review.
func AllArgv() [][]string {
	var out [][]string
	for _, c := range Connectors {
		if c.Kind != SourceCLI {
			continue
		}
		if r, err := c.IdentityRequest(); err == nil {
			out = append(out, r.Argv)
		}
		if r, err := c.ListRequest(""); err == nil {
			out = append(out, r.Argv)
		}
		if c.Paged {
			if r, err := c.ListRequest("cursor0"); err == nil {
				out = append(out, r.Argv)
			}
		}
		if r, err := c.ViewRequest("00000000-0000-0000-0000-000000000000"); err == nil {
			out = append(out, r.Argv)
		}
	}
	return out
}

// Commands returns the set of vendor CLI names the table may run.
func Commands() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range Connectors {
		if c.Kind == SourceCLI && c.Command != "" && !seen[c.Command] {
			seen[c.Command] = true
			out = append(out, c.Command)
		}
	}
	return out
}

// --- CLI failure classification ----------------------------------------------

// stderrRule classifies one failed CLI run from its stderr. Walked top-down,
// first match wins; command "" matches every command.
type stderrRule struct {
	command  string
	contains string
	class    ErrorClass
}

var stderrRules = []stderrRule{
	{"", "rate limit", ErrRateLimited},
	{"codex", "not signed in", ErrNotSignedIn},
	{"codex", "codex login", ErrNotSignedIn},
	{"codex", "401", ErrNotSignedIn},
	{"codex", "403", ErrPermissionDenied},
	{"codex", "not enabled", ErrPermissionDenied},
	{"gh", "requires an oauth token", ErrNotSignedIn},
	{"gh", "gh auth login", ErrNotSignedIn},
	{"gh", "(http 401)", ErrNotSignedIn},
	{"gh", "(http 403)", ErrPermissionDenied},
	{"gh", "(http 404)", ErrPermissionDenied},
	{"gh", "unknown command", ErrNotInstalled}, // a gh older than 2.80 has no agent-task
	{"", "timed out", ErrTimeout},
	{"", "could not resolve", ErrUnreachable},
	{"", "connection refused", ErrUnreachable},
	{"", "network", ErrUnreachable},
}

// ClassifyCLIFailure maps a failed vendor CLI run (its exit code and
// stderr) to an error class. The stderr text itself is never returned.
func ClassifyCLIFailure(command string, exit int, stderr string) ErrorClass {
	low := strings.ToLower(stderr)
	for _, r := range stderrRules {
		if (r.command == "" || r.command == command) && strings.Contains(low, r.contains) {
			return r.class
		}
	}
	if command == "gh" && exit == 4 { // gh's documented "authentication required" exit code
		return ErrNotSignedIn
	}
	return ErrFailed
}

// Error is a typed failure of this package or of the egress that uses its
// classes. Its text never carries vendor output.
type Error struct {
	Class ErrorClass
	Msg   string
}

// Error implements error.
func (e *Error) Error() string {
	if e.Msg == "" {
		return "cloudagents: " + string(e.Class)
	}
	return "cloudagents: " + string(e.Class) + ": " + e.Msg
}

func errInvalid(msg string) error { return &Error{Class: ErrInvalid, Msg: msg} }

// ClassOf returns the error class of err: ErrNone for nil, the carried class
// for an *Error, ErrFailed otherwise.
func ClassOf(err error) ErrorClass {
	if err == nil {
		return ErrNone
	}
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Class
	}
	return ErrFailed
}

// NewError returns an *Error of class with a short safe message.
func NewError(class ErrorClass, msg string) error { return &Error{Class: class, Msg: msg} }
