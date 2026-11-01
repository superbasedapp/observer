package dashapi

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// delivery.go is the dashboard's delivery (commit to PR to merge, D-689)
// wire: the service seam the write routes call, the JSON shapes, and the
// PURE composition of the Projects "Delivery" tab and the session card from
// rows the handlers already loaded. No rule lives here: landings come from
// internal/delivery.Evaluate (stored by the landing scan), metrics from
// delivery.Summarise. This file only joins and shapes.

// DeliveryMinScheduleMinutes is the smallest mirror refresh schedule a
// project may pick (plan 12.2). It equals deliverysvc.MinScheduleMinutes;
// cmd/observer pins the two together in a test, because this package must
// not import the egress service.
const DeliveryMinScheduleMinutes = 30

// DeliveryMaxScheduleMinutes caps a mirror schedule at one week.
const DeliveryMaxScheduleMinutes = 7 * 24 * 60

// deliveryPRCap bounds the PR table; deliveryRowCap bounds the "not in a
// pull request" list.
const (
	deliveryPRCap  = 200
	deliveryRowCap = 200
)

// DeliveryService is the write seam of the delivery routes. cmd/observer
// adapts *deliverysvc.Service to it (delivery_wire.go), translating the
// service's errors into *DeliveryError so a handler never matches on
// another package's sentinels.
type DeliveryService interface {
	Connect(ctx context.Context, req DeliveryConnectRequest) (delivery.ProviderLink, error)
	TestLink(ctx context.Context, linkID int64) (delivery.ProviderLink, error)
	Disconnect(ctx context.Context, linkID int64) error
	DeleteMirror(ctx context.Context, mirrorID int64) error
	MirrorUsage(ctx context.Context) (used, capBytes int64, mirrors []delivery.Mirror, err error)
	CheckProject(ctx context.Context, projectID int64) (DeliveryCheckResult, error)
}

// DeliveryConnectRequest is one "connect a code host" request. Token is the
// secret for AuthMode "token"; it goes straight to the keychain.
type DeliveryConnectRequest struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	AuthMode string `json:"auth_mode"`
	Token    string `json:"token,omitempty"`
}

// DeliveryCheckResult is what one "Check now" pass did.
type DeliveryCheckResult struct {
	CheckedAt   string              `json:"checked_at"`
	Reevaluated bool                `json:"reevaluated"`
	Repos       []DeliveryCheckRepo `json:"repos"`
}

// DeliveryCheckRepo is one remote's outcome in a "Check now" pass.
type DeliveryCheckRepo struct {
	RemoteName     string `json:"remote_name"`
	RepoSlug       string `json:"repo_slug,omitempty"`
	Source         string `json:"source"`
	Status         string `json:"status"`
	Detail         string `json:"detail,omitempty"`
	CommitsChecked int    `json:"commits_checked"`
	PRsUpserted    int    `json:"prs_upserted"`
}

// DeliveryError is a service failure with the HTTP status and the closed
// kind the page renders. Message is a plain sentence and never a secret.
type DeliveryError struct {
	Status  int
	Kind    string
	Message string
}

// Error implements error.
func (e *DeliveryError) Error() string { return e.Message }

// ---------------------------------------------------------------- wire

// APIDeliveryLink is one code-host connection on the wire. It never carries
// a secret or the keychain entry name.
type APIDeliveryLink struct {
	ID            int64  `json:"id"`
	Provider      string `json:"provider"`
	Host          string `json:"host"`
	AuthMode      string `json:"auth_mode"`
	AccountLogin  string `json:"account_login,omitempty"`
	ScopesSeen    string `json:"scopes_seen,omitempty"`
	Status        string `json:"status"`
	LastOKAt      string `json:"last_ok_at,omitempty"`
	LastErrorKind string `json:"last_error_kind,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	NextRunAt     string `json:"next_run_at,omitempty"`
	Failures      int    `json:"failures"`
	CreatedAt     string `json:"created_at,omitempty"`
	// Repos counts the repositories with recent AI-touched commits this
	// link answers for.
	Repos int `json:"repos"`
}

// APIDeliveryMirror is one Observer-owned mirror on the wire.
type APIDeliveryMirror struct {
	ID            int64  `json:"id"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	DefaultBranch string `json:"default_branch,omitempty"`
	SizeBytes     int64  `json:"size_bytes"`
	Status        string `json:"status"`
	LastError     string `json:"last_error,omitempty"`
	LastRefreshAt string `json:"last_refresh_at,omitempty"`
	LastCheckAt   string `json:"last_check_at,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

// APIDeliveryLinksResponse is GET /api/delivery/links.
type APIDeliveryLinksResponse struct {
	// ServiceAvailable is false when this process has no delivery service
	// (connect, test and disconnect then answer 503).
	ServiceAvailable bool              `json:"service_available"`
	PollMinutes      int               `json:"poll_minutes"`
	Links            []APIDeliveryLink `json:"links"`
}

// APIDeliveryMirrorsResponse is GET /api/delivery/mirrors.
type APIDeliveryMirrorsResponse struct {
	ServiceAvailable bool                `json:"service_available"`
	UsedBytes        int64               `json:"used_bytes"`
	CapBytes         int64               `json:"cap_bytes"`
	Mirrors          []APIDeliveryMirror `json:"mirrors"`
}

// APIDeliverySettings is one project's delivery switches on the wire.
type APIDeliverySettings struct {
	MirrorEnabled   bool   `json:"mirror_enabled"`
	ScheduleMinutes int    `json:"schedule_minutes"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

// APIDeliveryLanding is one AI-touched commit's delivery outcome.
type APIDeliveryLanding struct {
	CommitID       int64    `json:"commit_id"`
	SHA            string   `json:"sha"`
	Subject        string   `json:"subject"`
	CommittedAt    string   `json:"committed_at"`
	Reachable      bool     `json:"reachable"`
	Status         string   `json:"status"`
	Kind           string   `json:"kind,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	RuleID         string   `json:"rule_id,omitempty"`
	LandingSHA     string   `json:"landing_sha,omitempty"`
	PRID           int64    `json:"pr_id,omitempty"`
	PRNumber       int64    `json:"pr_number,omitempty"`
	AbandonReason  string   `json:"abandon_reason,omitempty"`
	Source         string   `json:"source,omitempty"`
	LandedAt       string   `json:"landed_at,omitempty"`
	LandedAtSource string   `json:"landed_at_source,omitempty"`
	FirstPushedAt  string   `json:"first_pushed_at,omitempty"`
	EvaluatedAt    string   `json:"evaluated_at,omitempty"`
	SessionIDs     []string `json:"session_ids"`
	// OwnerSessionID is the commit's owning session (the Ownership rule),
	// "" when none is known for this window.
	OwnerSessionID string `json:"owner_session_id,omitempty"`
	// Prompt is one prompt whose files the commit carried (the owner's when
	// it has one), for the "prompt" excerpt on the row.
	Prompt *APIDeliveryPrompt `json:"prompt,omitempty"`
}

// APIDeliveryPrompt is a prompt reference on a landing row.
type APIDeliveryPrompt struct {
	ActionID  int64  `json:"action_id"`
	SessionID string `json:"session_id"`
	Preview   string `json:"preview"`
}

// APIDeliveryPR is one pull request on the wire.
type APIDeliveryPR struct {
	ID        int64  `json:"id"`
	LinkID    int64  `json:"link_id"`
	Provider  string `json:"provider"`
	Host      string `json:"host"`
	RepoSlug  string `json:"repo_slug"`
	Number    int64  `json:"number"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	State     string `json:"state"`
	Readiness string `json:"readiness,omitempty"`
	// Bucket is delivery.PRBucket's one definition of mergeable / blocked
	// (draft, open_ready, open_blocked, open_unknown, merged,
	// closed_unmerged), so the page never re-derives it.
	Bucket      string          `json:"bucket"`
	Facets      delivery.Facets `json:"facets"`
	RawState    string          `json:"raw_state,omitempty"`
	MergeMethod string          `json:"merge_method,omitempty"`
	CreatedAt   string          `json:"created_at,omitempty"`
	MergedAt    string          `json:"merged_at,omitempty"`
	ClosedAt    string          `json:"closed_at,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
	FetchedAt   string          `json:"fetched_at,omitempty"`
	// MergeSeconds is merged_at minus created_at, 0 when not merged.
	MergeSeconds int64 `json:"merge_seconds,omitempty"`
	// Stale is true when the link that fetched this PR is not currently
	// healthy: the row is the last good sync, shown dimmed.
	Stale bool `json:"stale"`
	// AICommits are this project's AI-touched commits in the PR, in the
	// window; Sessions the sessions that contributed to them.
	AICommits []APIDeliveryLanding `json:"ai_commits"`
	Sessions  []string             `json:"sessions"`
}

// APIDeliveryRate is a delivery.Rate on the wire. Value is meaningful only
// when Known.
type APIDeliveryRate struct {
	Known         bool    `json:"known"`
	Value         float64 `json:"value"`
	Num           int64   `json:"num"`
	Den           int64   `json:"den"`
	Caveat        string  `json:"caveat,omitempty"`
	UnknownReason string  `json:"unknown_reason,omitempty"`
}

// APIDeliveryCount is a delivery.Count on the wire.
type APIDeliveryCount struct {
	Known         bool   `json:"known"`
	Value         int64  `json:"value"`
	UnknownReason string `json:"unknown_reason,omitempty"`
}

// APIDeliveryMergeTime is a delivery.MergeTime on the wire, in seconds.
type APIDeliveryMergeTime struct {
	Known         bool   `json:"known"`
	P50Seconds    int64  `json:"p50_seconds"`
	P75Seconds    int64  `json:"p75_seconds"`
	Samples       int64  `json:"samples"`
	Source        string `json:"source,omitempty"`
	Caveat        string `json:"caveat,omitempty"`
	UnknownReason string `json:"unknown_reason,omitempty"`
}

// APIDeliveryFunnel is the prompt funnel on the wire.
type APIDeliveryFunnel struct {
	Known         bool   `json:"known"`
	EditedPrompts int64  `json:"edited_prompts"`
	Committed     int64  `json:"committed"`
	Pushed        int64  `json:"pushed"`
	InPR          int64  `json:"in_pr"`
	Landed        int64  `json:"landed"`
	Caveat        string `json:"caveat,omitempty"`
}

// APIDeliverySummary is delivery.Summary on the wire.
type APIDeliverySummary struct {
	AICommits        int64                `json:"ai_commits"`
	ByStatus         map[string]int64     `json:"by_status"`
	LandedExact      int64                `json:"landed_exact"`
	LandedPatch      int64                `json:"landed_patch"`
	LandedSquash     int64                `json:"landed_squash"`
	AcceptedWorkRate APIDeliveryRate      `json:"accepted_work_rate"`
	LandedShare      APIDeliveryRate      `json:"landed_share"`
	PRMergeRate      APIDeliveryRate      `json:"pr_merge_rate"`
	OpenMergeable    APIDeliveryCount     `json:"open_mergeable"`
	BlockedBacklog   map[string]int64     `json:"blocked_backlog"`
	BlockedKnown     bool                 `json:"blocked_known"`
	TimeToMerge      APIDeliveryMergeTime `json:"time_to_merge"`
	Funnel           APIDeliveryFunnel    `json:"funnel"`
	FetchAge         string               `json:"fetch_age"`
	StaleCaveat      string               `json:"stale_caveat,omitempty"`
}

// APIDeliveryRemote is one project remote with how it is kept fresh.
type APIDeliveryRemote struct {
	Name          string `json:"name"`
	URL           string `json:"url,omitempty"`
	Host          string `json:"host,omitempty"`
	Provider      string `json:"provider"`
	RepoSlug      string `json:"repo_slug,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	FetchHeadAt   string `json:"fetch_head_at,omitempty"`
	// Source is where this remote's evidence comes from: provider (a code
	// host link serves it), mirror (an Observer-owned mirror exists and the
	// project opted in) or user_refs (the user's own fetches).
	Source string `json:"source"`
	// LinkID / LinkStatus name the serving link; 0 / "" when none.
	LinkID     int64  `json:"link_id,omitempty"`
	LinkStatus string `json:"link_status,omitempty"`
	// Mirror is this remote's mirror, nil when none exists.
	Mirror *APIDeliveryMirror `json:"mirror,omitempty"`
}

// APIDeliverySource is the source line at the top of the Delivery tab.
type APIDeliverySource struct {
	// Kind: provider | mirror | user_refs | none (no remote).
	Kind string `json:"kind"`
	// Provider / AuthMode / AccountLogin / SyncedAt describe the serving
	// link when Kind is provider.
	Provider     string `json:"provider,omitempty"`
	AuthMode     string `json:"auth_mode,omitempty"`
	AccountLogin string `json:"account_login,omitempty"`
	RepoSlug     string `json:"repo_slug,omitempty"`
	SyncedAt     string `json:"synced_at,omitempty"`
	// LastFetchAt is the newest FETCH_HEAD mtime of the user's clone;
	// MirrorRefreshAt the mirror's last refresh. EvidenceAt is the one the
	// metrics were judged against.
	LastFetchAt     string `json:"last_fetch_at,omitempty"`
	MirrorRefreshAt string `json:"mirror_refresh_at,omitempty"`
	EvidenceAt      string `json:"evidence_at,omitempty"`
	// DefaultBranch is what "landed" means ("main"), "" when unknown.
	DefaultBranch string `json:"default_branch,omitempty"`
}

// APIDeliveryLinkProblem is set when the link serving this project is not
// healthy: the PR data below is the last good sync.
type APIDeliveryLinkProblem struct {
	LinkID    int64  `json:"link_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	LastOKAt  string `json:"last_ok_at,omitempty"`
	NextRunAt string `json:"next_run_at,omitempty"`
}

// APIProjectDelivery is GET /api/project/{id}/delivery.
type APIProjectDelivery struct {
	ProjectID      int64                   `json:"project_id"`
	LocalEnabled   bool                    `json:"local_enabled"`
	CountLikely    bool                    `json:"count_likely"`
	CanCheck       bool                    `json:"can_check"`
	Source         APIDeliverySource       `json:"source"`
	Remotes        []APIDeliveryRemote     `json:"remotes"`
	ProviderLinked bool                    `json:"provider_linked"`
	LinkProblem    *APIDeliveryLinkProblem `json:"link_problem,omitempty"`
	// MirrorEligible is true when at least one remote has no code-host link
	// serving it, so the per-project mirror opt-in applies.
	MirrorEligible bool                `json:"mirror_eligible"`
	Settings       APIDeliverySettings `json:"settings"`
	Summary        APIDeliverySummary  `json:"summary"`
	PullRequests   []APIDeliveryPR     `json:"pull_requests"`
	// NotInPR are AI-touched commits held by no PR shown above.
	NotInPR      []APIDeliveryLanding `json:"not_in_pr"`
	NotInPRTotal int                  `json:"not_in_pr_total"`
	// PendingCommits are commits in the window that an AI session touched
	// but whose landing is not evaluated yet.
	PendingCommits int  `json:"pending_commits"`
	Truncated      bool `json:"truncated,omitempty"`
	WindowDays     int  `json:"window_days"`
}

// APISessionDeliveryRow is one commit a session contributed to.
type APISessionDeliveryRow struct {
	CommitID    int64               `json:"commit_id"`
	SHA         string              `json:"sha"`
	Subject     string              `json:"subject"`
	CommittedAt string              `json:"committed_at"`
	Reachable   bool                `json:"reachable"`
	Owner       bool                `json:"owner"`
	Evaluated   bool                `json:"evaluated"`
	Landing     *APIDeliveryLanding `json:"landing,omitempty"`
	PR          *APIDeliveryPR      `json:"pr,omitempty"`
}

// APISessionDelivery is GET /api/session/{id}/delivery.
type APISessionDelivery struct {
	SessionID      string                  `json:"session_id"`
	ProjectID      int64                   `json:"project_id,omitempty"`
	LocalEnabled   bool                    `json:"local_enabled"`
	ProviderLinked bool                    `json:"provider_linked"`
	DefaultBranch  string                  `json:"default_branch,omitempty"`
	LastFetchAt    string                  `json:"last_fetch_at,omitempty"`
	Rows           []APISessionDeliveryRow `json:"rows"`
}

// ---------------------------------------------------------------- shaping

// DeliveryLinkWire shapes a link; repos is the served repository count.
func DeliveryLinkWire(l delivery.ProviderLink, repos int) APIDeliveryLink {
	return APIDeliveryLink{
		ID: l.ID, Provider: string(l.Provider), Host: l.Host, AuthMode: l.AuthMode,
		AccountLogin: l.AccountLogin, ScopesSeen: l.ScopesSeen, Status: nonEmpty(l.Status, "never_checked"),
		LastOKAt: FmtProjectTime(l.LastOKAt), LastErrorKind: l.LastErrorKind, LastError: l.LastError,
		NextRunAt: FmtProjectTime(l.NextRunAt), Failures: l.ConsecutiveFailures, CreatedAt: FmtProjectTime(l.CreatedAt),
		Repos: repos,
	}
}

// DeliveryMirrorWire shapes a mirror.
func DeliveryMirrorWire(m delivery.Mirror) APIDeliveryMirror {
	return APIDeliveryMirror{
		ID: m.ID, URL: m.URL, Path: m.Path, DefaultBranch: m.DefaultBranch, SizeBytes: m.SizeBytes,
		Status: nonEmpty(m.Status, "never"), LastError: m.LastError, LastRefreshAt: FmtProjectTime(m.LastRefreshAt),
		LastCheckAt: FmtProjectTime(m.LastCheckAt), CreatedAt: FmtProjectTime(m.CreatedAt),
	}
}

// DeliverySettingsWire shapes project settings.
func DeliverySettingsWire(ps delivery.ProjectSettings) APIDeliverySettings {
	return APIDeliverySettings{MirrorEnabled: ps.MirrorEnabled, ScheduleMinutes: ps.ScheduleMinutes, UpdatedAt: FmtProjectTime(ps.UpdatedAt)}
}

// ValidDeliverySchedule reports whether minutes is an allowed mirror
// schedule: 0 ("Check now" only) or between the minimum and one week.
func ValidDeliverySchedule(minutes int) bool {
	return minutes == 0 || (minutes >= DeliveryMinScheduleMinutes && minutes <= DeliveryMaxScheduleMinutes)
}

// deliveryLinkHealthy reports whether a link's last pass succeeded (or it
// has not been checked yet).
func deliveryLinkHealthy(status string) bool {
	return status == "" || status == "ok" || status == "never_checked"
}

// CountServedRepos counts, per link id, the remotes it serves.
func CountServedRepos(links []delivery.ProviderLink, remotes []delivery.Remote) map[int64]int {
	out := map[int64]int{}
	for _, l := range links {
		seen := map[string]bool{}
		for _, r := range remotes {
			key := strings.ToLower(r.Host) + "|" + r.RepoSlug
			if delivery.LinkServes(l, r) && !seen[key] {
				seen[key] = true
				out[l.ID]++
			}
		}
	}
	return out
}

// DeliveryLandingWire shapes a landing with its commit identity.
func DeliveryLandingWire(l delivery.Landing, sha, subject string, committedAt time.Time, reachable bool) APIDeliveryLanding {
	sessions := l.SessionIDs
	if sessions == nil {
		sessions = []string{}
	}
	return APIDeliveryLanding{
		CommitID: l.CommitID, SHA: sha, Subject: subject, CommittedAt: FmtProjectTime(committedAt), Reachable: reachable,
		Status: string(l.Status), Kind: string(l.Kind), Confidence: string(l.Confidence), RuleID: l.RuleID,
		LandingSHA: l.LandingSHA, PRID: l.PRID, PRNumber: l.PRNumber, AbandonReason: string(l.AbandonReason),
		Source: string(l.Source), LandedAt: FmtProjectTime(l.LandedAt), LandedAtSource: l.LandedAtSource,
		FirstPushedAt: FmtProjectTime(l.FirstPushedAt), EvaluatedAt: FmtProjectTime(l.EvaluatedAt),
		SessionIDs: sessions,
	}
}

// DeliveryPRWire shapes a PR (without its commits).
func DeliveryPRWire(p delivery.PullRequest, stale bool) APIDeliveryPR {
	out := APIDeliveryPR{
		ID: p.ID, LinkID: p.LinkID, Provider: string(p.Provider), Host: p.Host, RepoSlug: p.RepoSlug,
		Number: p.Number, Title: p.Title, URL: safeHTTPURL(p.URL), State: string(p.State), Readiness: string(p.Readiness),
		Bucket: string(delivery.PRBucket(p.State, p.Readiness)),
		Facets: p.Facets, RawState: p.RawState, MergeMethod: string(p.MergeMethod),
		CreatedAt: FmtProjectTime(p.CreatedAt), MergedAt: FmtProjectTime(p.MergedAt), ClosedAt: FmtProjectTime(p.ClosedAt),
		UpdatedAt: FmtProjectTime(p.UpdatedAt), FetchedAt: FmtProjectTime(p.FetchedAt), Stale: stale,
		AICommits: []APIDeliveryLanding{}, Sessions: []string{},
	}
	if p.State == delivery.PRMerged && !p.CreatedAt.IsZero() && p.MergedAt.After(p.CreatedAt) {
		out.MergeSeconds = int64(p.MergedAt.Sub(p.CreatedAt) / time.Second)
	}
	return out
}

// safeHTTPURL passes only an https URL through, so a stored value can never
// become a javascript: link on the page.
func safeHTTPURL(u string) string {
	if strings.HasPrefix(strings.ToLower(u), "https://") {
		return u
	}
	return ""
}

// DeliverySummaryWire shapes delivery.Summary.
func DeliverySummaryWire(s delivery.Summary) APIDeliverySummary {
	by := map[string]int64{}
	for k, v := range s.ByStatus {
		by[string(k)] = v
	}
	blocked := map[string]int64{}
	for k, v := range s.BlockedBacklog {
		blocked[string(k)] = v
	}
	rate := func(r delivery.Rate) APIDeliveryRate {
		return APIDeliveryRate{Known: r.Known, Value: r.Value, Num: r.Num, Den: r.Den, Caveat: r.Caveat, UnknownReason: r.UnknownReason}
	}
	return APIDeliverySummary{
		AICommits: s.AICommits, ByStatus: by,
		LandedExact: s.LandedExact, LandedPatch: s.LandedPatch, LandedSquash: s.LandedSquash,
		AcceptedWorkRate: rate(s.AcceptedWorkRate), LandedShare: rate(s.LandedShare), PRMergeRate: rate(s.PRMergeRate),
		OpenMergeable:  APIDeliveryCount{Known: s.OpenMergeable.Known, Value: s.OpenMergeable.Value, UnknownReason: s.OpenMergeable.UnknownReason},
		BlockedBacklog: blocked, BlockedKnown: s.BlockedKnown,
		TimeToMerge: APIDeliveryMergeTime{
			Known: s.TimeToMerge.Known, P50Seconds: int64(s.TimeToMerge.P50 / time.Second), P75Seconds: int64(s.TimeToMerge.P75 / time.Second),
			Samples: s.TimeToMerge.Samples, Source: string(s.TimeToMerge.Source), Caveat: s.TimeToMerge.Caveat, UnknownReason: s.TimeToMerge.UnknownReason,
		},
		Funnel: APIDeliveryFunnel{
			Known: s.Funnel.Known, EditedPrompts: s.Funnel.EditedPrompts, Committed: s.Funnel.Committed,
			Pushed: s.Funnel.Pushed, InPR: s.Funnel.InPR, Landed: s.Funnel.Landed, Caveat: s.Funnel.Caveat,
		},
		FetchAge: s.FetchAge, StaleCaveat: s.StaleCaveat,
	}
}

// ProjectDeliveryInput is everything ComposeProjectDelivery reads, already
// loaded and windowed by the handler.
type ProjectDeliveryInput struct {
	ProjectID    int64
	Now          time.Time
	WindowDays   int
	LocalEnabled bool
	CountLikely  bool
	CanCheck     bool
	Remotes      []delivery.Remote
	Links        []delivery.ProviderLink
	Mirrors      []delivery.Mirror
	Settings     delivery.ProjectSettings
	// Landings are the window's evaluated AI-touched commits.
	Landings []delivery.Landing
	// Ownership is the window's ownership fold (commits, owners, prompts).
	Ownership store.CommitOwnershipResult
	PRs       []delivery.PullRequest
	PRCommits map[int64][]delivery.PRCommit
}

// commitInfo is one window commit's identity.
type commitInfo struct {
	sha, subject string
	at           time.Time
	reachable    bool
}

// ComposeProjectDelivery builds the Delivery tab from loaded rows: the
// remotes and source line, then the window's landings joined to their
// commits, owners and prompts, the PRs that hold them, and the metrics.
func ComposeProjectDelivery(in ProjectDeliveryInput) APIProjectDelivery {
	out := APIProjectDelivery{
		ProjectID: in.ProjectID, LocalEnabled: in.LocalEnabled, CountLikely: in.CountLikely, CanCheck: in.CanCheck,
		Remotes: []APIDeliveryRemote{}, Settings: DeliverySettingsWire(in.Settings),
		PullRequests: []APIDeliveryPR{}, NotInPR: []APIDeliveryLanding{}, WindowDays: in.WindowDays,
		Truncated: in.Ownership.Truncated(),
	}
	evidenceAt := composeDeliverySource(in, &out)
	j := newLandingJoin(in)
	out.PendingCommits = j.pending
	summaryPRs, inPR := composeDeliveryPRs(in, j, &out)
	for _, l := range in.Landings {
		if inPR[l.CommitID] {
			continue
		}
		out.NotInPRTotal++
		if len(out.NotInPR) < deliveryRowCap {
			out.NotInPR = append(out.NotInPR, j.row(l))
		}
	}
	sort.SliceStable(out.NotInPR, func(i, k int) bool { return out.NotInPR[i].CommittedAt > out.NotInPR[k].CommittedAt })
	out.Summary = DeliverySummaryWire(delivery.Summarise(delivery.SummaryInput{
		Landings: in.Landings, CommittedAt: j.committedAt, PRs: summaryPRs,
		ProviderConnected: out.ProviderLinked, Prompts: funnelPrompts(in.Ownership.Linkage), EvidenceAt: evidenceAt,
		CountLikely: in.CountLikely, Now: in.Now,
	}))
	return out
}

// composeDeliverySource fills Remotes, ProviderLinked, MirrorEligible,
// LinkProblem and Source, and returns the evidence time the metrics are
// judged against.
func composeDeliverySource(in ProjectDeliveryInput, out *APIProjectDelivery) time.Time {
	mirrorByKey := map[string]delivery.Mirror{}
	for _, m := range in.Mirrors {
		mirrorByKey[m.URLHash] = m
	}
	var (
		servingLink         *delivery.ProviderLink
		servingSlug         string
		lastFetch, mirrorAt time.Time
	)
	for _, r := range in.Remotes {
		ar := APIDeliveryRemote{
			Name: r.Name, URL: r.URL, Host: r.Host, Provider: string(r.Provider), RepoSlug: r.RepoSlug,
			DefaultBranch: r.DefaultBranch, FetchHeadAt: FmtProjectTime(r.FetchHeadAt), Source: string(delivery.SourceUserRefs),
		}
		if r.FetchHeadAt.After(lastFetch) {
			lastFetch = r.FetchHeadAt
		}
		l, served := servingLinkFor(in.Links, r)
		if served {
			ar.Source, ar.LinkID, ar.LinkStatus = string(delivery.SourceProvider), l.ID, nonEmpty(l.Status, "never_checked")
			if servingLink == nil {
				servingLink, servingSlug = &l, r.RepoSlug
			}
		} else {
			out.MirrorEligible = true
		}
		if m, ok := mirrorByKey[delivery.MirrorKey(r.URL)]; ok && r.URL != "" {
			mw := DeliveryMirrorWire(m)
			ar.Mirror = &mw
			if !served && in.Settings.MirrorEnabled && m.LastRefreshAt.After(mirrorAt) {
				ar.Source, mirrorAt = string(delivery.SourceMirror), m.LastRefreshAt
			}
		}
		out.Remotes = append(out.Remotes, ar)
	}
	out.ProviderLinked = servingLink != nil
	src := APIDeliverySource{
		Kind: string(delivery.SourceUserRefs), LastFetchAt: FmtProjectTime(lastFetch),
		MirrorRefreshAt: FmtProjectTime(mirrorAt), DefaultBranch: defaultBranchOf(in.Remotes),
	}
	evidenceAt := lastFetch
	if mirrorAt.After(lastFetch) {
		evidenceAt, src.Kind = mirrorAt, string(delivery.SourceMirror)
	}
	switch {
	case len(in.Remotes) == 0:
		src.Kind = "none"
	case servingLink != nil:
		src.Kind = string(delivery.SourceProvider)
		src.Provider, src.AuthMode, src.AccountLogin = string(servingLink.Provider), servingLink.AuthMode, servingLink.AccountLogin
		src.RepoSlug, src.SyncedAt = servingSlug, FmtProjectTime(servingLink.LastOKAt)
		if !deliveryLinkHealthy(servingLink.Status) {
			out.LinkProblem = &APIDeliveryLinkProblem{
				LinkID: servingLink.ID, Status: servingLink.Status, Message: servingLink.LastError,
				LastOKAt: FmtProjectTime(servingLink.LastOKAt), NextRunAt: FmtProjectTime(servingLink.NextRunAt),
			}
		}
	}
	src.EvidenceAt = FmtProjectTime(evidenceAt)
	out.Source = src
	return evidenceAt
}

// servingLinkFor returns the first link that serves r.
func servingLinkFor(links []delivery.ProviderLink, r delivery.Remote) (delivery.ProviderLink, bool) {
	for _, l := range links {
		if delivery.LinkServes(l, r) {
			return l, true
		}
	}
	return delivery.ProviderLink{}, false
}

// defaultBranchOf names what "landed" means: origin's or upstream's default
// branch when known, else the first remote's.
func defaultBranchOf(remotes []delivery.Remote) string {
	out := ""
	for _, r := range remotes {
		if r.DefaultBranch != "" && (out == "" || r.Name == "origin" || r.Name == "upstream") {
			out = r.DefaultBranch
		}
	}
	return out
}

// landingJoin joins the window's landings to their commits, owners and
// prompts.
type landingJoin struct {
	in          ProjectDeliveryInput
	commits     map[int64]commitInfo
	shaToID     map[string]int64
	prompts     map[int64]projectroi.Prompt
	landed      map[int64]delivery.Landing
	committedAt map[int64]time.Time
	pending     int
}

func newLandingJoin(in ProjectDeliveryInput) *landingJoin {
	j := &landingJoin{
		in: in, commits: map[int64]commitInfo{}, shaToID: map[string]int64{}, prompts: map[int64]projectroi.Prompt{},
		landed: map[int64]delivery.Landing{}, committedAt: map[int64]time.Time{},
	}
	for _, c := range in.Ownership.Commits {
		j.commits[c.ID] = commitInfo{sha: c.SHA, subject: c.Subject, at: c.CommittedAt, reachable: c.Reachable}
		j.shaToID[c.SHA] = c.ID
	}
	for _, ch := range in.Ownership.Linkage.Chains {
		j.prompts[ch.Prompt.ActionID] = ch.Prompt
	}
	for _, l := range in.Landings {
		j.landed[l.CommitID] = l
		if ci, ok := j.commits[l.CommitID]; ok {
			j.committedAt[l.CommitID] = ci.at
		}
	}
	for id, own := range in.Ownership.Ownership {
		if _, ok := j.landed[id]; !ok && own.OwnerSessionID != "" {
			j.pending++
		}
	}
	return j
}

// row shapes one landing with its commit, owner and prompt.
func (j *landingJoin) row(l delivery.Landing) APIDeliveryLanding {
	ci := j.commits[l.CommitID]
	row := DeliveryLandingWire(l, ci.sha, ci.subject, ci.at, ci.reachable)
	own := j.in.Ownership.Ownership[l.CommitID]
	row.OwnerSessionID = own.OwnerSessionID
	row.Prompt = pickPrompt(j.in.Ownership.Linkage.ByCommit[l.CommitID], j.prompts, own.OwnerSessionID)
	return row
}

// members are the window's evaluated AI commits a PR holds: by its commit
// list, or because a landing names it.
func (j *landingJoin) members(p delivery.PullRequest) map[int64]bool {
	out := map[int64]bool{}
	for _, pc := range j.in.PRCommits[p.ID] {
		if id, ok := j.shaToID[pc.SHA]; ok {
			if _, ev := j.landed[id]; ev {
				out[id] = true
			}
		}
	}
	for _, l := range j.in.Landings {
		if l.PRID == p.ID {
			out[l.CommitID] = true
		}
	}
	return out
}

// composeDeliveryPRs fills the PR table (PRs holding a window AI commit,
// open work first) and returns those PRs for the metrics plus the commits
// they hold.
func composeDeliveryPRs(in ProjectDeliveryInput, j *landingJoin, out *APIProjectDelivery) ([]delivery.PullRequest, map[int64]bool) {
	linkStatus := map[int64]string{}
	for _, l := range in.Links {
		linkStatus[l.ID] = l.Status
	}
	inPR := map[int64]bool{}
	var summaryPRs []delivery.PullRequest
	for _, p := range in.PRs {
		members := j.members(p)
		if len(members) == 0 {
			continue
		}
		summaryPRs = append(summaryPRs, p)
		st, known := linkStatus[p.LinkID]
		w := DeliveryPRWire(p, !known || !deliveryLinkHealthy(st))
		sessions := map[string]bool{}
		for _, id := range sortedIDs(members) {
			inPR[id] = true
			row := j.row(j.landed[id])
			w.AICommits = append(w.AICommits, row)
			for _, s := range append(append([]string{}, row.SessionIDs...), row.OwnerSessionID) {
				if s != "" {
					sessions[s] = true
				}
			}
		}
		w.Sessions = sortedKeys(sessions)
		out.PullRequests = append(out.PullRequests, w)
	}
	sort.SliceStable(out.PullRequests, func(i, k int) bool {
		a, b := out.PullRequests[i], out.PullRequests[k]
		if prOpenRank(a.State) != prOpenRank(b.State) {
			return prOpenRank(a.State) < prOpenRank(b.State)
		}
		return a.Number > b.Number
	})
	if len(out.PullRequests) > deliveryPRCap {
		out.PullRequests = out.PullRequests[:deliveryPRCap]
		out.Truncated = true
	}
	return summaryPRs, inPR
}

// funnelPrompts turns the link chains into the funnel's prompt units: every
// prompt with AI edits and the commits that carried its files.
func funnelPrompts(linkage projectroi.Linkage) []delivery.PromptDelivery {
	out := []delivery.PromptDelivery{}
	for _, ch := range linkage.Chains {
		if ch.Status == projectroi.StatusNoEdits {
			continue
		}
		pd := delivery.PromptDelivery{CommitIDs: []int64{}}
		for _, c := range ch.Commits {
			pd.CommitIDs = append(pd.CommitIDs, c.ID)
		}
		out = append(out, pd)
	}
	return out
}

// prOpenRank orders the PR table: open work first, then merged, then closed.
func prOpenRank(state string) int {
	switch delivery.PRState(state) {
	case delivery.PROpen:
		return 0
	case delivery.PRDraft:
		return 1
	case delivery.PRMerged:
		return 2
	}
	return 3
}

// pickPrompt chooses the prompt shown on a landing row: the owner session's
// first prompt when it has one, else the first linked prompt.
func pickPrompt(actionIDs []int64, prompts map[int64]projectroi.Prompt, owner string) *APIDeliveryPrompt {
	var first *APIDeliveryPrompt
	for _, id := range actionIDs {
		p, ok := prompts[id]
		if !ok {
			continue
		}
		ref := &APIDeliveryPrompt{ActionID: p.ActionID, SessionID: p.SessionID, Preview: p.Preview}
		if owner != "" && p.SessionID == owner {
			return ref
		}
		if first == nil {
			first = ref
		}
	}
	return first
}

// ComposeSessionDelivery shapes the session card's rows.
func ComposeSessionDelivery(sessionID string, projectID int64, localEnabled bool, remotes []delivery.Remote, links []delivery.ProviderLink, rows []store.SessionLanding) APISessionDelivery {
	out := APISessionDelivery{SessionID: sessionID, ProjectID: projectID, LocalEnabled: localEnabled, Rows: []APISessionDeliveryRow{}}
	var lastFetch time.Time
	for _, r := range remotes {
		if r.FetchHeadAt.After(lastFetch) {
			lastFetch = r.FetchHeadAt
		}
		if out.DefaultBranch == "" || r.Name == "origin" || r.Name == "upstream" {
			if r.DefaultBranch != "" {
				out.DefaultBranch = r.DefaultBranch
			}
		}
		for _, l := range links {
			if delivery.LinkServes(l, r) {
				out.ProviderLinked = true
			}
		}
	}
	out.LastFetchAt = FmtProjectTime(lastFetch)
	linkStatus := map[int64]string{}
	for _, l := range links {
		linkStatus[l.ID] = l.Status
	}
	for _, sl := range rows {
		row := APISessionDeliveryRow{
			CommitID: sl.CommitID, SHA: sl.SHA, Subject: sl.Subject, CommittedAt: FmtProjectTime(sl.CommittedAt),
			Reachable: sl.Reachable, Owner: sl.Owner, Evaluated: sl.Evaluated,
		}
		if sl.Evaluated {
			l := DeliveryLandingWire(sl.Landing, sl.SHA, sl.Subject, sl.CommittedAt, sl.Reachable)
			row.Landing = &l
		}
		if sl.PR != nil {
			st, known := linkStatus[sl.PR.LinkID]
			p := DeliveryPRWire(*sl.PR, !known || !deliveryLinkHealthy(st))
			row.PR = &p
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func sortedIDs(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
