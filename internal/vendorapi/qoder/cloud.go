package qoder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Qoder Cloud Agents managed API surfaces (lane CA-V2, cloud agents arc;
// grounding docs/plans/cloud-agents/grounding/wave-c-vendors-2026-11-01.md
// section 2). They are consumed by the node connector qoder-cloud with the
// developer's own personal access token through the node's egress package,
// not by the org runner. Every request is a GET under /api/v1/cloud on
// api.qoder.com (or api.qoder.com.cn for the China region; the host is the
// connector's choice, never the driver's).
//
// Written from the official Python SDK qca-sdk
// (github.com/QoderAI/qoder-cloud-agents-sdk-python at commit
// 54e7a3140c51d76fd3143e993c5dfbf550bac082, 2026-10-29), which says it aligns
// with the official API documentation retrieved on 2026-10-27. A live check
// on 2026-11-02 (a free account, region global) confirmed the list, the
// environment read and the events shapes; the members it showed beyond the
// SDK's are ignored by the closed DTOs.
const (
	SurfaceCloudSessions    vs.SurfaceID = "qoder.ca.sessions"
	SurfaceCloudSession     vs.SurfaceID = "qoder.ca.session_retrieve"
	SurfaceCloudEnvironment vs.SurfaceID = "qoder.ca.environment_retrieve"

	CloudSessionsContract    = "qoder.ca.sessions/v1 qca-sdk 54e7a314 (2026-10-29)"
	CloudSessionContract     = "qoder.ca.session_retrieve/v1 qca-sdk 54e7a314 (2026-10-29)"
	CloudEnvironmentContract = "qoder.ca.environment_retrieve/v1 qca-sdk 54e7a314 (2026-10-29)"

	// CloudPathPrefix is the managed API's path prefix (the SDK's default
	// base URL https://api.qoder.com/api/v1/cloud/).
	CloudPathPrefix = "/api/v1/cloud"

	// CloudTool is the registry tool a Cloud Agents session lands under: the
	// same tool as the local qodercli transcripts (where it ran is
	// execution_location, CA-D1, never a new tool id).
	CloudTool = "qoder"

	// CloudSessionClass is the snapshot class of one Cloud Agents session;
	// its subject is the session id (kept as sessions.id, CA-D2).
	CloudSessionClass = "qoder.cloud_session"
	// CloudEnvironmentClass is the snapshot class of one environment; its
	// subject is the environment id and its body carries the config type
	// ("cloud" or "self_hosted").
	CloudEnvironmentClass = "qoder.cloud_environment"

	// CloudSessionUsageNamespace and CloudSessionUsageJoinKind key a
	// session's cumulative token row: one row per session, re-landed with a
	// higher revision (updated_at) as the session grows.
	CloudSessionUsageNamespace = "qoder.cloud_session"
	CloudSessionUsageJoinKind  = "session_id"
	// CloudSessionCreditsNamespace keys a session's cumulative credit row:
	// usage.total_credits, charged in qoder_credit, one row per session read
	// (the session's running total, model plus sandbox runtime credits).
	CloudSessionCreditsNamespace = "qoder.cloud_session.credits" //nolint:gosec // G101: a usage join namespace name, never a credential.
	// FlagModelCreditsMicros and FlagSandboxCreditsMicros carry the split of
	// a credit row's total (usage.model_credits and
	// usage.sandbox_runtime_credits, micro-credits) when the session reports
	// it. They are a breakdown already inside the total, never an addend.
	FlagModelCreditsMicros   = "model_credits_micros"
	FlagSandboxCreditsMicros = "sandbox_runtime_credits_micros"

	// CloudIdentityCaller names the row owner: a personal access token reads
	// its own sessions and the Session schema names no creator.
	CloudIdentityCaller      = "caller"
	CloudIdentityCallerValue = "self"

	// UnitCloudCredit is the Cloud Agents credit (never money, never summed
	// with tokens or USD, CA-D11).
	UnitCloudCredit = "qoder_credit"

	// ParamSessionID names the session a retrieve or events request reads.
	ParamSessionID = "session_id"
	// ParamEnvironmentID names the environment a retrieve request reads.
	ParamEnvironmentID = "environment_id"

	// CloudPageSize is the documented maximum page size (limit <= 100).
	CloudPageSize = 100
)

var (
	// cloudIDRE bounds a session, environment, agent or event id before it
	// enters a path or a landing (the SDK's ids are sess_..., env_...,
	// agent_..., evt_...).
	cloudIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	// cloudPageRE bounds an opaque next_page token before it is sent back.
	cloudPageRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:~-]{1,512}$`)
	// cloudTokenRE bounds a short vendor enum value (status, config type,
	// resource type, stop reason).
	cloudTokenRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// CloudSessions returns the driver of qoder.ca.sessions.
//
// Contract (qca-sdk Managed sessions.list, "GET /sessions"): query limit
// (at most 100), order (asc|desc), page (the previous next_page),
// created_at[gt|gte|lt|lte], statuses[], include_archived, agent_id,
// deployment_id; response {data: [Session], has_more, next_page, first_id,
// last_id} (BasePage, page style BidirectionalPageCursor). The list filters
// only on creation time, so the window, when one is passed, is a
// created_at[gte] / created_at[lt] window. Each session lands as one snapshot
// of class qoder.cloud_session (status, timestamps, environment, agent and
// model ids, the first repository resource, the cumulative credits and
// seconds), when usage reports a token count one usage row in tokens keyed by
// the session id with updated_at as its revision, and when usage reports
// total_credits one cumulative credit row (namespace
// qoder.cloud_session.credits, unit qoder_credit) with the model and sandbox
// runtime split as flags. The session's total is the one credit figure the
// connector lands (CA-D11, CA-D12): the events' per-request and session.usage
// credits repeat it. environment_variables, metadata, title, the agent's
// system prompt, name and description, tools, MCP servers, skills, vault ids
// and every resource credential are never decoded.
func CloudSessions() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudSessions,
		Build:           buildCloudSessions,
		ParseResponse:   parseCloudSessions,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: CloudSessionsContract,
		Tool:            CloudTool,
		KnownPaths:      cloudSessionsKnownPaths,
	}
}

// CloudSession returns the driver of qoder.ca.session_retrieve.
//
// Contract (qca-sdk Managed sessions.retrieve, "GET /sessions/{session_id}"):
// one Session. It lands exactly what one list item lands.
func CloudSession() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudSession,
		Build:           buildCloudSession,
		ParseResponse:   parseCloudSession,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: CloudSessionContract,
		Tool:            CloudTool,
		KnownPaths:      cloudSessionKnownPaths,
	}
}

// CloudEnvironment returns the driver of qoder.ca.environment_retrieve.
//
// Contract (qca-sdk Managed environments.retrieve, "GET
// /environments/{environment_id}"): one Environment {id, name, config {type,
// setup_script, networking, packages, storage}, created_at, updated_at,
// archived_at, scope, metadata}. Only the id, config.type, scope and the
// archive time land (snapshot qoder.cloud_environment); the setup script,
// networking policy, packages, name, description and metadata are never
// decoded.
func CloudEnvironment() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudEnvironment,
		Build:           buildCloudEnvironment,
		ParseResponse:   parseCloudEnvironment,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: CloudEnvironmentContract,
		Tool:            CloudTool,
		KnownPaths:      cloudEnvironmentKnownPaths,
	}
}

// cloudWindow adds a half-open [From, To) created_at filter. A zero window
// adds nothing (a full listing); a half or inverted window is refused.
func cloudWindow(surface vs.SurfaceID, q map[string][]string, w vendorapi.Window) error {
	switch {
	case w.From.IsZero() && w.To.IsZero():
		return nil
	case w.From.IsZero() || !w.To.After(w.From):
		return fmt.Errorf("%s: a window needs both bounds, From before To", surface)
	}
	q["created_at[gte]"] = []string{w.From.UTC().Format(time.RFC3339)}
	q["created_at[lt]"] = []string{w.To.UTC().Format(time.RFC3339)}
	return nil
}

// cloudPageQuery adds the page size, the order and a validated page token.
func cloudPageQuery(surface vs.SurfaceID, q map[string][]string, order, cursor string) error {
	q["limit"] = []string{strconv.Itoa(CloudPageSize)}
	q["order"] = []string{order}
	if cursor == "" {
		return nil
	}
	if !cloudPageRE.MatchString(cursor) {
		return fmt.Errorf("%s: cursor is not an opaque next_page token", surface)
	}
	q["page"] = []string{cursor}
	return nil
}

func buildCloudSessions(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{}
	if err := cloudWindow(SurfaceCloudSessions, q, w); err != nil {
		return vendorapi.Request{}, err
	}
	// Newest created first (the list has no updated-at order).
	if err := cloudPageQuery(SurfaceCloudSessions, q, "desc", cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: CloudPathPrefix + "/sessions", Query: q}, nil
}

// cloudIDPath validates one id parameter and returns it path-escaped.
func cloudIDPath(surface vs.SurfaceID, p vendorapi.Params, name string) (string, error) {
	id := p[name]
	if !cloudIDRE.MatchString(id) {
		return "", fmt.Errorf("%s: parameter %s must be a Qoder id", surface, name)
	}
	return url.PathEscape(id), nil
}

func buildCloudSession(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	id, err := cloudIDPath(SurfaceCloudSession, p, ParamSessionID)
	if err != nil {
		return vendorapi.Request{}, err
	}
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: a single session has no page", SurfaceCloudSession)
	}
	return vendorapi.Request{Method: "GET", Path: CloudPathPrefix + "/sessions/" + id}, nil
}

func buildCloudEnvironment(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	id, err := cloudIDPath(SurfaceCloudEnvironment, p, ParamEnvironmentID)
	if err != nil {
		return vendorapi.Request{}, err
	}
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: a single environment has no page", SurfaceCloudEnvironment)
	}
	return vendorapi.Request{Method: "GET", Path: CloudPathPrefix + "/environments/" + id}, nil
}

// cloudPage is the SDK's BasePage envelope.
type cloudPage[T any] struct {
	Data     *[]T    `json:"data"`
	HasMore  *bool   `json:"has_more"`
	NextPage *string `json:"next_page"`
}

func cloudDecode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// cloudEnvelope checks one list page's paging contract and returns its next
// cursor ("" on the last page: has_more false, or next_page null or empty).
func cloudEnvelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *cloudPage[T]) (string, error) {
	d := driftOf(surface)
	if r.Status != 200 {
		return "", d("status %d is not the documented 200", r.Status)
	}
	if err := cloudDecode(r.Body, doc); err != nil {
		return "", d("body does not decode as the documented page")
	}
	if doc.Data == nil {
		return "", d("required field data is missing")
	}
	if (doc.HasMore != nil && !*doc.HasMore) || doc.NextPage == nil || *doc.NextPage == "" {
		return "", nil
	}
	if !cloudPageRE.MatchString(*doc.NextPage) {
		return "", d("next_page is not an opaque page token")
	}
	if *doc.NextPage == r.Cursor {
		return "", d("next_page repeats the page the request asked for")
	}
	return *doc.NextPage, nil
}

// cloudTime reads an ISO 8601 timestamp into UTC seconds.
func cloudTime(s *string) (time.Time, bool) {
	if s == nil || *s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC().Truncate(time.Second), true
}

// cloudModel is the session agent's model: a bare id string or a ModelConfig
// object {id, effort, ...}; only the id is read.
type cloudModel struct{ id string }

func (m *cloudModel) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		return json.Unmarshal(b, &m.id)
	}
	var o struct {
		ID *string `json:"id"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	m.id = str(o.ID)
	return nil
}

// cloudSession is the closed DTO of one Session. The members that can carry
// content or a secret (environment_variables, metadata, title, the agent's
// system prompt, name, description, tools, MCP servers and skills, vault ids,
// outcome evaluations, a resource's instructions, password or mount path) are
// deliberately absent.
type cloudSession struct {
	ID            *string `json:"id"`
	Status        *string `json:"status"`
	Type          *string `json:"type"`
	CreatedAt     *string `json:"created_at"`
	UpdatedAt     *string `json:"updated_at"`
	ArchivedAt    *string `json:"archived_at"`
	EnvironmentID *string `json:"environment_id"`
	DeploymentID  *string `json:"deployment_id"`
	Agent         *struct {
		ID      *string     `json:"id"`
		Version *count      `json:"version"`
		Model   *cloudModel `json:"model"`
	} `json:"agent"`
	Resources *[]struct {
		Type     *string `json:"type"`
		URL      *string `json:"url"`
		Checkout *struct {
			Type *string `json:"type"`
			Name *string `json:"name"`
		} `json:"checkout"`
	} `json:"resources"`
	Stats *struct {
		ActiveSeconds   *count `json:"active_seconds"`
		DurationSeconds *count `json:"duration_seconds"`
	} `json:"stats"`
	Usage *cloudUsage `json:"usage"`
}

// cloudUsage is a Session's usage block.
type cloudUsage struct {
	InputTokens          *count `json:"input_tokens"`
	OutputTokens         *count `json:"output_tokens"`
	CacheReadInputTokens *count `json:"cache_read_input_tokens"`
	CacheCreation        *struct {
		Ephemeral5m *count `json:"ephemeral_5m_input_tokens"`
		Ephemeral1h *count `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	ModelCredits          *count `json:"model_credits"`
	SandboxRuntimeCredits *count `json:"sandbox_runtime_credits"`
	TotalCredits          *count `json:"total_credits"`
	ActiveSeconds         *count `json:"active_seconds"`
}

// repoResourceTypes are the session resource types that name a repository.
var repoResourceTypes = map[string]bool{"github_repository": true, "git_repository": true}

// cloudRepoURL returns a repository URL fit to keep: https, a host, no user
// information (a git_repository resource may carry one) and no query or
// fragment; "" otherwise.
func cloudRepoURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		len(raw) > vendorapi.MaxAttrValue {
		return ""
	}
	return raw
}

// tokens reads a non-negative whole token count.
func tokens(n *count) (int64, bool) {
	s, ok := wholeCount(n)
	if !ok {
		return 0, false
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v, true
}

// seconds reads a non-negative decimal number of seconds, rendered exactly.
func seconds(n *count) (string, bool) { return credits(n) }

// landCloudSession turns one Session into its snapshot and, when usage
// reports them, its token row and its cumulative credit row. i names the
// record in drift messages.
func landCloudSession(surface vs.SurfaceID, s cloudSession, i int, page *vendorapi.Page) error {
	d := driftOf(surface)
	id := str(s.ID)
	if !cloudIDRE.MatchString(id) {
		return d("session %d: id is missing or not an id", i)
	}
	status := str(s.Status)
	if !cloudTokenRE.MatchString(status) {
		return d("session %d: status is missing or not a token", i)
	}
	body := map[string]string{"status": status}
	at, err := cloudSessionTimes(d, s, i, body)
	if err != nil {
		return err
	}
	if err := cloudSessionRefs(d, s, i, body); err != nil {
		return err
	}
	cloudSessionRepos(s, body)
	if err := cloudSessionStats(d, s, i, body); err != nil {
		return err
	}
	page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: CloudSessionClass, Subject: id, Body: body})
	if s.Usage == nil {
		return nil
	}
	return landCloudUsage(d, s.Usage, i, id, at, body, page)
}

// cloudSessionTimes validates a session's created_at, updated_at and
// archived_at into body and returns the row time: updated_at when present,
// else created_at.
func cloudSessionTimes(d func(string, ...any) error, s cloudSession, i int, body map[string]string) (time.Time, error) {
	created, ok := cloudTime(s.CreatedAt)
	if !ok {
		return time.Time{}, d("session %d: created_at is not an ISO timestamp", i)
	}
	at := created
	body["created_at"] = created.Format(time.RFC3339)
	if s.UpdatedAt != nil {
		u, ok := cloudTime(s.UpdatedAt)
		if !ok {
			return time.Time{}, d("session %d: updated_at is not an ISO timestamp", i)
		}
		at = u
		body["updated_at"] = u.Format(time.RFC3339)
	}
	if s.ArchivedAt != nil {
		a, ok := cloudTime(s.ArchivedAt)
		if !ok {
			return time.Time{}, d("session %d: archived_at is not an ISO timestamp", i)
		}
		body["archived_at"] = a.Format(time.RFC3339)
	}
	return at, nil
}

// cloudSessionRefs lands a session's environment and deployment ids (a
// present one must be an id), its type and its agent id and model (kept
// only when well formed).
func cloudSessionRefs(d func(string, ...any) error, s cloudSession, i int, body map[string]string) error {
	for _, f := range []struct {
		key string
		v   *string
	}{{"environment_id", s.EnvironmentID}, {"deployment_id", s.DeploymentID}} {
		if v := str(f.v); v != "" {
			if !cloudIDRE.MatchString(v) {
				return d("session %d: %s is not an id", i, f.key)
			}
			body[f.key] = v
		}
	}
	if v := str(s.Type); v != "" && cloudTokenRE.MatchString(v) {
		body["type"] = v
	}
	if s.Agent != nil {
		if v := str(s.Agent.ID); v != "" && cloudIDRE.MatchString(v) {
			body["agent_id"] = v
		}
		if s.Agent.Model != nil && s.Agent.Model.id != "" && len(s.Agent.Model.id) <= 128 {
			body["model"] = s.Agent.Model.id
		}
	}
	return nil
}

// cloudSessionRepos lands the repository count and, from the first
// repository resource, its URL, type and checked-out branch.
func cloudSessionRepos(s cloudSession, body map[string]string) {
	if s.Resources == nil {
		return
	}
	repos := 0
	for _, r := range *s.Resources {
		if !repoResourceTypes[str(r.Type)] {
			continue
		}
		repos++
		if repos > 1 {
			continue
		}
		if u := cloudRepoURL(str(r.URL)); u != "" {
			body["repo_url"] = u
			body["repo_type"] = str(r.Type)
		}
		if r.Checkout != nil && str(r.Checkout.Type) == "branch" {
			if b := str(r.Checkout.Name); b != "" && len(b) <= 255 {
				body["repo_branch"] = b
			}
		}
	}
	body["repository_count"] = strconv.Itoa(repos)
}

// cloudSessionStats lands a session's active and duration seconds.
func cloudSessionStats(d func(string, ...any) error, s cloudSession, i int, body map[string]string) error {
	if s.Stats == nil {
		return nil
	}
	for _, f := range []struct {
		key string
		v   *count
	}{{"active_seconds", s.Stats.ActiveSeconds}, {"duration_seconds", s.Stats.DurationSeconds}} {
		if f.v == nil {
			continue
		}
		v, ok := seconds(f.v)
		if !ok {
			return d("session %d: stats.%s is not a non-negative number", i, f.key)
		}
		body[f.key] = v
	}
	return nil
}

// landCloudUsage validates a session's credit amounts into its snapshot
// body, then lands its token row (when any count is reported) and its
// cumulative credit row.
func landCloudUsage(d func(string, ...any) error, u *cloudUsage, i int, id string, at time.Time, body map[string]string, page *vendorapi.Page) error {
	for _, f := range []struct {
		key string
		v   *count
	}{{"model_credits", u.ModelCredits}, {"sandbox_runtime_credits", u.SandboxRuntimeCredits}, {"total_credits", u.TotalCredits}} {
		if f.v == nil {
			continue
		}
		v, ok := credits(f.v)
		if !ok {
			return d("session %d: usage.%s is not a non-negative amount", i, f.key)
		}
		body[f.key] = v
	}
	row := vendorapi.UsageRow{
		JoinKind: CloudSessionUsageJoinKind, JoinNamespace: CloudSessionUsageNamespace, JoinValue: id,
		IdentityKind: CloudIdentityCaller, Identity: CloudIdentityCallerValue,
		At: at, SessionRef: id, Model: body["model"], Revision: at.Unix(),
	}
	any := false
	for _, f := range []struct {
		name string
		v    *count
		dst  *int64
	}{
		{"input_tokens", u.InputTokens, &row.InputTokens},
		{"output_tokens", u.OutputTokens, &row.OutputTokens},
		{"cache_read_input_tokens", u.CacheReadInputTokens, &row.CacheReadTokens},
	} {
		if f.v == nil {
			continue
		}
		n, ok := tokens(f.v)
		if !ok {
			return d("session %d: usage.%s is not a whole count", i, f.name)
		}
		*f.dst, any = n, true
	}
	if cc := u.CacheCreation; cc != nil {
		for _, v := range []*count{cc.Ephemeral5m, cc.Ephemeral1h} {
			if v == nil {
				continue
			}
			n, ok := tokens(v)
			if !ok {
				return d("session %d: usage.cache_creation is not a whole count", i)
			}
			row.CacheWriteTokens += n
			any = true
		}
	}
	if any {
		page.Usage = append(page.Usage, row)
	}
	landCloudCredits(u.TotalCredits, u.ModelCredits, u.SandboxRuntimeCredits, id, at, page)
	return nil
}

// landCloudCredits lands a session's usage.total_credits as one cumulative
// credit row (the amounts were validated with the snapshot body). A session
// whose usage reports no total lands none (absent, never zero).
func landCloudCredits(total, model, sandbox *count, id string, at time.Time, page *vendorapi.Page) {
	micros := func(n *count) int64 {
		v, _ := vendorapi.DecimalMicros(string(*n), 0)
		return v
	}
	if total == nil {
		return
	}
	row := vendorapi.UsageRow{
		JoinKind: CloudSessionUsageJoinKind, JoinNamespace: CloudSessionCreditsNamespace, JoinValue: id,
		IdentityKind: CloudIdentityCaller, Identity: CloudIdentityCallerValue,
		At: at, SessionRef: id, Revision: at.Unix(), ChargedUnit: UnitCloudCredit, ChargedMicros: micros(total),
		Flags: map[string]string{},
	}
	if model != nil {
		row.Flags[FlagModelCreditsMicros] = strconv.FormatInt(micros(model), 10)
	}
	if sandbox != nil {
		row.Flags[FlagSandboxCreditsMicros] = strconv.FormatInt(micros(sandbox), 10)
	}
	page.Usage = append(page.Usage, row)
}

func parseCloudSessions(r vendorapi.Response) (vendorapi.Page, error) {
	var doc cloudPage[cloudSession]
	next, err := cloudEnvelope(SurfaceCloudSessions, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, s := range *doc.Data {
		if seen[str(s.ID)] {
			return vendorapi.Page{}, driftOf(SurfaceCloudSessions)("data[%d] repeats a session", i)
		}
		seen[str(s.ID)] = true
		if err := landCloudSession(SurfaceCloudSessions, s, i, &page); err != nil {
			return vendorapi.Page{}, err
		}
	}
	return page, nil
}

func parseCloudSession(r vendorapi.Response) (vendorapi.Page, error) {
	d := driftOf(SurfaceCloudSession)
	if r.Status != 200 {
		return vendorapi.Page{}, d("status %d is not the documented 200", r.Status)
	}
	var s cloudSession
	if err := cloudDecode(r.Body, &s); err != nil {
		return vendorapi.Page{}, d("body does not decode as the documented Session")
	}
	if want := r.Params[ParamSessionID]; want != "" && str(s.ID) != want {
		return vendorapi.Page{}, d("the response is not the session the request asked for")
	}
	page := vendorapi.Page{SourceRecords: 1}
	if err := landCloudSession(SurfaceCloudSession, s, 0, &page); err != nil {
		return vendorapi.Page{}, err
	}
	return page, nil
}

// cloudEnvironmentDoc is the closed DTO of one Environment.
type cloudEnvironmentDoc struct {
	ID         *string `json:"id"`
	Scope      *string `json:"scope"`
	ArchivedAt *string `json:"archived_at"`
	Config     *struct {
		Type *string `json:"type"`
	} `json:"config"`
}

func parseCloudEnvironment(r vendorapi.Response) (vendorapi.Page, error) {
	d := driftOf(SurfaceCloudEnvironment)
	if r.Status != 200 {
		return vendorapi.Page{}, d("status %d is not the documented 200", r.Status)
	}
	var e cloudEnvironmentDoc
	if err := cloudDecode(r.Body, &e); err != nil {
		return vendorapi.Page{}, d("body does not decode as the documented Environment")
	}
	id := str(e.ID)
	if !cloudIDRE.MatchString(id) {
		return vendorapi.Page{}, d("id is missing or not an id")
	}
	if want := r.Params[ParamEnvironmentID]; want != "" && id != want {
		return vendorapi.Page{}, d("the response is not the environment the request asked for")
	}
	body := map[string]string{}
	if e.Config != nil {
		if v := str(e.Config.Type); v != "" {
			if !cloudTokenRE.MatchString(v) {
				return vendorapi.Page{}, d("config.type is not a token")
			}
			body["config_type"] = v
		}
	}
	if v := str(e.Scope); v != "" && cloudTokenRE.MatchString(v) {
		body["scope"] = v
	}
	if e.ArchivedAt != nil {
		if a, ok := cloudTime(e.ArchivedAt); ok {
			body["archived_at"] = a.Format(time.RFC3339)
		}
	}
	return vendorapi.Page{Snapshots: []vendorapi.VendorSnapshot{{Class: CloudEnvironmentClass, Subject: id, Body: body}}}, nil
}

// cloudSessionFields are the Session members the corpus field ledger
// documents, relative to one Session (the members never decoded included:
// a driver knows a path it deliberately skips).
var cloudSessionFields = []string{
	"agent", "agent.id", "agent.model", "agent.model.effort", "agent.model.id", "agent.system", "agent.type",
	"agent.version", "archived_at", "created_at", "environment_id", "environment_variables", "id", "metadata",
	"resources", "resources[]", "resources[].checkout", "resources[].checkout.name", "resources[].checkout.type",
	"resources[].id", "resources[].mount_path", "resources[].type", "resources[].url",
	"stats", "stats.active_seconds", "stats.duration_seconds", "status", "title", "type", "updated_at",
	"usage", "usage.cache_creation", "usage.cache_creation.ephemeral_1h_input_tokens",
	"usage.cache_creation.ephemeral_5m_input_tokens", "usage.cache_read_input_tokens", "usage.input_tokens",
	"usage.model_credits", "usage.output_tokens", "usage.sandbox_runtime_credits", "usage.total_credits",
}

// cloudSessionLiveFields are the Session members the live check of
// 2026-11-02 showed beyond the SDK's types (the list fixture carries them;
// the closed DTO decodes none of them). The retrieve fixture stays on the
// SDK's members: a single document with an array member would read as a
// page to the mock.
var cloudSessionLiveFields = []string{
	"agent.description", "agent.mcp_servers", "agent.model.context_window", "agent.model.effective_context_window",
	"agent.multiagent", "agent.name", "agent.skills", "agent.tools", "agent.tools[]", "agent.tools[].enabled_tools",
	"agent.tools[].type", "deployment_id", "outcome_evaluations", "resources[].created_at", "resources[].updated_at",
	"vault_ids",
}

func prefixed(prefix string, fields []string, extra ...string) []string {
	out := append([]string(nil), extra...)
	for _, f := range fields {
		out = append(out, prefix+f)
	}
	return out
}

func withoutPrefix(in []string, prefix string) []string {
	var out []string
	for _, p := range in {
		if p != prefix && !strings.HasPrefix(p, prefix+".") && !strings.HasPrefix(p, prefix+"[") {
			out = append(out, p)
		}
	}
	return out
}

var (
	cloudSessionsKnownPaths = prefixed("data[].", append(append([]string(nil), cloudSessionFields...), cloudSessionLiveFields...),
		"data", "data[]", "has_more", "next_page", "first_id", "last_id")
	// The retrieve fixture is a session with no resources member (a single
	// document with an array member would read as a page to the mock).
	cloudSessionKnownPaths     = withoutPrefix(prefixed("", cloudSessionFields), "resources")
	cloudEnvironmentKnownPaths = []string{
		"archived_at", "config", "config.setup_script", "config.type", "created_at", "id", "name", "scope", "type", "updated_at",
	}
)
