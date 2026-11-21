package warp

import (
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Run surfaces.
const (
	SurfaceRunsList  vs.SurfaceID = "warp.agent_api.runs_list"
	SurfaceRunDetail vs.SurfaceID = "warp.agent_api.run_detail"

	RunsListContract  = "warp.agent_api.runs_list/v1 " + contract
	RunDetailContract = "warp.agent_api.run_detail/v1 " + contract
)

// Run vocabulary.
const (
	// RunClass is the snapshot class of one run (the session Observer
	// shows); its subject is the run id.
	RunClass = "warp.run"
	// The two usage rows of a run's request_usage, one per unit, each keyed
	// by the run id. They are never summed with each other (CA-D11).
	CreditsNamespace = "warp.run.credits"
	USDNamespace     = "warp.run.usd"
	UsageJoinKind    = "run_id"
	// UnitCredit is the unit of inference_cost, compute_cost and
	// platform_cost (Warp credits); UnitUSD of their *_usd twins ("what the
	// run ... was billed at, in US dollars"; older runs fall back to an
	// estimate, which the response does not mark).
	UnitCredit = "warp_credit"
	UnitUSD    = "usd"
	// HarnessOz is Warp's built-in harness: the documented default when a
	// run's agent_config carries no harness.
	HarnessOz = "oz"
	// HarnessDefaulted is the body value of harness_source when the run did
	// not state its harness and the documented default was applied.
	HarnessDefaulted = "default"
	// HarnessStated is the body value of harness_source when the run named
	// its harness.
	HarnessStated = "stated"
	// IdentityCaller names the key owner when a run carries no creator.
	IdentityCaller      = "caller"
	IdentityCallerValue = "self"
)

// RunsList returns the driver of warp.agent_api.runs_list.
//
// Contract (OpenAPI listRuns): GET /api/v1/agent/runs with limit, cursor,
// sort_by=updated_at, sort_order=desc and execution_location=REMOTE (always:
// the list also carries the user's LOCAL runs). An incremental run sends its
// window start as updated_after; the route has no upper bound, so a run
// updated after the window's end is listed too (the consumer deduplicates by
// run id). Response {runs, page_info{has_next_page, next_cursor}, as_of,
// team_uid}. Each run lands as one warp.run snapshot plus a credits and a
// USD usage row when request_usage reports them. The prompt, title, creator
// e-mail, display name and photo are never decoded.
func RunsList() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceRunsList,
		Build:           buildRunsList,
		ParseResponse:   parseRunsList,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: RunsListContract,
		KnownPaths:      runsListKnownPaths,
	}
}

// RunDetail returns the driver of warp.agent_api.run_detail: GET
// /api/v1/agent/runs/{runId}, one RunItem mapped exactly like a list entry.
func RunDetail() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceRunDetail,
		Build:           buildRunDetail,
		ParseResponse:   parseRunDetail,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: RunDetailContract,
		KnownPaths:      runDetailKnownPaths,
	}
}

func buildRunsList(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{
		"limit":              {strconv.Itoa(PageSize)},
		"sort_by":            {"updated_at"},
		"sort_order":         {"desc"},
		"execution_location": {ExecutionRemote},
	}
	switch {
	case w.From.IsZero() && w.To.IsZero():
	case w.From.IsZero() || !w.To.After(w.From):
		return vendorapi.Request{}, drift(SurfaceRunsList, "a window needs both bounds, From before To")
	default:
		q["updated_after"] = []string{w.From.UTC().Format(time.RFC3339)}
	}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return vendorapi.Request{}, drift(SurfaceRunsList, "cursor is not an opaque page cursor")
		}
		q["cursor"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: APIBase + "/agent/runs", Query: q}, nil
}

func buildRunDetail(p vendorapi.Params, _ vendorapi.Window, _ string) (vendorapi.Request, error) {
	path, err := runPath(SurfaceRunDetail, p, "")
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path}, nil
}

// principal is RunCreatorInfo without its display name, e-mail and photo.
type principal struct {
	Type *string `json:"type"`
	UID  *string `json:"uid"`
}

// run is the closed DTO of one RunItem: title, prompt, submitted_prompt,
// session_link, trigger_url, status_message, schedule, metadata, scope and
// agent_skill are deliberately absent, and so are the creator's e-mail,
// display name and photo.
type run struct {
	RunID             *string    `json:"run_id"`
	State             *string    `json:"state"`
	ExecutionLocation *string    `json:"execution_location"`
	CreatedAt         *string    `json:"created_at"`
	UpdatedAt         *string    `json:"updated_at"`
	StartedAt         *string    `json:"started_at"`
	FinishedAt        *string    `json:"finished_at"`
	Source            *string    `json:"source"`
	Creator           *principal `json:"creator"`
	ConversationID    *string    `json:"conversation_id"`
	ParentRunID       *string    `json:"parent_run_id"`
	RootRunID         *string    `json:"root_run_id"`
	RequestUsage      *struct {
		InferenceCost    *num `json:"inference_cost"`
		ComputeCost      *num `json:"compute_cost"`
		PlatformCost     *num `json:"platform_cost"`
		InferenceCostUSD *num `json:"inference_cost_usd"`
		ComputeCostUSD   *num `json:"compute_cost_usd"`
		PlatformCostUSD  *num `json:"platform_cost_usd"`
	} `json:"request_usage"`
	AgentConfig *struct {
		ModelID       *string `json:"model_id"`
		EnvironmentID *string `json:"environment_id"`
		WorkerHost    *string `json:"worker_host"`
		Harness       *struct {
			Type    *string `json:"type"`
			ModelID *string `json:"model_id"`
		} `json:"harness"`
	} `json:"agent_config"`
	Artifacts *[]struct {
		ArtifactType *string `json:"artifact_type"`
		Data         *struct {
			URL    *string `json:"url"`
			Branch *string `json:"branch"`
		} `json:"data"`
	} `json:"artifacts"`
}

// listDoc is ListRunsResponse.
type listDoc struct {
	Runs     *[]run `json:"runs"`
	PageInfo *struct {
		HasNextPage *bool   `json:"has_next_page"`
		NextCursor  *string `json:"next_cursor"`
	} `json:"page_info"`
}

func parseRunsList(r vendorapi.Response) (vendorapi.Page, error) {
	if err := status200(SurfaceRunsList, r); err != nil {
		return vendorapi.Page{}, err
	}
	var doc listDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceRunsList, "body does not decode as the documented ListRunsResponse")
	}
	if doc.Runs == nil {
		return vendorapi.Page{}, drift(SurfaceRunsList, "required field runs is missing")
	}
	if doc.PageInfo == nil || doc.PageInfo.HasNextPage == nil {
		return vendorapi.Page{}, drift(SurfaceRunsList, "required field page_info.has_next_page is missing")
	}
	out := vendorapi.Page{SourceRecords: len(*doc.Runs)}
	if *doc.PageInfo.HasNextPage {
		next := str(doc.PageInfo.NextCursor)
		switch {
		case !cursorRE.MatchString(next):
			return vendorapi.Page{}, drift(SurfaceRunsList, "has_next_page is true without a usable next_cursor")
		case next == r.Cursor:
			return vendorapi.Page{}, drift(SurfaceRunsList, "next_cursor repeats the page the request asked for")
		}
		out.NextCursor = next
	}
	seen := map[string]bool{}
	for i, rn := range *doc.Runs {
		if err := mapRun(SurfaceRunsList, i, rn, seen, &out); err != nil {
			return vendorapi.Page{}, err
		}
	}
	return out, nil
}

func parseRunDetail(r vendorapi.Response) (vendorapi.Page, error) {
	if err := status200(SurfaceRunDetail, r); err != nil {
		return vendorapi.Page{}, err
	}
	var rn run
	if err := decode(r.Body, &rn); err != nil {
		return vendorapi.Page{}, drift(SurfaceRunDetail, "body does not decode as the documented RunItem")
	}
	out := vendorapi.Page{SourceRecords: 1}
	if err := mapRun(SurfaceRunDetail, 0, rn, map[string]bool{}, &out); err != nil {
		return vendorapi.Page{}, err
	}
	if want := r.Params[ParamRunID]; want != "" && out.Snapshots[0].Subject != want {
		return vendorapi.Page{}, drift(SurfaceRunDetail, "run_id is not the run the request asked for")
	}
	return out, nil
}

// putID sets an optional id-shaped body value, refusing a malformed one.
func putID(body map[string]string, key string, v *string) bool {
	s := str(v)
	if s == "" {
		return true
	}
	if !tokenRE.MatchString(s) {
		return false
	}
	body[key] = s
	return true
}

// mapRun lands one RunItem: its snapshot and its usage rows.
func mapRun(surface vs.SurfaceID, i int, rn run, seen map[string]bool, out *vendorapi.Page) error {
	id := str(rn.RunID)
	if !idRE.MatchString(id) {
		return drift(surface, "runs[%d].run_id is missing or not an id", i)
	}
	if seen[id] {
		return drift(surface, "runs[%d] repeats a run", i)
	}
	seen[id] = true
	if !tokenRE.MatchString(str(rn.State)) {
		return drift(surface, "runs[%d].state is missing or not a state", i)
	}
	created, ok := rfc3339(rn.CreatedAt)
	if !ok {
		return drift(surface, "runs[%d].created_at is not an RFC 3339 timestamp", i)
	}
	updated, ok := rfc3339(rn.UpdatedAt)
	if !ok {
		return drift(surface, "runs[%d].updated_at is not an RFC 3339 timestamp", i)
	}
	body := map[string]string{
		"created_at": created.Format(time.RFC3339), "updated_at": updated.Format(time.RFC3339),
		"state": strings.ToLower(str(rn.State)),
	}
	for _, f := range []struct {
		key string
		v   *string
	}{{"started_at", rn.StartedAt}, {"finished_at", rn.FinishedAt}} {
		if f.v == nil || *f.v == "" {
			continue // null while active, and for terminal runs with no recorded finish
		}
		t, ok := rfc3339(f.v)
		if !ok {
			return drift(surface, "runs[%d].%s is not an RFC 3339 timestamp", i, f.key)
		}
		body[f.key] = t.Format(time.RFC3339)
	}
	ids := []struct {
		key string
		v   *string
	}{
		{"execution_location", rn.ExecutionLocation},
		{"source", rn.Source},
		{"conversation_id", rn.ConversationID},
		{"parent_run_id", rn.ParentRunID},
		{"root_run_id", rn.RootRunID},
	}
	if c := rn.Creator; c != nil {
		ids = append(ids, struct {
			key string
			v   *string
		}{"creator_type", c.Type}, struct {
			key string
			v   *string
		}{"creator_uid", c.UID})
	}
	harness, harnessSource := HarnessOz, HarnessDefaulted
	if ac := rn.AgentConfig; ac != nil {
		model := ac.ModelID
		if h := ac.Harness; h != nil {
			if t := str(h.Type); t != "" {
				harness, harnessSource = t, HarnessStated
			}
			if str(h.ModelID) != "" && harness != HarnessOz {
				// A third-party harness's model is harness.model_id; the
				// top-level model_id targets the built-in harness.
				model = h.ModelID
			}
		}
		ids = append(ids, []struct {
			key string
			v   *string
		}{{"model_id", model}, {"environment_id", ac.EnvironmentID}, {"worker_host", ac.WorkerHost}}...)
	}
	if !tokenRE.MatchString(harness) {
		return drift(surface, "runs[%d].agent_config.harness.type is not a harness id", i)
	}
	body["harness"], body["harness_source"] = strings.ToLower(harness), harnessSource
	for _, f := range ids {
		if !putID(body, f.key, f.v) {
			return drift(surface, "runs[%d].%s is not an id-shaped value", i, f.key)
		}
	}
	if body["execution_location"] != "" {
		body["execution_location"] = strings.ToUpper(body["execution_location"])
	}
	if rn.Artifacts != nil {
		prs := 0
		for _, a := range *rn.Artifacts {
			if str(a.ArtifactType) != "PULL_REQUEST" || a.Data == nil {
				continue
			}
			prs++
			if prs > 1 {
				continue
			}
			u, cut := capText(str(a.Data.URL), vendorapi.MaxAttrValue)
			if u == "" || cut || !strings.HasPrefix(u, "https://") {
				return drift(surface, "runs[%d] has a pull request artifact without an https url", i)
			}
			body["pr_url"] = u
			if b, cut := capText(str(a.Data.Branch), vendorapi.MaxIDLen); b != "" && !cut {
				body["pr_branch"] = b
			}
		}
		body["pr_count"] = strconv.Itoa(prs)
	}
	out.Snapshots = append(out.Snapshots, vendorapi.VendorSnapshot{Class: RunClass, Subject: id, Body: body})
	return usageRows(surface, i, id, updated, body, rn, out)
}

// usageRows lands request_usage as one credits row and one USD row, each the
// sum of the inference, compute and platform parts the run reports (the
// parts are kept as flags). A unit with no part reported lands no row.
func usageRows(surface vs.SurfaceID, i int, id string, at time.Time, body map[string]string, rn run, out *vendorapi.Page) error {
	ru := rn.RequestUsage
	if ru == nil {
		return nil
	}
	identityKind, identity := IdentityCaller, IdentityCallerValue
	if uid := body["creator_uid"]; uid != "" {
		identityKind = "user_uid"
		if body["creator_type"] == "service_account" {
			identityKind = "service_account_uid"
		}
		identity = uid
	}
	for _, u := range []struct {
		namespace, unit string
		parts           [3]*num
	}{
		{CreditsNamespace, UnitCredit, [3]*num{ru.InferenceCost, ru.ComputeCost, ru.PlatformCost}},
		{USDNamespace, UnitUSD, [3]*num{ru.InferenceCostUSD, ru.ComputeCostUSD, ru.PlatformCostUSD}},
	} {
		row := vendorapi.UsageRow{
			JoinKind: UsageJoinKind, JoinNamespace: u.namespace, JoinValue: id, At: at, SessionRef: id,
			Model: body["model_id"], Revision: at.Unix(), IdentityKind: identityKind, Identity: identity,
			ChargedUnit: u.unit, Flags: map[string]string{},
		}
		reported := false
		for k, name := range []string{"inference", "compute", "platform"} {
			v, present, ok := amount(u.parts[k])
			if !ok {
				return drift(surface, "runs[%d].request_usage.%s cost is not a non-negative amount", i, name)
			}
			if !present {
				continue
			}
			reported = true
			row.ChargedMicros += v
			row.Flags[name+"_micros"] = strconv.FormatInt(v, 10)
		}
		if reported {
			out.Usage = append(out.Usage, row)
		}
	}
	return nil
}
