package cline

import (
	"encoding/json"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceSessions is the catalog id of the cloud session list.
const SurfaceSessions vs.SurfaceID = "cline.cloud.sessions"

// Session list vocabulary.
const (
	SessionsContract = "cline.cloud.sessions/v1 @cline/core 0.2.0 CloudSessionApi.list (undocumented)"

	// SessionClass is the snapshot class of one cloud session; its subject
	// is the outer cloud session id ("ses-...").
	SessionClass = "cline.cloud_session"
	// ParamOrganizationID optionally scopes the list to an organization
	// (the client's ?organizationId=); absent lists the default scope.
	ParamOrganizationID = "organization_id"
)

// Sessions returns the driver of cline.cloud.sessions.
//
// Contract (observed in the vendor client, undocumented; @cline/core 0.2.0
// dist/cloud/api.d.ts CloudSessionRecord and dist/cloud/index.js
// CloudSessionApi.listWithToken): GET /api/v1/session[?organizationId=],
// Bearer account token, response {data: [record]} (the client reads
// response.data and treats a missing data as an empty list). The list is
// not paged. A record carries id, status, sandboxType, title, sandboxUrl,
// repoContext {repoUrl, branch}, metadata {sandboxType, modelId, taskId,
// statusReason, provisioningPhase, createRequestTitle, cwd, handoff
// {sourceSessionId}}, expiredAt, lastActivityAt, createdAt, updatedAt.
// Each record lands as one snapshot of class cline.cloud_session. title,
// sandboxUrl, statusReason, createRequestTitle and cwd are never decoded
// (prompt-derived text, a sandbox address, free text, a sandbox path). The
// live check of 2026-11-02 also saw success on the envelope and userId,
// sandboxId, origin and historyUrl on a record; the closed DTO ignores them.
func Sessions() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceSessions,
		Build:           buildSessions,
		ParseResponse:   parseSessions,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: SessionsContract,
		Tool:            Tool,
		KnownPaths:      sessionsKnownPaths,
	}
}

func buildSessions(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, drift(SurfaceSessions, "the session list is not paged")
	}
	q := map[string][]string{}
	if org := p[ParamOrganizationID]; org != "" {
		if !ValidID(org) {
			return vendorapi.Request{}, drift(SurfaceSessions, "organization id is not an id")
		}
		q["organizationId"] = []string{org}
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/session", Query: q}, nil
}

// record is the closed DTO of one CloudSessionRecord.
type record struct {
	ID          *string `json:"id"`
	Status      *string `json:"status"`
	SandboxType *string `json:"sandboxType"`
	RepoContext *struct {
		RepoURL *string `json:"repoUrl"`
		Branch  *string `json:"branch"`
	} `json:"repoContext"`
	Metadata *struct {
		SandboxType       *string `json:"sandboxType"`
		ModelID           *string `json:"modelId"`
		TaskID            *string `json:"taskId"`
		ProvisioningPhase *string `json:"provisioningPhase"`
		Handoff           *struct {
			SourceSessionID *string `json:"sourceSessionId"`
		} `json:"handoff"`
	} `json:"metadata"`
	ExpiredAt      *string `json:"expiredAt"`
	LastActivityAt *string `json:"lastActivityAt"`
	CreatedAt      *string `json:"createdAt"`
	UpdatedAt      *string `json:"updatedAt"`
}

// field is one optional snapshot body value and its key.
type field struct {
	key string
	v   *string
}

// envelope is the client's {data: ...} response wrapper.
type envelope struct {
	Data json.RawMessage `json:"data"`
}

func parseSessions(r vendorapi.Response) (vendorapi.Page, error) {
	if err := checkStatus(SurfaceSessions, r); err != nil {
		return vendorapi.Page{}, err
	}
	var env envelope
	if err := decode(r.Body, &env); err != nil {
		return vendorapi.Page{}, drift(SurfaceSessions, "body does not decode as the {data} envelope")
	}
	if env.Data == nil {
		return vendorapi.Page{}, drift(SurfaceSessions, "required field data is missing")
	}
	var recs []record
	if !isNull(env.Data) {
		if err := decode(env.Data, &recs); err != nil {
			return vendorapi.Page{}, drift(SurfaceSessions, "data is not a list of session records")
		}
	}
	out := vendorapi.Page{SourceRecords: len(recs)}
	seen := map[string]bool{}
	for i, rec := range recs {
		id := str(rec.ID)
		if !ValidID(id) {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d].id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d] repeats a session", i)
		}
		seen[id] = true
		if str(rec.Status) == "" {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d].status is missing", i)
		}
		created, ok := isoTime(str(rec.CreatedAt))
		if !ok {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d].createdAt is not an ISO timestamp", i)
		}
		updated, ok := isoTime(str(rec.UpdatedAt))
		if !ok {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d].updatedAt is not an ISO timestamp", i)
		}
		body := map[string]string{
			"created_at": created.Format(time.RFC3339), "updated_at": updated.Format(time.RFC3339),
		}
		if !putTime(body, "last_activity_at", rec.LastActivityAt) || !putTime(body, "expired_at", rec.ExpiredAt) {
			return vendorapi.Page{}, drift(SurfaceSessions, "data[%d] has a timestamp that is not ISO", i)
		}
		fields := []field{{"status", rec.Status}, {"sandbox_type", rec.SandboxType}}
		if rc := rec.RepoContext; rc != nil {
			fields = append(fields, field{"repo_url", rc.RepoURL}, field{"branch", rc.Branch})
		}
		if m := rec.Metadata; m != nil {
			if rec.SandboxType == nil {
				fields = append(fields, field{"sandbox_type", m.SandboxType})
			}
			fields = append(fields, field{"model_id", m.ModelID}, field{"task_id", m.TaskID},
				field{"provisioning_phase", m.ProvisioningPhase})
			if m.Handoff != nil {
				fields = append(fields, field{"handoff_source_session_id", m.Handoff.SourceSessionID})
			}
		}
		for _, f := range fields {
			if !putShort(body, f.key, f.v) {
				return vendorapi.Page{}, drift(SurfaceSessions, "data[%d].%s is over-long", i, f.key)
			}
		}
		out.Snapshots = append(out.Snapshots, vendorapi.VendorSnapshot{Class: SessionClass, Subject: id, Body: body})
	}
	return out, nil
}

// sessionsKnownPaths are the response paths of the corpus field ledger of
// the session list.
var sessionsKnownPaths = []string{
	"data", "data[]", "data[].createdAt", "data[].expiredAt", "data[].id", "data[].lastActivityAt",
	"data[].metadata", "data[].metadata.createRequestTitle", "data[].metadata.cwd", "data[].metadata.handoff",
	"data[].metadata.handoff.sourceSessionId", "data[].metadata.modelId", "data[].metadata.provisioningPhase",
	"data[].metadata.sandboxType", "data[].metadata.statusReason", "data[].metadata.taskId", "data[].repoContext",
	"data[].repoContext.branch", "data[].repoContext.repoUrl", "data[].sandboxType", "data[].sandboxUrl",
	"data[].status", "data[].title", "data[].updatedAt",
	// Seen live 2026-11-02, not in the type; never decoded.
	"data[].historyUrl", "data[].origin", "data[].sandboxId", "data[].userId", "success",
}
