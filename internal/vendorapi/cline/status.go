package cline

import (
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceSessionStatus is the catalog id of one cloud session's status.
const SurfaceSessionStatus vs.SurfaceID = "cline.cloud.session_status"

// Status vocabulary.
const (
	SessionStatusContract = "cline.cloud.session_status/v1 @cline/core 0.2.0 CloudSessionApi.status (undocumented)"

	// StatusClass is the snapshot class of one status read; its subject is
	// the cloud session id the request named.
	StatusClass = "cline.cloud_session_status"
)

// SessionStatus returns the driver of cline.cloud.session_status.
//
// Contract (observed in the vendor client, undocumented; @cline/core 0.2.0
// CloudSessionApi.status and waitUntilReady): GET
// /api/v1/session/{id}/status, Bearer account token, response {data:
// {sessionId?, status?, phase?, statusReason?}}. The client treats status
// "ready" or "active" as a running sandbox, "provisioning" as starting and
// "failed" as failed; phase is the provisioning phase (provisioning,
// cloning_repo, agent_starting, ready, failed). The read lands as one
// snapshot of class cline.cloud_session_status with status and phase;
// statusReason (free text) is never decoded. A body that is the JSON
// literal null (the node egress answers a 404, "session not found", with
// it) lands nothing.
func SessionStatus() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceSessionStatus,
		Build:           buildSessionStatus,
		ParseResponse:   parseSessionStatus,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: SessionStatusContract,
		Tool:            Tool,
		KnownPaths:      statusKnownPaths,
	}
}

func buildSessionStatus(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	id := p[ParamSessionID]
	if !ValidID(id) || cursor != "" {
		return vendorapi.Request{}, drift(SurfaceSessionStatus, "a status read needs one session id and no cursor")
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/session/" + id + "/status"}, nil
}

// statusDoc is the closed DTO of a status read.
type statusDoc struct {
	SessionID *string `json:"sessionId"`
	Status    *string `json:"status"`
	Phase     *string `json:"phase"`
}

func parseSessionStatus(r vendorapi.Response) (vendorapi.Page, error) {
	if err := checkStatus(SurfaceSessionStatus, r); err != nil {
		return vendorapi.Page{}, err
	}
	if isNull(r.Body) {
		return vendorapi.Page{}, nil
	}
	id := r.Params[ParamSessionID]
	if !ValidID(id) {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "the response names no requested session")
	}
	var env envelope
	if err := decode(r.Body, &env); err != nil || env.Data == nil || isNull(env.Data) {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "body is not the {data: {...}} envelope")
	}
	var doc statusDoc
	if err := decode(env.Data, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "data is not a status object")
	}
	if s := str(doc.SessionID); s != "" && s != id {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "data.sessionId names another session")
	}
	if str(doc.Status) == "" {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "data.status is missing")
	}
	body := map[string]string{}
	if !putShort(body, "status", doc.Status) || !putShort(body, "phase", doc.Phase) {
		return vendorapi.Page{}, drift(SurfaceSessionStatus, "data has an over-long status or phase")
	}
	return vendorapi.Page{
		Snapshots: []vendorapi.VendorSnapshot{{Class: StatusClass, Subject: id, Body: body}}, SourceRecords: 1,
	}, nil
}

// statusKnownPaths are the response paths of the corpus field ledger of the
// status read.
var statusKnownPaths = []string{"data", "data.phase", "data.sessionId", "data.status", "data.statusReason", "success"}
