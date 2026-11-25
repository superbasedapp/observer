package cursor

import (
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The one vendor write (lane ENTAPI-L14, T-617): Cursor Admin API "Set User
// Spend Limit". This file holds only the pure half: the surface, the path and
// the parse of the documented answer. The body is vendorapi.UserSpendLimitSet
// (a closed DTO with no null), the egress seam's closed write table is the
// only thing that sends it, and the executor in
// internal/orgserver/vendorconn/controlwrite is the only caller of that table.
//
// Contract (Cursor Admin API, checked 2026-10-07): POST
// /teams/user-spend-limit with {"userEmail", "spendLimitDollars"} (whole
// dollars; null removes the limit; Enterprise only; the user must already be
// a team member). The documented answers are {"outcome": "success",
// "message": ...} and {"outcome": "error", "message": ...}; the message is
// free text that names the member, so it is never read.

// SurfaceUserSpendLimit is the catalog surface of the write.
const SurfaceUserSpendLimit vs.SurfaceID = "cursor.admin.user_spend_limit"

// Path and contract version of the write.
const (
	UserSpendLimitPath     = "/teams/user-spend-limit"
	UserSpendLimitContract = "cursor.admin.user_spend_limit/v1 admin-api 2026-10-07"
)

// Write answers.
const (
	// WriteApplied is a documented success answer.
	WriteApplied = "applied"
	// WriteRejected is a documented error answer: the vendor refused the
	// write and changed nothing.
	WriteRejected = "rejected"
)

type writeResult struct {
	Outcome *string `json:"outcome"`
}

// ParseUserSpendLimitResult reads the documented answer of a 2xx write. Only
// the closed outcome field is read; any other shape is schema drift, which
// the executor records as an unknown effect (the request may have applied).
func ParseUserSpendLimitResult(r vendorapi.Response) (string, error) {
	if r.Status < 200 || r.Status > 299 {
		return "", vendorapi.Drift(SurfaceUserSpendLimit, "status %d is not a 2xx answer", r.Status)
	}
	var doc writeResult
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil || doc.Outcome == nil {
		return "", vendorapi.Drift(SurfaceUserSpendLimit, "body does not decode as the documented {outcome, message} object")
	}
	switch *doc.Outcome {
	case "success":
		return WriteApplied, nil
	case "error":
		return WriteRejected, nil
	}
	return "", vendorapi.Drift(SurfaceUserSpendLimit, "outcome is neither of the documented values")
}
