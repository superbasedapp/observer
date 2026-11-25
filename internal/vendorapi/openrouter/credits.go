package openrouter

import (
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceCredits is the catalog id of the credits balance.
const SurfaceCredits vs.SurfaceID = "openrouter.mgmt.credits" //nolint:gosec // G101: a surface id, not a credential

// Credits vocabulary.
const (
	CreditsContract = "openrouter.mgmt.credits/v1 openapi getCredits (2026-10-08)" //nolint:gosec // G101: a contract label, not a credential
	// SnapshotClass is the snapshot class of the balance (one per account).
	SnapshotClass = "openrouter.credits"
)

// Credits returns the driver of openrouter.mgmt.credits.
//
// Contract (OpenAPI getCredits): GET /api/v1/credits; response {data:
// {total_credits, total_usage}}, both doubles in OpenRouter credits (USD),
// lifetime totals. One point-in-time snapshot of the account: purchased and
// used, in micro-dollars. It is a balance, never a spend series: nothing sums
// it or reads it as a period's cost.
func Credits() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCredits,
		Build:           buildCredits,
		ParseResponse:   parseCredits,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: CreditsContract,
		Tool:            Tool,
		KnownPaths:      []string{"data", "data.total_credits", "data.total_usage"},
	}
}

func buildCredits(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, vendorapi.Drift(SurfaceCredits, "the balance is not paged")
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/credits"}, nil
}

type creditsDoc struct {
	Data *struct {
		TotalCredits *decimal `json:"total_credits"`
		TotalUsage   *decimal `json:"total_usage"`
	} `json:"data"`
}

func parseCredits(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceCredits
	var doc creditsDoc
	if err := decode(r, s, &doc); err != nil {
		return vendorapi.Page{}, err
	}
	if doc.Data == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field data is missing")
	}
	total, ok1 := dollars(doc.Data.TotalCredits)
	used, ok2 := dollars(doc.Data.TotalUsage)
	if !ok1 || !ok2 {
		return vendorapi.Page{}, vendorapi.Drift(s, "data.total_credits or data.total_usage is missing, negative or not a number")
	}
	return vendorapi.Page{SourceRecords: 1, Snapshots: []vendorapi.VendorSnapshot{{
		Class: SnapshotClass, Subject: "account", Body: map[string]string{
			"unit": "usd_micros", "total_credits": strconv.FormatInt(total, 10), "total_usage": strconv.FormatInt(used, 10),
		},
	}}}, nil
}
