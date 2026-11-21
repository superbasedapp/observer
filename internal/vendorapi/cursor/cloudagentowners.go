package cursor

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The cloud-agent owner read of the Admin API (cloud agents arc, lane
// CA-C8). It is the usage-events endpoint again (one DTO, usageEventsDoc,
// and one paging contract with cursor.admin.usage_events), narrowed to
// cloud-hosted events, and it keeps only who ran each cloud agent: the
// event's cloudAgentId and its userEmail or serviceAccountId. Tokens, cents
// and the billing breakdown are never read into the page (the node rail owns
// Cursor cloud usage, and cursor.admin.usage_events owns the Admin API usage
// rows). It is its own catalog row, not a mode of cursor.admin.usage_events,
// because that row lands every token and cent it parses and waits on the
// legacy cursoradminpoll ownership gate (invariant I8), and this read must
// land neither and run regardless.
const (
	SurfaceCloudAgentOwners vs.SurfaceID = "cursor.admin.cloud_agent_owners"

	CloudAgentOwnersContract = "cursor.admin.cloud_agent_owners/v1 admin-api 2026-10-07"

	// CloudAgentOwnerClass is the snapshot class of one (cloud agent,
	// identity) pair the Admin API stated. Its subject is the cloud agent id
	// plus a digest of the identity, so two identities for one agent are two
	// rows (the projection holds such an agent as a conflict) and a later
	// event for the same pair stores nothing new.
	CloudAgentOwnerClass = "cursor.cloud_agent_owner"

	// OwnerKindEmail and OwnerKindServiceAccount are the identity kinds of an
	// owner snapshot: the member's e-mail, or the service account's id.
	OwnerKindEmail          = "email"
	OwnerKindServiceAccount = "service_account"
)

// cloudAgentIDRE bounds a cloudAgentId before it keys a snapshot. The
// reference calls it "the ID of the cloud agent run", so it may be an agent
// id (bc-<uuid>) or a run id; both shapes pass and the projection tries both
// readings. 200 bytes leaves room for the subject's digest suffix inside
// vendorapi.MaxIDLen.
var cloudAgentIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

// CloudAgentOwners returns the driver of cursor.admin.cloud_agent_owners.
//
// Contract (Cursor Admin API, "Get Usage Events Data"): POST
// /teams/filtered-usage-events with {"startDate", "endDate", "page",
// "pageSize", "hostingType": "CLOUD"} (the documented filter, ANDed with the
// range); the response and paging are cursor.admin.usage_events's. Each
// event carrying a cloudAgentId lands, once per (cloudAgentId, identity) on a
// page, as a cursor.cloud_agent_owner snapshot: the id, the identity kind and
// the identity (the serviceAccountId when the event carries one, else the
// folded userEmail). An event with no cloudAgentId is counted and skipped;
// one naming neither a member nor a service account is schema drift, exactly
// as on the usage row.
func CloudAgentOwners() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudAgentOwners,
		Build:           buildCloudAgentOwners,
		ParseResponse:   parseCloudAgentOwners,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassIdentity},
		ClosedDTO:       true,
		ContractVersion: CloudAgentOwnersContract,
		Tool:            Tool,
		MaxWindow:       UsageMaxWindow,
		KnownPaths:      cloudAgentOwnersKnownPaths,
	}
}

func buildCloudAgentOwners(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	start, end, err := inclusiveRange(SurfaceCloudAgentOwners, w, UsageMaxWindow)
	if err != nil {
		return vendorapi.Request{}, err
	}
	page, err := pageCursor(SurfaceCloudAgentOwners, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{
		Method: "POST", Path: "/teams/filtered-usage-events",
		Body: vendorapi.EpochRangePageHosting{
			StartMillis: start, EndMillis: end, Page: page, PageSize: UsagePageSize, HostingType: vendorapi.HostingCloud,
		},
	}, nil
}

// OwnerSubject is the snapshot subject of one (cloud agent id, identity)
// pair: the id, "~" and the first 16 hex of sha256(kind ":" identity).
func OwnerSubject(cloudAgentID, kind, identity string) string {
	sum := sha256.Sum256([]byte(kind + ":" + identity))
	return cloudAgentID + "~" + hex.EncodeToString(sum[:8])
}

func parseCloudAgentOwners(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "status %d is not the documented 200", r.Status)
	}
	var doc usageEventsDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "body does not decode as the documented object")
	}
	if doc.UsageEvents == nil || doc.Pagination == nil || doc.Pagination.CurrentPage == nil || doc.Pagination.HasNextPage == nil {
		return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "required field usageEvents, pagination.currentPage or pagination.hasNextPage is missing")
	}
	current, err := doc.Pagination.CurrentPage.Int64()
	if err != nil || current < 1 {
		return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "pagination.currentPage is not a page number")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.UsageEvents)}
	if *doc.Pagination.HasNextPage {
		page.NextCursor = strconv.FormatInt(current+1, 10)
	}
	seen := map[string]bool{}
	for i, e := range *doc.UsageEvents {
		var kind, identity string
		// A service-account event can also carry a userEmail (the official
		// service-account example does: the account's own address), so the
		// service account id decides first: such an event names no member.
		switch {
		case str(e.ServiceAccountID) != "":
			kind, identity = OwnerKindServiceAccount, *e.ServiceAccountID
		case str(e.UserEmail) != "":
			kind, identity = OwnerKindEmail, vendorapi.FoldEmail(*e.UserEmail)
		default:
			return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "usageEvents[%d] names neither userEmail nor serviceAccountId", i)
		}
		agent := str(e.CloudAgentID)
		if agent == "" {
			continue
		}
		if !cloudAgentIDRE.MatchString(agent) {
			return vendorapi.Page{}, drift(SurfaceCloudAgentOwners, "usageEvents[%d].cloudAgentId is not an id", i)
		}
		subject := OwnerSubject(agent, kind, identity)
		if seen[subject] {
			continue
		}
		seen[subject] = true
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{
			Class: CloudAgentOwnerClass, Subject: subject,
			Body: map[string]string{"cloud_agent_id": agent, "identity_kind": kind, "identity": identity},
		})
	}
	return page, nil
}

// cloudAgentOwnersKnownPaths are the documented response paths (the corpus
// field ledger of the cloud-filtered usage events).
var cloudAgentOwnersKnownPaths = []string{
	"pagination", "pagination.currentPage", "pagination.hasNextPage", "pagination.hasPreviousPage",
	"pagination.numPages", "pagination.pageSize", "period", "period.endDate", "period.startDate",
	"totalUsageEventsCount", "usageEvents", "usageEvents[]", "usageEvents[].chargedCents",
	"usageEvents[].cloudAgentId", "usageEvents[].conversationId", "usageEvents[].isChargeable",
	"usageEvents[].isHeadless", "usageEvents[].isTokenBasedCall", "usageEvents[].kind", "usageEvents[].maxMode",
	"usageEvents[].model", "usageEvents[].requestsCosts", "usageEvents[].serviceAccountId",
	"usageEvents[].serviceAccountName", "usageEvents[].timestamp", "usageEvents[].tokenUsage",
	"usageEvents[].tokenUsage.cacheReadTokens", "usageEvents[].tokenUsage.cacheWriteTokens",
	"usageEvents[].tokenUsage.inputTokens", "usageEvents[].tokenUsage.outputTokens",
	"usageEvents[].tokenUsage.totalCents", "usageEvents[].userEmail",
}
