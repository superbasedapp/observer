package qoder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The group and billing group lists of lane ENTAPI-L16C (T-710). Both share
// the member list's auth, host, organization parameter and nextToken paging.
const (
	SurfaceGroups        vs.SurfaceID = "qoder.oapi.groups"
	SurfaceBillingGroups vs.SurfaceID = "qoder.oapi.billing_groups"

	GroupsContract        = "qoder.oapi.groups/v1 teams-openapi groups (2026-10-08)"
	BillingGroupsContract = "qoder.oapi.billing_groups/v1 teams-openapi billing-groups (2026-10-08)"

	// GroupType is one organization group (manual or synchronized).
	GroupType vs.ResourceType = "Group/qoder.group/v1"
	// NamespaceGroup keys a group by its id.
	NamespaceGroup = "qoder.group"
	// BillingGroupType is one billing group (a cost center with a period
	// limit in Credits), including the built-in Unassigned group.
	BillingGroupType vs.ResourceType = "Group/qoder.billing_group/v1"
	// NamespaceBillingGroup keys a billing group by its id (the literal
	// "unassigned" for the built-in group).
	NamespaceBillingGroup = "qoder.billing_group"
	// UnitCredits is Qoder's Credit (never money).
	UnitCredits = "credits"
)

// Groups returns the driver of qoder.oapi.groups.
//
// Contract (Qoder Teams OpenAPI, "List groups"): GET
// /v1/organizations/{organization_id}/groups with maxResults (max 100) and
// nextToken; response {groups: [{id, organizationId, displayName,
// description?, source, externalId?, syncType?, isManaged, creatorId?,
// createdAt?, updatedAt?, memberCount}], maxResults, nextToken (omitted on
// the last page)}. No filter is sent, so a complete page set is
// authoritative. The description is admin-authored free text and is not
// landed; the creator id is not landed.
func Groups() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceGroups,
		Build:                 listBuilder(SurfaceGroups, "/groups"),
		ParseResponse:         parseGroups,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassGroups},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       GroupsContract,
		KnownPaths: []string{
			"groups", "groups[]", "groups[].createdAt", "groups[].creatorId", "groups[].description",
			"groups[].displayName", "groups[].externalId", "groups[].id", "groups[].isManaged", "groups[].memberCount",
			"groups[].organizationId", "groups[].source", "groups[].syncType", "groups[].updatedAt", "maxResults",
			"nextToken",
		},
	}
}

// BillingGroups returns the driver of qoder.oapi.billing_groups.
//
// Contract (Qoder Teams OpenAPI, "List billing groups"): GET
// /v1/organizations/{organization_id}/billing-groups with maxResults (max
// 100) and nextToken; periodEnd and keyword are never sent, so the current
// period is selected and every group is listed (the first page prepends the
// built-in Unassigned row, not counted against maxResults). Response
// {billingGroups: [{id, organizationId, name, description?, isUnassigned,
// memberCount, limitAmount (-1 unlimited, 0 frozen, else Credits),
// currentUsed, isBlocked, creatorId?, createdAt?, updatedAt?}], maxResults,
// nextToken?, selectedPeriod? {periodStart, periodEnd}}. Lands one resource
// per group: member count, the limit state and amount, the selected period's
// usage and whether it is blocked, and the period. A complete page set is
// authoritative. Read only: the limit, assignment and create operations are
// not built.
func BillingGroups() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceBillingGroups,
		Build:                 listBuilder(SurfaceBillingGroups, "/billing-groups"),
		ParseResponse:         parseBillingGroups,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassProjects, vs.ClassGroups, vs.ClassLimits},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       BillingGroupsContract,
		KnownPaths: []string{
			"billingGroups", "billingGroups[]", "billingGroups[].createdAt", "billingGroups[].creatorId",
			"billingGroups[].currentUsed", "billingGroups[].description", "billingGroups[].id",
			"billingGroups[].isBlocked", "billingGroups[].isUnassigned", "billingGroups[].limitAmount",
			"billingGroups[].memberCount", "billingGroups[].name", "billingGroups[].organizationId",
			"billingGroups[].updatedAt", "maxResults", "nextToken", "selectedPeriod", "selectedPeriod.periodEnd",
			"selectedPeriod.periodStart",
		},
	}
}

// listBuilder is the shared request of an organization list: the validated
// organization id as a path segment, maxResults and the opaque nextToken.
func listBuilder(s vs.SurfaceID, suffix string) func(vendorapi.Params, vendorapi.Window, string) (vendorapi.Request, error) {
	return func(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
		o := p[ParamOrganization]
		if !orgRE.MatchString(o) {
			return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not an organization id", s, ParamOrganization)
		}
		q := map[string][]string{"maxResults": {strconv.Itoa(PageSize)}}
		if cursor != "" {
			if !tokenRE.MatchString(cursor) {
				return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque token", s)
			}
			q["nextToken"] = []string{cursor}
		}
		return vendorapi.Request{Method: "GET", Path: "/v1/organizations/" + o + suffix, Query: q}, nil
	}
}

func driftOf(s vs.SurfaceID) func(string, ...any) error {
	return func(format string, a ...any) error {
		return vendorapi.Drift(s, format, a...)
	}
}

// nextToken applies the shared token rules: a present token is opaque and
// never the one the page was asked with.
func nextToken(s vs.SurfaceID, tok *string, asked string) (string, error) {
	t := vendorapi.Str(tok)
	if t == "" {
		return "", nil
	}
	if !tokenRE.MatchString(t) {
		return "", driftOf(s)("nextToken is not an opaque token")
	}
	if asked != "" && t == asked {
		return "", driftOf(s)("nextToken repeats the token the page was asked with")
	}
	return t, nil
}

// count is a JSON number kept as its literal text; a quoted value fails the
// page (plan 12A.5).
type count string

// UnmarshalJSON accepts a bare JSON number only.
func (n *count) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("qoder: %.16q is not a JSON number", b)
	}
	*n = count(b)
	return nil
}

// wholeCount reads a non-negative integer count.
func wholeCount(n *count) (string, bool) {
	if n == nil {
		return "", false
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 {
		return "", false
	}
	return strconv.FormatInt(v, 10), true
}

// credits reads a non-negative decimal Credit amount and renders it exactly
// (at most six decimals, never a float).
func credits(n *count) (string, bool) {
	if n == nil {
		return "", false
	}
	v, ok := vendorapi.DecimalMicros(string(*n), 0)
	if !ok || v < 0 {
		return "", false
	}
	whole, frac := v/1_000_000, v%1_000_000
	if frac == 0 {
		return strconv.FormatInt(whole, 10), true
	}
	return strings.TrimRight(fmt.Sprintf("%d.%06d", whole, frac), "0"), true
}

type groupsDoc struct {
	Groups *[]struct {
		ID          *string `json:"id"`
		DisplayName *string `json:"displayName"`
		Source      *string `json:"source"`
		ExternalID  *string `json:"externalId"`
		SyncType    *string `json:"syncType"`
		IsManaged   *bool   `json:"isManaged"`
		CreatedAt   *string `json:"createdAt"`
		UpdatedAt   *string `json:"updatedAt"`
		MemberCount *count  `json:"memberCount"`
	} `json:"groups"`
	NextToken *string `json:"nextToken"`
}

func parseGroups(r vendorapi.Response) (vendorapi.Page, error) {
	drift := driftOf(SurfaceGroups)
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc groupsDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	if doc.Groups == nil {
		return vendorapi.Page{}, drift("required field groups is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceGroup, Kind: vs.KindGroup}},
		SelectorDigest: "organization_all", PageSet: "organization_groups", ContractVersion: GroupsContract,
	}}
	tok, err := nextToken(SurfaceGroups, doc.NextToken, r.Cursor)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page.NextCursor = tok
	seen := map[string]bool{}
	for i, g := range *doc.Groups {
		id := vendorapi.Str(g.ID)
		if id == "" || g.DisplayName == nil || g.Source == nil || g.IsManaged == nil {
			return vendorapi.Page{}, drift("groups[%d] misses id, displayName, source or isManaged", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift("groups[%d] repeats a group", i)
		}
		seen[id] = true
		members, ok := wholeCount(g.MemberCount)
		if !ok {
			return vendorapi.Page{}, drift("groups[%d].memberCount is not a non-negative integer", i)
		}
		attrs := map[string]string{
			"source": *g.Source, "is_managed": strconv.FormatBool(*g.IsManaged), "member_count": members,
		}
		for k, v := range map[string]string{"external_id": vendorapi.Str(g.ExternalID), "sync_type": vendorapi.Str(g.SyncType)} {
			if v != "" {
				attrs[k] = v
			}
		}
		for k, v := range map[string]*string{"created_at": g.CreatedAt, "updated_at": g.UpdatedAt} {
			if v == nil {
				continue
			}
			t, ok := isoTime(*v)
			if !ok {
				return vendorapi.Page{}, drift("groups[%d].%s is not ISO 8601", i, k)
			}
			attrs[k] = t
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: GroupType, ID: vs.ExternalID{Namespace: NamespaceGroup, Value: id}, DisplayName: *g.DisplayName, Attrs: attrs,
		})
	}
	return page, nil
}

type billingGroupsDoc struct {
	BillingGroups *[]struct {
		ID           *string `json:"id"`
		Name         *string `json:"name"`
		IsUnassigned *bool   `json:"isUnassigned"`
		MemberCount  *count  `json:"memberCount"`
		LimitAmount  *count  `json:"limitAmount"`
		CurrentUsed  *count  `json:"currentUsed"`
		IsBlocked    *bool   `json:"isBlocked"`
		CreatedAt    *string `json:"createdAt"`
		UpdatedAt    *string `json:"updatedAt"`
	} `json:"billingGroups"`
	NextToken      *string `json:"nextToken"`
	SelectedPeriod *struct {
		PeriodStart *string `json:"periodStart"`
		PeriodEnd   *string `json:"periodEnd"`
	} `json:"selectedPeriod"`
}

func parseBillingGroups(r vendorapi.Response) (vendorapi.Page, error) {
	drift := driftOf(SurfaceBillingGroups)
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc billingGroupsDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	if doc.BillingGroups == nil {
		return vendorapi.Page{}, drift("required field billingGroups is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceBillingGroup, Kind: vs.KindGroup}},
		SelectorDigest: "organization_current_period", PageSet: "organization_billing_groups",
		ContractVersion: BillingGroupsContract,
	}}
	tok, err := nextToken(SurfaceBillingGroups, doc.NextToken, r.Cursor)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page.NextCursor = tok
	period := map[string]string{}
	if sp := doc.SelectedPeriod; sp != nil {
		start, ok1 := isoTime(vendorapi.Str(sp.PeriodStart))
		end, ok2 := isoTime(vendorapi.Str(sp.PeriodEnd))
		if !ok1 || !ok2 || end <= start {
			return vendorapi.Page{}, drift("selectedPeriod is not a half-open ISO 8601 interval")
		}
		period["period_start"], period["period_end"] = start, end
	}
	seen := map[string]bool{}
	for i, g := range *doc.BillingGroups {
		id := vendorapi.Str(g.ID)
		if id == "" || g.Name == nil || g.IsUnassigned == nil || g.IsBlocked == nil {
			return vendorapi.Page{}, drift("billingGroups[%d] misses id, name, isUnassigned or isBlocked", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift("billingGroups[%d] repeats a billing group", i)
		}
		seen[id] = true
		if *g.IsUnassigned != (id == "unassigned") {
			return vendorapi.Page{}, drift("billingGroups[%d]: isUnassigned disagrees with the documented id", i)
		}
		members, ok := wholeCount(g.MemberCount)
		if !ok {
			return vendorapi.Page{}, drift("billingGroups[%d].memberCount is not a non-negative integer", i)
		}
		used, ok := credits(g.CurrentUsed)
		if !ok {
			return vendorapi.Page{}, drift("billingGroups[%d].currentUsed is not a non-negative amount", i)
		}
		attrs := map[string]string{
			"is_unassigned": strconv.FormatBool(*g.IsUnassigned), "member_count": members, "current_used": used,
			"is_blocked": strconv.FormatBool(*g.IsBlocked), "unit": UnitCredits,
		}
		// limitAmount: -1 unlimited, 0 frozen, else a limit in Credits. Any
		// other negative value is undocumented.
		switch {
		case g.LimitAmount == nil:
			return vendorapi.Page{}, drift("billingGroups[%d].limitAmount is missing", i)
		case string(*g.LimitAmount) == "-1":
			attrs["limit_state"] = "unlimited"
		default:
			lim, ok := credits(g.LimitAmount)
			if !ok {
				return vendorapi.Page{}, drift("billingGroups[%d].limitAmount is not -1 or a non-negative amount", i)
			}
			attrs["limit_amount"] = lim
			attrs["limit_state"] = "set"
			if lim == "0" {
				attrs["limit_state"] = "frozen"
			}
		}
		for k, v := range period {
			attrs[k] = v
		}
		for k, v := range map[string]*string{"created_at": g.CreatedAt, "updated_at": g.UpdatedAt} {
			if v == nil {
				continue
			}
			t, ok := isoTime(*v)
			if !ok {
				return vendorapi.Page{}, drift("billingGroups[%d].%s is not ISO 8601", i, k)
			}
			attrs[k] = t
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: BillingGroupType, ID: vs.ExternalID{Namespace: NamespaceBillingGroup, Value: id}, DisplayName: *g.Name,
			Attrs: attrs,
		})
	}
	return page, nil
}
