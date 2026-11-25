package prime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceWallet is the catalog id of the team wallet.
const SurfaceWallet vs.SurfaceID = "prime.billing.wallet"

// Wallet vocabulary (lane ENTAPI-L16D, T-713).
const (
	WalletContract = "prime.billing.wallet/v1 openapi wallet balance snapshot (2026-10-08)"
	// WalletClass is the snapshot class of the team wallet balance.
	WalletClass = "prime.wallet"
)

// walletCategories maps the documented credit categories of
// credits_remaining_by_category ("sandboxes, training, inference") to their
// snapshot body keys. Another category is read past, never landed.
var walletCategories = map[string]string{
	"sandboxes": "credits_remaining_sandboxes",
	"training":  "credits_remaining_training",
	"inference": "credits_remaining_inference",
}

// Wallet returns the driver of prime.billing.wallet.
//
// Contract (OpenAPI get wallet): GET /api/v1/billing/wallet with teamId (the
// connection parameter team_id; "return the team's wallet, requires
// membership"), limit 1 and offset 0; response WalletResponse {wallet_id,
// team_id|null, balance_usd, currency, total_billings, recent_billings[],
// credit_grants[], sandbox_credits_remaining_usd, credits_remaining_by_category}.
// One point-in-time snapshot of the team wallet lands: balance and the
// remaining grant credits per documented category, in micro-dollars, and the
// total billing row count. It is a balance, never a spend series: nothing
// sums it or reads it as a period's cost. The billing rows are running
// per-resource accumulators (updated in place, no member on a row) and the
// grant labels are customer text, so neither is decoded beyond its shape. A
// currency other than USD or a team other than the one asked is drift.
func Wallet() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceWallet,
		Build:           buildWallet,
		ParseResponse:   parseWallet,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassLimits},
		ClosedDTO:       true,
		ContractVersion: WalletContract,
		KnownPaths: []string{
			"balance_usd", "credit_grants", "credit_grants[]", "credit_grants[].amount_usd", "credit_grants[].category",
			"credit_grants[].currency", "credit_grants[].expiresAt", "credit_grants[].id", "credit_grants[].label",
			"credit_grants[].qualifier", "credit_grants[].remaining_usd", "credit_grants[].revokedAt",
			"credits_remaining_by_category", "credits_remaining_by_category.inference",
			"credits_remaining_by_category.sandboxes", "credits_remaining_by_category.training", "currency",
			"recent_billings", "recent_billings[]", "recent_billings[].amount_usd", "recent_billings[].created_at",
			"recent_billings[].credits_covered_usd", "recent_billings[].currency", "recent_billings[].id",
			"recent_billings[].last_billed_at", "recent_billings[].resource_id", "recent_billings[].resource_type",
			"recent_billings[].updated_at", "sandbox_credits_remaining_usd", "team_id", "total_billings", "wallet_id",
		},
	}
}

func buildWallet(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the wallet is not paged", SurfaceWallet)
	}
	t := p[ParamTeam]
	if !teamRE.MatchString(t) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not a team id", SurfaceWallet, ParamTeam)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/billing/wallet", Query: map[string][]string{
		"teamId": {t}, "limit": {"1"}, "offset": {"0"},
	}}, nil
}

// usd is a bare JSON number in dollars kept as its literal text.
type usd string

// UnmarshalJSON accepts a bare JSON number only.
func (u *usd) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("prime: %.16q is not a JSON number", b)
	}
	*u = usd(b)
	return nil
}

type walletDoc struct {
	WalletID   *string            `json:"wallet_id"`
	TeamID     *string            `json:"team_id"`
	Balance    *usd               `json:"balance_usd"`
	Currency   *string            `json:"currency"`
	Total      *count             `json:"total_billings"`
	Recent     *[]json.RawMessage `json:"recent_billings"`
	Grants     *[]json.RawMessage `json:"credit_grants"`
	Sandbox    *usd               `json:"sandbox_credits_remaining_usd"`
	ByCategory map[string]usd     `json:"credits_remaining_by_category"`
}

func walletDrift(format string, a ...any) error {
	return fmt.Errorf("%w: %s: "+format, append([]any{vendorapi.ErrSchemaDrift, SurfaceWallet}, a...)...)
}

func micros(u *usd, allowNegative bool) (string, bool) {
	if u == nil {
		return "", false
	}
	v, ok := vendorapi.DecimalMicros(string(*u), 0)
	if !ok || (!allowNegative && v < 0) {
		return "", false
	}
	return strconv.FormatInt(v, 10), true
}

func parseWallet(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, walletDrift("status %d is not the documented 200", r.Status)
	}
	var doc walletDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	// WalletResponse is a closed set of members: a renamed or added member
	// (credit_grants renamed, say) is drift, not a silently thinner snapshot.
	// The billing rows and grants are raw, so only the top level is closed.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, walletDrift("body does not decode as the documented response")
	}
	if vendorapi.TrimStr(doc.WalletID) == "" || doc.Balance == nil || doc.Currency == nil || doc.Total == nil || doc.Recent == nil {
		return vendorapi.Page{}, walletDrift("required field wallet_id, balance_usd, currency, total_billings or recent_billings is missing")
	}
	if !strings.EqualFold(*doc.Currency, "usd") {
		return vendorapi.Page{}, walletDrift("currency %q is not USD", *doc.Currency)
	}
	if t := r.Params[ParamTeam]; t != "" && vendorapi.TrimStr(doc.TeamID) != t {
		return vendorapi.Page{}, walletDrift("the wallet answers another team than the one asked")
	}
	if *doc.Total < 0 {
		return vendorapi.Page{}, walletDrift("total_billings is negative")
	}
	// The balance may be negative (an amount owed); credits never are.
	balance, ok := micros(doc.Balance, true)
	if !ok {
		return vendorapi.Page{}, walletDrift("balance_usd is not a number in dollars")
	}
	body := map[string]string{
		"unit": "usd_micros", "balance": balance, "total_billings": strconv.FormatInt(int64(*doc.Total), 10),
	}
	if doc.Sandbox != nil {
		v, ok := micros(doc.Sandbox, false)
		if !ok {
			return vendorapi.Page{}, walletDrift("sandbox_credits_remaining_usd is not a non-negative number")
		}
		body["sandbox_credits_remaining"] = v
	}
	for cat, u := range doc.ByCategory {
		key, known := walletCategories[cat]
		if !known {
			continue
		}
		u := u
		v, ok := micros(&u, false)
		if !ok {
			return vendorapi.Page{}, walletDrift("credits_remaining_by_category.%s is not a non-negative number", cat)
		}
		body[key] = v
	}
	return vendorapi.Page{SourceRecords: 1, Snapshots: []vendorapi.VendorSnapshot{{
		Class: WalletClass, Subject: "team:" + r.Params[ParamTeam], Body: body,
	}}}, nil
}
