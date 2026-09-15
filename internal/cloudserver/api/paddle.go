package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle.go is the W9 Paddle billing webhook + the portal Billing read
// (divergence remediation plan §3 "W9"; ruling R4; closes D6). It mirrors the
// WorkOS webhook's discipline exactly: FAIL-CLOSED on configuration (no secret ⇒
// 501, nothing read), nothing before the signature check touches the database,
// constant-time HMAC verification with a replay tolerance, idempotent + retry-
// safe intake (5xx-with-no-processed-stamp on an apply failure so Paddle
// redelivers), and NO storage of card/payment data.

const (
	// paddleSignatureHeader carries Paddle Billing's timestamped HMAC in the form
	// `ts=<unix-seconds>;h1=<hex hmac-sha256>`.
	paddleSignatureHeader = "Paddle-Signature"
	// paddleSignatureTolerance bounds how far a delivery's signed timestamp may
	// be from now (replay window). Paddle recommends 5s; 5 min is generous
	// (matches the WorkOS webhook's tolerance) because Paddle RE-SIGNS each
	// retry with a fresh ts rather than replaying the original signed
	// timestamp, so a tighter window trades nothing away — a retry always
	// arrives freshly signed. The operator may tighten this later (A3 /
	// gap 1.7); documented here rather than silently narrowed so a future
	// change is a deliberate one.
	paddleSignatureTolerance = 5 * time.Minute
	// paddleMaxSignatureCandidates bounds how many `h1=` values on one
	// delivery are ever checked (P3-b). Paddle's own rotation shape sends at
	// most a couple (one per secret it currently knows about); an attacker
	// padding the header with an unbounded number of h1= entries would
	// otherwise force an unbounded number of hex-decode + HMAC computations
	// per delivery, a cheap DoS lever. Extra h1= values beyond the cap are
	// silently ignored, not a signature-invalid rejection of the whole
	// header — the FIRST 4 are still checked normally.
	paddleMaxSignatureCandidates = 4
)

var errPaddleSignature = errors.New("cloudserver/api: paddle webhook signature invalid")

// composePaddleWebhookSecrets merges Options.PaddleWebhookSecret (the current
// secret) with Options.PaddleWebhookSecrets (additional ones — e.g. a
// not-yet-retired previous secret during rotation, A3 / gap 1.7) into the one
// list verifyPaddleSignature checks a delivery against, trimming whitespace
// and dropping empties so an unset field never contributes a blank "secret".
func composePaddleWebhookSecrets(primary string, extra []string) []string {
	out := make([]string, 0, 1+len(extra))
	if v := strings.TrimSpace(primary); v != "" {
		out = append(out, v)
	}
	for _, v := range extra {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// verifyPaddleSignature checks the `ts=<unix-seconds>;h1=<hex>` header against
// HMAC-SHA256("<ts>:<raw body>") under ANY of `secrets`, within the replay
// tolerance. Every digest comparison is constant-time.
//
// A3 (gap 1.7): Paddle sends MULTIPLE `h1=` values on the header during a
// webhook-secret rotation (one per secret it knows about), and this
// deployment may itself hold more than one currently-valid secret (the
// current + a not-yet-retired previous one). The delivery verifies if ANY
// presented h1 matches under ANY configured secret — so rotating
// SBCI_PADDLE_WEBHOOK_SECRET is never an outage: set the new value, keep the
// old one in SBCI_PADDLE_WEBHOOK_SECRET_PREVIOUS until Paddle confirms the
// new secret is live, then drop the previous one.
//
// UNITS: Paddle's `ts` is unix SECONDS (Paddle Billing docs), parsed with
// time.Unix; the unit lives on exactly one line and never leaks into the window
// math (a time.Duration compared against a time.Time).
func verifyPaddleSignature(header string, secrets []string, body []byte, now time.Time) error {
	if strings.TrimSpace(header) == "" {
		return errPaddleSignature
	}
	var rawTS string
	var macs []string
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "ts":
			rawTS = v
		case "h1":
			if len(macs) < paddleMaxSignatureCandidates {
				macs = append(macs, v)
			}
		}
	}
	if rawTS == "" || len(macs) == 0 {
		return errPaddleSignature
	}
	secs, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return errPaddleSignature
	}
	skew := now.Sub(time.Unix(secs, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > paddleSignatureTolerance {
		return errPaddleSignature
	}
	for _, rawMAC := range macs {
		presented, err := hex.DecodeString(rawMAC)
		if err != nil {
			continue
		}
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(rawTS))
			mac.Write([]byte(":"))
			mac.Write(body)
			if hmac.Equal(presented, mac.Sum(nil)) {
				return nil
			}
		}
	}
	return errPaddleSignature
}

// paddleWebhookEnvelope is the slice of Paddle's Billing (v2) event we decode.
// Only ids/status/price/period/custom_data — no card or payment-instrument data.
// It covers three event families: subscription.* (data.id is the sub_),
// transaction.* (data.subscription_id + data.status), and adjustment.*
// (data.action/type/status + data.subscription_id — refunds/chargebacks, which
// carry NO custom_data; docs:
// https://developer.paddle.com/webhooks/adjustments/adjustment-created and
// https://developer.paddle.com/webhooks/transactions/transaction-completed).
type paddleWebhookEnvelope struct {
	EventID    string `json:"event_id"`
	EventType  string `json:"event_type"`
	OccurredAt string `json:"occurred_at"`
	Data       struct {
		ID             string `json:"id"`              // sub_... | txn_... | adj_...
		CustomerID     string `json:"customer_id"`     // ctm_...
		Status         string `json:"status"`          // subscription/transaction/adjustment status
		SubscriptionID string `json:"subscription_id"` // transaction.* / adjustment.*
		Action         string `json:"action"`          // adjustment.* : refund|chargeback|...
		Type           string `json:"type"`            // adjustment.* : full|partial
		CustomData     struct {
			AccountID     string `json:"account_id"`
			CheckoutNonce string `json:"checkout_nonce"`
		} `json:"custom_data"`
		CurrentBillingPeriod struct {
			StartsAt string `json:"starts_at"`
			EndsAt   string `json:"ends_at"`
		} `json:"current_billing_period"`
		// NextBilledAt (A7 / gap 1.11) is the fallback trial-end estimate when
		// current_billing_period is absent — Paddle's trialing/canceled
		// payloads sometimes carry one without the other.
		NextBilledAt string `json:"next_billed_at"`
		// ManagementURLs (A7 / gap 1.4) is Paddle's hosted customer-portal
		// link pair. Paddle's own docs note subscription.updated omits this
		// entirely — absence is normal, not an error.
		ManagementURLs struct {
			UpdatePaymentMethod string `json:"update_payment_method"`
			Cancel              string `json:"cancel"`
		} `json:"management_urls"`
		Items []paddleWebhookItem `json:"items"`
		// Details carries the transaction totals (transaction.* only) the
		// live-defect fix (2026-09-12) uses to detect a $0 trial-start
		// transaction.completed. Amounts are Paddle's decimal STRINGS in
		// minor units (e.g. "0", "1500"), never a card/payment-instrument
		// value.
		Details struct {
			Totals struct {
				Total      string `json:"total"`
				GrandTotal string `json:"grand_total"`
			} `json:"totals"`
		} `json:"details"`
	} `json:"data"`
}

// paddleWebhookItem is one entry of data.items[] - shared by every event
// family that carries items (subscription.* and transaction.*). TrialDates
// (subscription.* only) and Price.TrialPeriod (both families - it lives on
// the price object itself) are the live-defect fix (2026-09-12) additions.
type paddleWebhookItem struct {
	Price struct {
		ID string `json:"id"` // pri_...
		// TrialPeriod is non-nil when this price carries a Paddle-side
		// trial. A nil pointer (the field absent, or present but not an
		// object) distinguishes "no trial period" from a zero-frequency one
		// -either way paddleItemsHaveTrialPeriod requires Frequency > 0.
		TrialPeriod *struct {
			Interval  string `json:"interval"`
			Frequency int    `json:"frequency"`
		} `json:"trial_period"`
	} `json:"price"`
	// TrialDates is present on subscription.* items while trialing/created
	// for a trial price; transaction.* items never carry it.
	TrialDates struct {
		StartsAt string `json:"starts_at"`
		EndsAt   string `json:"ends_at"`
	} `json:"trial_dates"`
}

// paddleAmountIsZero reports whether a Paddle decimal-string minor-unit
// amount (e.g. "0", "1500") parses as zero. An amount that fails to parse -
// or is empty - is deliberately NOT treated as zero: fail toward the
// pre-fix "money moved" assumption rather than silently granting trial-like
// treatment on malformed input.
func paddleAmountIsZero(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return false
	}
	return n == 0
}

// paddleTransactionZeroTotal reports whether a transaction event's
// details.totals amount is zero. grand_total is preferred (the amount
// actually charged after tax/discount/credit); total is the fallback when
// grand_total is absent. Both empty (every non-transaction event, which
// carries no details.totals at all) resolves to false, never true.
func paddleTransactionZeroTotal(grandTotal, total string) bool {
	if strings.TrimSpace(grandTotal) != "" {
		return paddleAmountIsZero(grandTotal)
	}
	return paddleAmountIsZero(total)
}

// paddleItemsHaveTrialPeriod reports whether any item's price carries a
// Paddle-side trial period (frequency > 0) - a PRICE-level trial
// configuration, independent of any particular subscription's current
// status or event family.
func paddleItemsHaveTrialPeriod(items []paddleWebhookItem) bool {
	for _, it := range items {
		if it.Price.TrialPeriod != nil && it.Price.TrialPeriod.Frequency > 0 {
			return true
		}
	}
	return false
}

// paddleEventFromEnvelope normalizes a decoded webhook envelope into the
// store.PaddleEvent the store acts on. Shared by handlePaddleWebhook and
// DecodePaddleWebhookEnvelope so there is exactly one decode implementation
// (CLAUDE.md #2: one seam, no type leakage past it).
//
// P2-1: a custom_data.account_id that does not even PARSE as a UUID is
// sanitized to "" here — the earliest possible point — rather than reaching
// the store as a malformed value. Before this, a non-UUID string flowed all
// the way to a `::uuid` cast inside the store's own transaction and raised a
// hard error there, which (with no processed_at ever stamped) made Paddle
// redeliver the SAME failing event forever. A syntactically valid but
// entirely foreign UUID (one that parses fine but names no real account) is
// intentionally left as-is: the store's account-existence check already
// resolves that case gracefully (outcome account_not_found), and rejecting
// well-formed input here would just duplicate that logic in two places.
func paddleEventFromEnvelope(env paddleWebhookEnvelope, now time.Time) store.PaddleEvent {
	accountID := strings.TrimSpace(env.Data.CustomData.AccountID)
	if accountID != "" {
		if _, err := uuid.Parse(accountID); err != nil {
			accountID = ""
		}
	}
	ev := store.PaddleEvent{
		EventID:             env.EventID,
		EventType:           env.EventType,
		AccountID:           accountID,
		CheckoutNonce:       strings.TrimSpace(env.Data.CustomData.CheckoutNonce),
		CustomerID:          env.Data.CustomerID,
		Status:              env.Data.Status,
		ManagementUpdateURL: env.Data.ManagementURLs.UpdatePaymentMethod,
		ManagementCancelURL: env.Data.ManagementURLs.Cancel,
		Now:                 now,
	}
	// The subscription id lives in different places per family: data.id for
	// subscription.*, data.subscription_id for transaction.*/adjustment.*.
	switch {
	case strings.HasPrefix(env.EventType, "subscription."):
		ev.SubscriptionID = env.Data.ID
	case strings.HasPrefix(env.EventType, "transaction."):
		ev.SubscriptionID = env.Data.SubscriptionID
	case strings.HasPrefix(env.EventType, "adjustment."):
		ev.SubscriptionID = env.Data.SubscriptionID
		ev.AdjustmentAction = env.Data.Action
		ev.AdjustmentType = env.Data.Type
		ev.AdjustmentStatus = env.Data.Status
	default:
		ev.SubscriptionID = env.Data.ID
	}
	if len(env.Data.Items) > 0 {
		ev.PriceID = env.Data.Items[0].Price.ID
	}
	ev.OccurredAt = parsePaddleTime(env.OccurredAt)
	ev.CurrentPeriodEnd = parsePaddleTime(env.Data.CurrentBillingPeriod.EndsAt)
	ev.NextBilledAt = parsePaddleTime(env.Data.NextBilledAt)

	// Live-defect fix (2026-09-12): a $0 transaction.completed for a price
	// that carries a Paddle-side trial must never be read as "money moved".
	ev.TransactionZeroTotal = paddleTransactionZeroTotal(env.Data.Details.Totals.GrandTotal, env.Data.Details.Totals.Total)
	ev.TrialPeriodOnPrice = paddleItemsHaveTrialPeriod(env.Data.Items)
	// TrialEndsAt ladder: items[0].trial_dates.ends_at (the most direct
	// signal, subscription.* only) -> CurrentPeriodEnd -> NextBilledAt. May
	// stay zero (a transaction.completed's payload carries none of these
	// three on a fresh first-purchase delivery).
	trialEndsAt := time.Time{}
	if len(env.Data.Items) > 0 {
		trialEndsAt = parsePaddleTime(env.Data.Items[0].TrialDates.EndsAt)
	}
	if trialEndsAt.IsZero() {
		trialEndsAt = ev.CurrentPeriodEnd
	}
	if trialEndsAt.IsZero() {
		trialEndsAt = ev.NextBilledAt
	}
	ev.TrialEndsAt = trialEndsAt
	return ev
}

// DecodePaddleWebhookEnvelope parses a Paddle webhook body into the
// normalized store.PaddleEvent the store acts on — the SAME decode
// handlePaddleWebhook itself calls, exported so golden fixtures (A10 — no
// live Paddle account is approved yet, so these are Paddle's own DOCUMENTED
// example payloads) can be run through the real decoder in a test without
// standing up an HTTP server. body must already be signature-verified; this
// performs no verification of its own.
func DecodePaddleWebhookEnvelope(body []byte, now time.Time) (store.PaddleEvent, error) {
	var env paddleWebhookEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return store.PaddleEvent{}, err
	}
	if env.EventID == "" || env.EventType == "" {
		return store.PaddleEvent{}, errors.New("invalid event envelope (event_id and event_type are required)")
	}
	return paddleEventFromEnvelope(env, now), nil
}

// handlePaddleWebhook takes delivery of one Paddle billing event.
func (s *Server) handlePaddleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(s.paddleWebhookSecrets) == 0 {
		writeErr(w, http.StatusNotImplemented, "webhook_not_configured",
			"Paddle webhook intake is not configured on this deployment (SBCI_PADDLE_WEBHOOK_SECRET is unset). Deliveries are refused rather than accepted unverified.")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return
	}
	if err := verifyPaddleSignature(r.Header.Get(paddleSignatureHeader), s.paddleWebhookSecrets, body, s.now()); err != nil {
		s.audit(ctx, "", "paddle_webhook_signature_invalid")
		writeErr(w, http.StatusUnauthorized, "signature_invalid",
			"the delivery signature was missing, malformed, stale, or did not verify")
		return
	}

	ev, err := DecodePaddleWebhookEnvelope(body, s.now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid event envelope (event_id and event_type are required)")
		return
	}

	intake, err := s.store.ProcessPaddleEvent(ctx, ev)
	if err != nil {
		// Recorded but not finished: answer 5xx with NO processed stamp so Paddle
		// redelivers (retry-safety). A lost billing event silently drops a paid
		// upgrade or a cancellation.
		s.log.Error("cloudserver/api: process paddle event", "event_id", ev.EventID, "event_type", ev.EventType, "err", err)
		writeErr(w, http.StatusInternalServerError, "event_processing_failed",
			"the event was accepted but could not be processed; it will be retried on redelivery")
		return
	}
	// Every verified delivery is 200-acknowledged (never 5xx for a refused
	// binding, an unattributed adjustment, or an unknown event type — those must
	// not trigger endless Paddle redelivery) and audited with the honest outcome.
	outcome := intake.Outcome
	if outcome == "" {
		switch {
		case intake.Duplicate:
			outcome = "duplicate"
		case intake.Applied:
			outcome = "applied"
		default:
			outcome = "acknowledged"
		}
	}
	// P3-d: audit the RESOLVED account intake actually acted on (or attributed
	// to), never the untrusted request-supplied ev.AccountID — a self-
	// initiated checkout can set custom_data.account_id to anything, so
	// auditing that value would let an attacker write arbitrary account
	// attribution into the security audit trail even for an event that was
	// correctly refused.
	s.audit(ctx, intake.AccountID, "paddle_"+ev.EventType+"_"+outcome)
	status := "processed"
	if intake.Duplicate {
		status = "duplicate"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "event_id": ev.EventID, "applied": intake.Applied, "outcome": outcome,
	})
}

// parsePaddleTime parses an RFC3339 timestamp, returning the zero time on failure
// (the store treats a zero time as "unknown").
func parsePaddleTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// handlePortalBilling is GET /portal/api/billing — the portal Billing page's
// data: the account's current subscription (if any) + the plan it is on.
func (s *Server) handlePortalBilling(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	view := map[string]any{"has_subscription": false}
	sub, err := s.store.AccountSubscription(r.Context(), p.AccountID)
	switch {
	case err == nil:
		view["has_subscription"] = true
		view["subscription"] = sub
	case errors.Is(err, store.ErrNotFound):
		// no subscription — free tier
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	// The current plan/allowance (so the page shows what they have now).
	if snap, uerr := s.store.Usage(r.Context(), p.AccountID, store.FeatureSessionEnrichment, s.now()); uerr == nil {
		view["plan"] = snap
	}
	// A6: the checkout catalogue Wave B's Upgrade button reads — prices,
	// environment, client token, trial length. "available" is the single
	// boolean the UI needs to decide whether to render an Upgrade button at
	// all (a client token AND at least one price must both be configured).
	// Prices defaults to a non-nil empty slice: PaddleCheckout is a plain
	// struct any caller (including a zero-value Options in a test, or a
	// deployment that never wires PaddleCheckout at all) can leave
	// zero-valued, and a nil slice would encode as JSON null rather than [].
	prices := s.paddleCheckout.Prices
	if prices == nil {
		prices = []PaddlePriceEntry{}
	}
	view["checkout"] = map[string]any{
		"available":    s.paddleCheckout.Available(),
		"environment":  s.paddleCheckout.Environment,
		"client_token": s.paddleCheckout.ClientToken,
		"prices":       prices,
		"trial_days":   s.paddleCheckout.TrialDays,
	}
	writeJSON(w, http.StatusOK, view)
}

// checkoutIntentTTL bounds how long a minted checkout nonce stays bindable. A
// Paddle checkout is completed in minutes; 30m is generous and short enough that
// a leaked nonce expires quickly.
const checkoutIntentTTL = 30 * time.Minute

// paddleSubscriptionStatusIsLive mirrors migration 0034's
// paddle_subscriptions_one_live partial unique index predicate exactly
// (status NOT IN ('canceled','refunded','charged_back')) — the precise set
// of statuses that occupy an account's one live-subscription slot (P2-3).
func paddleSubscriptionStatusIsLive(status string) bool {
	switch status {
	case "", "canceled", "refunded", "charged_back":
		return false
	default:
		return true
	}
}

// handlePortalCheckout is POST /portal/api/billing/checkout — the server-initiated
// checkout scaffold (G2-07 / F2 core). It mints a single-use nonce bound to the
// AUTHENTICATED account and returns the server-set custom_data (account_id +
// nonce) the client hands to Paddle.js when opening the checkout. The webhook
// later REQUIRES this nonce to bind the resulting subscription to the account, so
// a user-initiated checkout that forges custom_data.account_id can never bind.
//
// DARK: no live Paddle transaction is created here (no Paddle API key on the
// wire). The actual checkout is opened client-side with the returned custom_data,
// or server-side once an operator provisions a Paddle API key — go-live gated.
func (s *Server) handlePortalCheckout(w http.ResponseWriter, r *http.Request) {
	p, ok := portalPrincipalFrom(r.Context())
	if !ok || strings.TrimSpace(p.AccountID) == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "no portal session")
		return
	}
	// P2-3: refuse a second checkout BEFORE minting a nonce when the account
	// already holds a live subscription. Without this, a second checkout
	// bound to a SECOND, DISTINCT Paddle subscription id would reach the
	// webhook and hit paddle_subscriptions_one_live — refused there too
	// (store-side pre-check), but only after the customer has already been
	// charged by Paddle for a subscription this system will never grant.
	if sub, serr := s.store.AccountSubscription(r.Context(), p.AccountID); serr == nil {
		if paddleSubscriptionStatusIsLive(sub.Status) {
			writeErr(w, http.StatusConflict, "already_subscribed",
				"this account already holds a live subscription; manage or cancel it before starting a new checkout")
			return
		}
	} else if !errors.Is(serr, store.ErrNotFound) {
		s.log.Error("cloudserver/api: check existing subscription", "err", serr)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check existing subscription")
		return
	}
	var req struct {
		PriceID string `json:"price_id"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if e := json.Unmarshal(body, &req); e != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}
	}
	price := strings.TrimSpace(req.PriceID)
	if price == "" || !s.store.PaddlePriceKnown(price) {
		// Dark posture: with no provisioned prices every price is unknown, so
		// checkout is unavailable until the operator wires SBCI_PADDLE_PRICES
		// (or the legacy single-price SBCI_PADDLE_PRICE_PLUS).
		writeErr(w, http.StatusNotImplemented, "checkout_unavailable",
			"no purchasable plan is configured for this deployment (SBCI_PADDLE_PRICES is unset, or the requested price is not a known plan price)")
		return
	}
	nonce, expiresAt, err := s.store.CreateCheckoutIntent(r.Context(), p.AccountID, price, checkoutIntentTTL, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: create checkout intent", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not create checkout")
		return
	}
	s.audit(r.Context(), p.AccountID, "paddle_checkout_intent_created")
	writeJSON(w, http.StatusOK, map[string]any{
		"price_id":   price,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"custom_data": map[string]string{
			"account_id":     p.AccountID,
			"checkout_nonce": nonce,
		},
	})
}

// PaddleCheckout is the resolved, validated Paddle checkout configuration for
// a deployment: the A4 (gap 1.1) environment switch and the A5/A6 (gap 1.8)
// purchasable price catalogue GET /portal/api/billing exposes to the portal.
// Built once at startup by ValidatePaddleCheckoutEnv — nothing here is read
// again from the process environment after boot.
type PaddleCheckout struct {
	// Environment is "sandbox" or "live" (SBCI_PADDLE_ENV; default sandbox).
	Environment string `json:"environment"`
	// ClientToken is the Paddle.js CLIENT-SIDE token (SBCI_PADDLE_CLIENT_TOKEN)
	// — never a secret: it authorizes opening a Paddle.js overlay in the
	// browser, nothing server-side. Empty until provisioned.
	ClientToken string `json:"client_token"`
	// Prices is the purchasable price catalogue, sorted by PriceID for a
	// stable response shape. Never nil (empty ⇒ [], not null).
	Prices []PaddlePriceEntry `json:"prices"`
	// TrialDays is the Paddle-side trial length this deployment advertises
	// (SBCI_PADDLE_TRIAL_DAYS, default 0). Paddle's own price-level trial
	// configuration is what actually grants the trial; this is display only.
	TrialDays int `json:"trial_days"`
}

// Available reports whether this deployment can actually open a checkout: a
// client token AND at least one price must both be configured. Used by
// GET /portal/api/billing's "checkout":{"available":...} and by Wave B's
// Upgrade-button gate.
func (c PaddleCheckout) Available() bool {
	return c.ClientToken != "" && len(c.Prices) > 0
}

// PaddlePriceEntry is one purchasable price in the portal catalogue.
type PaddlePriceEntry struct {
	PriceID     string `json:"price_id"`
	PlanName    string `json:"plan_name"`
	PlanVersion int    `json:"plan_version"`
	Interval    string `json:"interval"`
	Display     string `json:"display"`
}

// PaddleCheckoutEnv is the raw env-sourced input to ValidatePaddleCheckoutEnv.
// Kept as plain fields — never read from os.Getenv here — so the validator is
// pure and directly testable without a process environment (CLAUDE.md #5).
type PaddleCheckoutEnv struct {
	// Environment is the raw SBCI_PADDLE_ENV value ("" normalizes to sandbox).
	Environment string
	// ClientToken is the raw SBCI_PADDLE_CLIENT_TOKEN value.
	ClientToken string
	// WebhookConfigured reports whether at least one webhook secret is
	// configured (len(PaddleWebhookSecrets-composed) > 0).
	WebhookConfigured bool
	// Prices is the already-parsed price catalogue (ParsePaddlePriceEntries
	// output, converted to PaddlePriceEntry by the caller).
	Prices []PaddlePriceEntry
	// TrialDaysRaw is the raw SBCI_PADDLE_TRIAL_DAYS value ("" ⇒ 0).
	TrialDaysRaw string
	// OriginIsPublic is P3-f's sandbox-in-prod detector: true when this
	// deployment's external base URL is neither loopback (dev/test) nor a
	// host the operator has explicitly flagged as non-production via
	// SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1. PaddleCheckoutEnvFromProcess
	// computes this from the process environment; a caller that leaves this
	// the zero value (false) gets the pre-P3-f behavior — sandbox-on-public
	// is a NEW, additive refusal, never retroactively applied to a caller
	// that hasn't wired it.
	OriginIsPublic bool
}

// paddleCheckoutResolved is the normalized form paddleCheckoutValidations'
// rows walk — Environment lowercased/defaulted, ClientToken trimmed, TrialDays
// already parsed and range-checked.
type paddleCheckoutResolved struct {
	Environment       string
	ClientToken       string
	WebhookConfigured bool
	Prices            []PaddlePriceEntry
	TrialDays         int
	OriginIsPublic    bool
}

// paddleCheckoutValidation is one row of the table-driven startup-refusal
// ladder ValidatePaddleCheckoutEnv walks in order (CLAUDE.md #5 — an ordered
// rule set as a data table, not a growing if/else-if ladder). `fail` returns
// non-nil for the EXACT conditions gap 1.1/1.8 named as go-live blockers;
// everything else is honest "dark until provisioned", never a startup
// refusal (e.g. an unset SBCI_PADDLE_CLIENT_TOKEN in sandbox is fine).
type paddleCheckoutValidation struct {
	name string
	fail func(paddleCheckoutResolved) error
}

var paddleCheckoutValidations = []paddleCheckoutValidation{
	{
		name: "environment",
		fail: func(r paddleCheckoutResolved) error {
			if r.Environment != "sandbox" && r.Environment != "live" {
				return fmt.Errorf("SBCI_PADDLE_ENV must be %q or %q, got %q", "sandbox", "live", r.Environment)
			}
			return nil
		},
	},
	{
		// env=live and the client token does not start with live_ (including
		// EMPTY — going live requires the real live token, not silence);
		// env=sandbox and a SET token does not start with test_ (an unset
		// sandbox token stays the honest dark posture).
		name: "client token",
		fail: func(r paddleCheckoutResolved) error {
			switch r.Environment {
			case "live":
				if !strings.HasPrefix(r.ClientToken, "live_") {
					return errors.New("SBCI_PADDLE_ENV=live requires SBCI_PADDLE_CLIENT_TOKEN to be set to a live_ token")
				}
			case "sandbox":
				if r.ClientToken != "" && !strings.HasPrefix(r.ClientToken, "test_") {
					return errors.New("a configured SBCI_PADDLE_CLIENT_TOKEN must start with test_ when SBCI_PADDLE_ENV=sandbox")
				}
			}
			return nil
		},
	},
	{
		name: "webhook secret",
		fail: func(r paddleCheckoutResolved) error {
			if r.Environment == "live" && !r.WebhookConfigured {
				return errors.New("SBCI_PADDLE_ENV=live requires SBCI_PADDLE_WEBHOOK_SECRET to be set")
			}
			return nil
		},
	},
	{
		name: "prices",
		fail: func(r paddleCheckoutResolved) error {
			if r.Environment == "live" && len(r.Prices) == 0 {
				return errors.New("SBCI_PADDLE_ENV=live requires at least one configured price (SBCI_PADDLE_PRICES or SBCI_PADDLE_PRICE_PLUS)")
			}
			return nil
		},
	},
	{
		// P3-f: a sandbox checkout with a configured client token, reachable
		// on a PUBLIC origin, is the undetectable-sandbox-in-prod shape — an
		// operator who forgot to flip SBCI_PADDLE_ENV=live (or genuinely
		// believes this is production) would otherwise serve real customers
		// a sandbox checkout with no signal anything is wrong. Refused
		// unless the operator has explicitly acknowledged the origin is not
		// production via SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1
		// (folded into OriginIsPublic itself — see PaddleCheckoutEnvFromProcess).
		// A sandbox deployment with NO client token configured is still the
		// honest dark posture (Available()==false) and is not refused here.
		name: "sandbox on public origin",
		fail: func(r paddleCheckoutResolved) error {
			if r.Environment == "sandbox" && r.ClientToken != "" && r.OriginIsPublic {
				return errors.New("SBCI_PADDLE_ENV=sandbox with a configured SBCI_PADDLE_CLIENT_TOKEN is refused on a public origin; " +
					"set SBCI_PADDLE_ENV=live for a real deployment, or SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1 to confirm this " +
					"origin genuinely is not production")
			}
			return nil
		},
	},
}

// parsePaddleTrialDays parses SBCI_PADDLE_TRIAL_DAYS (raw, "" ⇒ 0) and range-
// checks it 0..90 — a trial longer than 90 days reads as a config typo, not
// an intentional trial (A6 / gap 1.8's "final price point" decision).
func parsePaddleTrialDays(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("SBCI_PADDLE_TRIAL_DAYS must be an integer, got %q", raw)
	}
	if n < 0 || n > 90 {
		return 0, fmt.Errorf("SBCI_PADDLE_TRIAL_DAYS must be 0..90, got %d", n)
	}
	return n, nil
}

// ValidatePaddleCheckoutEnv normalizes + validates the Paddle env inputs into
// a PaddleCheckout, walking paddleCheckoutValidations in order and failing on
// the first row that refuses (A4 — this is what a live deployment being
// mis-flipped to SBCI_PADDLE_ENV=live without the rest of the go-live
// prerequisites must fail STARTUP for, not silently serve a broken checkout).
// Pure — no os.Getenv, no I/O (CLAUDE.md #5).
func ValidatePaddleCheckoutEnv(in PaddleCheckoutEnv) (PaddleCheckout, error) {
	env := strings.ToLower(strings.TrimSpace(in.Environment))
	if env == "" {
		env = "sandbox"
	}
	trialDays, err := parsePaddleTrialDays(in.TrialDaysRaw)
	if err != nil {
		return PaddleCheckout{}, fmt.Errorf("cloudserver/api.ValidatePaddleCheckoutEnv: %w", err)
	}
	resolved := paddleCheckoutResolved{
		Environment: env, ClientToken: strings.TrimSpace(in.ClientToken),
		WebhookConfigured: in.WebhookConfigured, Prices: in.Prices, TrialDays: trialDays,
		OriginIsPublic: in.OriginIsPublic,
	}
	for _, v := range paddleCheckoutValidations {
		if err := v.fail(resolved); err != nil {
			return PaddleCheckout{}, fmt.Errorf("cloudserver/api.ValidatePaddleCheckoutEnv: %s: %w", v.name, err)
		}
	}
	prices := make([]PaddlePriceEntry, len(resolved.Prices))
	copy(prices, resolved.Prices)
	sort.Slice(prices, func(i, j int) bool { return prices[i].PriceID < prices[j].PriceID })
	return PaddleCheckout{
		Environment: resolved.Environment,
		ClientToken: resolved.ClientToken,
		Prices:      prices,
		TrialDays:   resolved.TrialDays,
	}, nil
}

// PaddleCheckoutEnvFromProcess resolves P3-f's OriginIsPublic signal for
// PaddleCheckoutEnv from a deployment's external base URL and the process
// environment. It is the one impure (env-reading) seam this file needs for
// P3-f, kept separate from the pure ValidatePaddleCheckoutEnv so that
// function stays directly testable with no process environment (CLAUDE.md
// #5). Call-site (cmd/observer-cloud/main.go is NOT in this remediation's
// file list — the orchestrator applies this one-line change to
// paddleCheckoutFromEnv's existing api.PaddleCheckoutEnv{...} literal):
//
//	OriginIsPublic: api.PaddleCheckoutEnvFromProcess(externalBase, os.Getenv),
//
// where externalBase is the same value externalBaseURL(listen) already
// resolves for this process (SBCI_EXTERNAL_BASE_URL, defaulting to
// http://localhost:<port>).
//
// A deployment is "public" (returns true) unless its external base URL host
// is loopback — localhost / 127.0.0.0/8 / ::1, the SAME predicate
// edgeConfigForExternalOrigin already applies for its own loopback carve-out,
// so the two never disagree about what "this is just dev" means — OR the
// operator has explicitly flagged the origin as non-production via
// SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1 (an intentional escape valve
// for a real, reachable staging host that is not production; every other
// value, including unset, leaves the origin "public"). An unparseable or
// empty-host base URL fails closed as public — malformed input has no
// business waving this gate through silently.
func PaddleCheckoutEnvFromProcess(externalBase string, getenv func(string) string) bool {
	if getenv != nil && strings.TrimSpace(getenv("SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN")) == "1" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(externalBase))
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}
