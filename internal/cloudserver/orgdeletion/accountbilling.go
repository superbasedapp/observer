package orgdeletion

import pc "github.com/marmutapp/superbased-observer/internal/platformcontract"

// accountbilling.go is the account deletion's billing rule (ORGDEL-7,
// PORTALORG-9): what an account deletion does with each Paddle subscription
// the account pays for.
//
// The account deletion purges every paddle_subscriptions row whose account_id
// is the account (the payer), so once it commits nothing in the control plane
// links Paddle's subscription to anyone. Before ORGDEL-7 an account-scope
// subscription (Personal Pro bought before the personal org existed, org_id
// NULL) was purged that way with no cancellation at Paddle, and Paddle kept
// billing a deleted account. The rule below closes it: the purge never
// deletes a subscription Paddle may still bill ([Subscription.MayBill]) that
// was not first confirmed canceled at Paddle. A live subscription either goes
// with the account (cancel it first) or pays for an org that outlives the
// account (refuse the deletion until the billing ends or moves, the existing
// PORTALORG-9 rule). A refunded or charged-back one grants nothing any more
// but still renews at Paddle (FR-7), so it is canceled first whatever it paid
// for.
//
// The store reads the facts, walks the table, cancels through the
// [Billing] seam BEFORE its deletion transaction, and re-walks the table
// inside that transaction, refusing when a subscription it must cancel was
// not confirmed canceled (internal/cloudserver/store/deletion.go).

// AccountSubscription is one subscription row the account pays for, as the
// account deletion reads it.
type AccountSubscription struct {
	// Subscription is the Paddle subscription id and its stored status.
	Subscription
	// OrgID is the org the subscription pays for, "" for an account-scope
	// subscription.
	OrgID string
	// OrgSeen is false when the org row is not visible to the account (no
	// membership any more, so RLS hides it) or does not exist.
	OrgSeen bool
	// PersonalOrg reports that the org is the account's own personal org.
	PersonalOrg bool
	// OrgStatus is the org's lifecycle status ("" when not seen).
	OrgStatus string
	// Slug and DisplayName name the org for a refusal ("" when not seen).
	Slug        string
	DisplayName string
}

// BillingFate is what an account deletion does with one subscription.
type BillingFate string

// The billing fates.
const (
	// BillingNothing: Paddle bills nothing more (the subscription is
	// canceled, or there is none); the purge deletes the record.
	BillingNothing BillingFate = "nothing"
	// BillingCancel: Paddle may still bill the subscription and nothing that
	// outlives the account needs it (what it pays for goes with the account,
	// or it was refunded or charged back); it is canceled at Paddle before
	// anything is deleted.
	BillingCancel BillingFate = "cancel"
	// BillingRefuse: the subscription is live and pays for an org that
	// outlives the account; the deletion is refused until the billing ends
	// or moves (PORTALORG-9).
	BillingRefuse BillingFate = "refuse"
)

// billingRule is one row of the account deletion's billing table.
type billingRule struct {
	name  string
	match func(s AccountSubscription) bool
	fate  BillingFate
}

// orgLiveStatus reports an org status that outlives an account deletion:
// being created, in service or suspended (the statuses an org may take a
// subscription in).
func orgLiveStatus(status string) bool {
	switch pc.TenantState(status) {
	case pc.StateProvisioning, pc.StateActive, pc.StateSuspended:
		return true
	}
	return false
}

// revokedStillRenewing reports a status whose plan a full refund or a
// chargeback revoked while the Paddle subscription itself goes on renewing:
// neither cancels it (FR-7, store/paddle_lifecycle.go; the go-live runbook
// 5c), and such a row holds no live slot (the 0090 trigger skips it).
func revokedStillRenewing(status string) bool {
	switch status {
	case "refunded", "charged_back":
		return true
	}
	return false
}

// billingRules is the account deletion's billing table, walked top-down per
// subscription; the first match decides and the last row always matches.
// One test case per row. A function, so no caller can change the policy.
func billingRules() []billingRule {
	return []billingRule{
		{
			name:  "a subscription Paddle bills no more (canceled, no status or no subscription id) is only a record",
			match: func(s AccountSubscription) bool { return !s.MayBill() },
			fate:  BillingNothing,
		},
		{
			name: "a refunded or charged-back subscription grants nothing but Paddle still renews it, and it holds no " +
				"org's live slot: cancel it first, whatever it paid for",
			match: func(s AccountSubscription) bool { return revokedStillRenewing(s.Status) },
			fate:  BillingCancel,
		},
		{
			name:  "an account-scope subscription (no org) goes with the account: cancel it first",
			match: func(s AccountSubscription) bool { return s.OrgID == "" },
			fate:  BillingCancel,
		},
		{
			name:  "the personal org is deleted with the account: cancel its subscription first",
			match: func(s AccountSubscription) bool { return s.PersonalOrg },
			fate:  BillingCancel,
		},
		{
			name:  "billing for an org the account can no longer see is still billing: refuse (PORTALORG-9)",
			match: func(s AccountSubscription) bool { return !s.OrgSeen },
			fate:  BillingRefuse,
		},
		{
			name:  "a team org being created, active or suspended outlives the account: refuse until its billing ends or moves",
			match: func(s AccountSubscription) bool { return orgLiveStatus(s.OrgStatus) },
			fate:  BillingRefuse,
		},
		{
			name: "an org on its way out (pending deletion, purging, purged): the purge deletes its row, so its own " +
				"cancel_billing step would find nothing to cancel; cancel it first",
			match: func(AccountSubscription) bool { return true },
			fate:  BillingCancel,
		},
	}
}

// DecideBilling returns the deciding billing row's fate for s.
func DecideBilling(s AccountSubscription) BillingFate {
	return billingRules()[decidingBillingRow(s)].fate
}

// decidingBillingRow returns the index of the billing row that decides s.
func decidingBillingRow(s AccountSubscription) int {
	rules := billingRules()
	for i, r := range rules {
		if r.match(s) {
			return i
		}
	}
	return len(rules) - 1
}

// AccountBilling is what an account deletion does with the account's
// subscriptions.
type AccountBilling struct {
	// Cancel are the subscriptions Paddle may still bill to cancel at Paddle
	// before the deletion (live ones, and refunded or charged-back ones), in
	// input order.
	Cancel []AccountSubscription
	// Refuse are the live subscriptions that refuse the deletion, in input
	// order.
	Refuse []AccountSubscription
}

// PlanAccountBilling sorts the account's subscriptions by fate. It is pure.
func PlanAccountBilling(subs []AccountSubscription) AccountBilling {
	var out AccountBilling
	for _, s := range subs {
		switch DecideBilling(s) {
		case BillingCancel:
			out.Cancel = append(out.Cancel, s)
		case BillingRefuse:
			out.Refuse = append(out.Refuse, s)
		}
	}
	return out
}

// AccountCancelKey is the idempotency key of an account deletion's
// cancellation of one subscription: one key per (account, subscription), so
// a retried deletion repeats the same cancellation.
func AccountCancelKey(accountID, subscriptionID string) string {
	return "acctdel:" + accountID + ":" + subscriptionID
}
