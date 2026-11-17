// Package seatbilling is the control plane's seat-quantity decision (plan
// 06 5.8.5; plan 07 M7b.2): from a billing period's seat count (the
// tenant's internal/orgserver/usage metric, pulled through the host API's
// usage verb) and the org's Paddle subscription, it decides whether to
// change the subscription's seat quantity and builds the one request that
// does it.
//
// The rule (plan 06 5.8.5, monthly plans): seats for month M are billed in
// arrears at the next renewal, as a Paddle quantity change; the plan
// minimum applies. So the quantity is max(seats, the plan's seats.min, 1)
// and the change is made with proration_billing_mode do_not_bill: nothing
// is charged mid-cycle, and the renewal bills the new quantity. Annual
// plans (after GO-3) bill committed seats with a quarterly true-up, which is
// a one-off charge, not a quantity change, so this package leaves them.
//
// The plan minimum comes from internal/entitlements (the only caps
// authority), never from a plan name. Decide is pure and table-driven;
// subpackage paddleapi is the HTTP client that sends the request, tested
// only against fakes and fixtures (sandbox semantics, no key, no network).
package seatbilling
