package store

// paddle_floor.go is the plan-version floor of the one Paddle subscription
// store: the ONE rule every webhook write of a subscription's plan goes
// through, on the account path (paddle.go) and the org path (paddle_org.go)
// alike (D-299; NEW-12).
//
// A plan version only ever moves forward: a plan-version migration (cloud
// 0039, 0041) or an operator moving an in-force subscription to the next
// version of its plan (a Business v1 row moved to v2 when the live price
// moves to v2) is never undone by a later event whose price still maps to
// the version it moved off. Before NEW-12 only the account path applied the
// floor, so an org's renewal wrote a moved Business v2 row back to v1 and
// the worker issued the org a v1 entitlement again.
//
// The rule is applied in two places, both through paddlePlanFloor:
//
//   - upsertSubscriptionTx, the only writer of paddle_subscriptions'
//     plan_name and plan_version, floors every write at the row it
//     overwrites. Every branch (account and org; activate, renewal, cancel)
//     writes the row through it, so no branch can move a row back, and a
//     new subscription (no row yet) takes its mapped plan unchanged.
//   - applyPaddleActivate also floors at the account's plan in force before
//     it assigns that plan (account_plans is the account path's entitlement
//     authority, and a migration moves it forward without the row), and then
//     assigns what upsertSubscriptionTx wrote, so the account plan and the
//     row never disagree. The org path assigns no plan: the worker issues the
//     org's entitlement from the row itself.

// paddlePlanFloor returns mapped, its version raised to the highest version
// of the SAME plan among held: the plan records the subscriber holds now.
// A held plan of another name, a held version at or below the mapped one, or
// no held plan at all (a new subscription) leaves mapped unchanged. Only
// Version ever changes; every other field (interval, display, the trial-less
// sibling) stays the mapped price's. Pure.
func paddlePlanFloor(mapped PaddlePlan, held ...PaddlePlan) PaddlePlan {
	for _, h := range held {
		if h.Name == mapped.Name && h.Version > mapped.Version {
			mapped.Version = h.Version
		}
	}
	return mapped
}

// heldPlan is the PaddlePlan record of a plan in force, for paddlePlanFloor.
func heldPlan(p Plan) PaddlePlan { return PaddlePlan{Name: p.Name, Version: p.Version} }
