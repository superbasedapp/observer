// Package repricesvc is the boundary service behind opt-in retroactive
// re-pricing of stored node costs (gap PRICE-REPRICE-1, docs/pricing.md
// "Re-pricing stored costs"). It is the ONE owner of the re-price flow: the
// `observer reprice` CLI and the node dashboard's Settings card
// (/api/reprice/*) both call [Service]; neither plans, prices or writes a row
// itself.
//
// The flow is dry run first, always:
//
//   - [Service.Plan] streams the candidate rows out of the store
//     (store.ScanRepriceRows, provenance already resolved into flags), runs
//     each through the pure planner (internal/reprice) with the injected
//     price function, and returns the summary plus a DIGEST over the facts a
//     human approved (window, model filter, pricing source + version, rule
//     version, changed / filled counts, old / new totals). It writes nothing.
//   - [Service.Apply] re-plans and refuses with [ErrPlanChanged] (carrying the
//     fresh plan) when the digest differs from the one the caller approved:
//     prices or rows moved since the dry run, so the operator must look again.
//     Otherwise it hands the plan's update decisions to store.ApplyReprice,
//     which writes them as compare-and-swap updates with a change log.
//   - [Service.Revert] undoes one apply run through store.RevertReprice.
//
// The price function and the pricing description are INJECTED: cmd/observer
// wraps the node's one process cost engine (internal/orgpricing.Mode
// precedence, the org's or the public feed's dated rows composed in), so this
// package never imports the cost engine and never decides which price table
// is in force.
//
// Apply and Revert are serialized within the process by one mutex; across
// processes (the daemon's dashboard and a CLI one-shot) the store's
// compare-and-swap writes are what keep two runs from overwriting each other.
package repricesvc
