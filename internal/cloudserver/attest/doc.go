// Package attest implements the ContentLogging route-policy canary (plan §2.2):
// the attested, bound, re-checked capability read that authorizes a Foundry
// route for real-evidence inference. The mechanism is the Azure Resource
// Manager REST API (the Microsoft.CognitiveServices/accounts resource read) —
// the service NEVER shells out to `az`; the CLI is grounding evidence only. A
// managed-identity token source is the sole credential, holding only the reader
// action for that resource.
//
// The healthy verdict is narrow: the capability value must be present, a JSON
// boolean, and exactly `false` (ContentLogging disabled). Absent, duplicate-
// collapsed, malformed, non-boolean, or `true` values are ALL unhealthy, and so
// is any control-plane outage — the canary fails closed in every ambiguous
// state (plan §2.2).
package attest
