// Package frontdoor owns the node front door's one-sentence status (managed
// SaaS plan 06 section 19.3 rule 1; plan 07 M8.4): identity (is this person
// signed in to SuperBased?) and destination (where does this machine's data
// go?) are separate, and every surface says both in one sentence, built
// here so `observer status`, `observer connect` and the dashboard can never
// word it differently:
//
//	Local only
//	Local only · signed in to SuperBased
//	Acme (managed) as dev@acme.example
//	Acme (managed, locked) as dev@acme.example · signed in to SuperBased
//	Acme (individual) as you@example.com
//
// The sentence is chosen by an ordered rule table walked top-down (one test
// case per row). The package is pure: the caller reads the enrolment and the
// local sign-in state and passes them in.
package frontdoor
