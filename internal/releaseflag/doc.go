// Package releaseflag is the table of RELEASE flags: temporary switches that
// let pooled-only or unfinished code ship dark inside a component (plan 06
// section 18.4, plan 07 row M2.5). Only the `release` kind exists; `ops`
// flags are cut to after GA (decision D-44).
//
// A flag row carries a name, the component it lives in, the owner lane, a
// default per deployment kind (in code, so a release SHA fully determines
// private behaviour), a creation date and an expiry date (at most 90 days
// after creation).
//
// The package is pure: the clock and the set of changed components are
// injected, and it reads no files, environment or network. Three questions
// are answered: Resolve (a flag's value for a deployment kind), Expired (the
// flags past expiry, for the nightly report to the owner lane), and Check
// (the pre-push verdict: an expired flag FAILS only a change that touches its
// component, otherwise it is a warning).
package releaseflag
